using Microsoft.Extensions.Logging;
using Winknow.Core;
using Winknow.Core.Results;

namespace Winknow.DeviceSecurity;

/// <summary>
/// 设备安全评估门面（V7.0 第 11 周核心流程编排）。
///
/// 单入口 <see cref="Assess"/> 聚合：
/// ① 固件信息采集（WMI + GetFirmwareType）→ 计算**当前固件指纹**；
/// ② 变化失效判定：指纹 vs 核验记录 → 不一致则自动失效旧记录并重置人工核验表；
/// ③ Secure Boot 检测 + 启动配置采集（自动项）；
/// ④ 人工核验表加载（五项固件检查，默认"需人工核验"）；
/// ⑤ 组装检查项清单 → 评分与等级 → <see cref="DeviceSecurityReport"/>。
///
/// 数据目录：ProgramData\Winknow\device_security\
/// （核验记录 verification.json + 人工核验 checklist.json）。
/// </summary>
public sealed class DeviceSecurityAssessor
{
    private readonly string _dataDir;
    private readonly ILogger? _logger;

    /// <summary>
    /// 构造评估器。
    /// </summary>
    /// <param name="logger">可选日志。</param>
    /// <param name="dataDir">数据目录（默认 ProgramData\Winknow\device_security）。</param>
    public DeviceSecurityAssessor(ILogger? logger = null, string? dataDir = null)
    {
        _logger = logger;
        _dataDir = dataDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Winknow", Constants.DeviceSecurity.DataDirName);
    }

    /// <summary>数据目录（核验记录与人工核验表持久化处）。</summary>
    public string DataDir => _dataDir;

    /// <summary>
    /// 执行完整评估（采集 → 失效判定 → 检查项组装 → 评分）。
    /// </summary>
    /// <param name="deviceId">设备 ID（null 则用 Core.DeviceId.Generate）。</param>
    public DeviceSecurityReport Assess(string? deviceId = null)
    {
        var firmware = new FirmwareInfoCollector(_logger).Collect();
        var fingerprint = FirmwareInfoCollector.ComputeFingerprint(firmware);

        // 变化失效：BIOS 更新/主板变化 → 旧核验记录失效 + 人工核验表重置
        var checklist = new ManualChecklist(_dataDir);
        var store = new VerificationStore(_dataDir, _logger);
        var (verificationCurrent, verificationDetail) = store.ValidateAndExpire(fingerprint, checklist);
        if (verificationCurrent == false)
        {
            _logger?.LogWarning("核验记录失效：{Detail}", verificationDetail);
        }

        // Secure Boot（自动项）
        var detector = new SecureBootDetector(_logger);
        var sbState = detector.Detect();
        var (sbStatus, sbDetail, sbRemediation) = SecureBootDetector.Evaluate(sbState);

        // 启动配置（自动项）
        var boot = new BootConfigCollector(_logger).Collect();

        // 组装检查项：自动 2 项（50 分）+ 人工 5 项（50 分）
        var checks = new List<CheckItem>
        {
            new()
            {
                Id = DeviceSecurityScorer.CheckSecureBoot,
                Title = "Secure Boot 已启用",
                Category = "auto",
                Weight = 30,
                Status = sbStatus,
                Detail = sbDetail,
                Remediation = sbRemediation
            },
            new()
            {
                Id = DeviceSecurityScorer.CheckUefiMode,
                Title = "UEFI 固件模式（非 Legacy）",
                Category = "auto",
                Weight = 20,
                Status = firmware.FirmwareType switch
                {
                    "UEFI" => CheckStatus.Pass,
                    "Legacy" => CheckStatus.Fail,
                    _ => CheckStatus.Pending
                },
                Detail = $"固件类型：{firmware.FirmwareType}；系统盘分区表：{boot.PartitionStyle}",
                Remediation = firmware.FirmwareType == "Legacy"
                    ? "将固件切换为 UEFI 模式并重装系统盘为 GPT（或开启 CSM 过渡）"
                    : "确认为 UEFI 模式启动（如显示 Legacy 请检查 BIOS 启动模式设置）"
            }
        };

        // 人工项：定义 + 已核验结果（未核验保持 Pending）
        var results = checklist.CurrentResults.ToDictionary(r => r.CheckId);
        foreach (var def in ManualChecklist.Definitions)
        {
            var r = results[def.Id];
            checks.Add(new CheckItem
            {
                Id = def.Id,
                Title = def.Title,
                Category = "manual",
                Weight = def.Weight,
                Status = r.Status,
                Detail = r.Status == CheckStatus.Pending
                    ? verificationDetail // 提示为何需人工核验（含失效原因）
                    : $"核验人：{r.VerifiedBy} @ {r.VerifiedAt}；{r.Note}".TrimEnd('；'),
                Remediation = def.Remediation
            });
        }

        var report = new DeviceSecurityReport
        {
            DeviceId = deviceId ?? DeviceId.Generate(),
            Firmware = firmware,
            SecureBootState = sbState.ToString(),
            BootConfig = boot,
            Checks = checks,
            VerificationCurrent = verificationCurrent,
            GeneratedAt = DateTimeOffset.UtcNow.ToString("O")
        };
        DeviceSecurityScorer.Score(report);

        _logger?.LogInformation(
            "设备安全评估完成：评分 {Score}/100，等级 {Grade}，核验有效性 {Valid}",
            report.Score, DeviceSecurityScorer.GradeText(report.Grade), verificationCurrent?.ToString() ?? "无记录");
        return report;
    }

    /// <summary>
    /// 保存人工核验结论（管理员完成现场核验后调用）：更新清单 + 写核验记录。
    /// </summary>
    /// <param name="deviceId">设备 ID。</param>
    /// <param name="firmware">核验时采集的固件信息（指纹来源）。</param>
    /// <param name="results">五项核验结论。</param>
    /// <param name="adminName">核验管理员。</param>
    /// <param name="notes">备注。</param>
    public Core.Results.Result SaveVerification(
        string deviceId,
        FirmwareInfo firmware,
        IReadOnlyList<(string CheckId, CheckStatus Status, string Note)> results,
        string adminName,
        string notes = "")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(adminName);

        var checklist = new ManualChecklist(_dataDir);
        var invalid = results.FirstOrDefault(r => r.Status == CheckStatus.Pending);
        if (invalid.CheckId is not null)
        {
            return Core.Results.Result.Failure(ErrorCode.InvalidParameter,
                $"检查项 {invalid.CheckId} 仍为待核验状态——核验结论只能是 Pass/Fail");
        }

        foreach (var (checkId, status, note) in results)
        {
            try
            {
                checklist.SetResult(checkId, status, adminName, note);
            }
            catch (ArgumentException ex)
            {
                return Core.Results.Result.Failure(ErrorCode.InvalidParameter, ex.Message);
            }
        }

        var record = new VerificationRecord
        {
            DeviceId = deviceId,
            FirmwareFingerprint = FirmwareInfoCollector.ComputeFingerprint(firmware),
            FirmwareVersion = firmware.BiosVersion,
            AdminName = adminName,
            VerifiedAt = DateTimeOffset.UtcNow.ToString("O"),
            Notes = notes,
            Checklist = checklist.CurrentResults.ToList()
        };
        return new VerificationStore(_dataDir, _logger).Save(record);
    }
}
