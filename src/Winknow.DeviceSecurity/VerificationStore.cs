using System.IO;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Winknow.Core;
using Winknow.Core.Results;

namespace Winknow.DeviceSecurity;

/// <summary>
/// 核验记录存储（V7.0 第 11 周"核验记录 + 变化失效机制"）。
///
/// 记录内容：管理员、时间、设备 ID、固件版本、固件指纹、备注、人工核验明细。
/// 持久化：ProgramData\Winknow\device_security\verification.json。
///
/// 变化失效（验收"BIOS 更新后旧核验记录自动失效"）：
/// 记录保存固件指纹 = SHA256(BIOS 版本+发布日期+主板序列号)。
/// 每次评估时用**当前指纹**比对记录指纹：
/// - 一致 → 核验有效（VerificationCurrent = true）；
/// - 不一致（BIOS 更新/主板更换）→ 核验失效（false），
///   且人工核验项全部回退 Pending，必须重新人工核验。
/// </summary>
public sealed class VerificationStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _dataDir;
    private readonly ILogger? _logger;

    private string StorePath => Path.Combine(_dataDir, Constants.DeviceSecurity.VerificationFileName);

    /// <summary>
    /// 构造核验记录存储。
    /// </summary>
    /// <param name="dataDir">数据目录（ProgramData\Winknow\device_security）。</param>
    /// <param name="logger">可选日志。</param>
    public VerificationStore(string dataDir, ILogger? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDir);
        _dataDir = dataDir;
        _logger = logger;
    }

    /// <summary>
    /// 加载核验记录；无记录或损坏返回 null。
    /// </summary>
    public VerificationRecord? Load()
    {
        try
        {
            if (!File.Exists(StorePath)) return null;
            return JsonSerializer.Deserialize<VerificationRecord>(File.ReadAllText(StorePath));
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "核验记录读取失败，按无记录处理");
            return null;
        }
    }

    /// <summary>
    /// 保存核验记录（覆盖旧记录——一台设备只保留最近一次有效核验）。
    /// </summary>
    public Result Save(VerificationRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        try
        {
            Directory.CreateDirectory(_dataDir);
            File.WriteAllText(StorePath, JsonSerializer.Serialize(record, JsonOptions));
            _logger?.LogInformation(
                "核验记录已保存：{Admin} @ {At}（指纹 {Fp}）",
                record.AdminName, record.VerifiedAt, record.FirmwareFingerprint[..8]);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ErrorCode.ExternalError, $"核验记录保存失败: {ex.Message}");
        }
    }

    /// <summary>
    /// 变化失效判定：当前固件指纹与记录指纹是否一致。
    /// </summary>
    /// <returns>无记录返回 null（从未核验）；一致 true；BIOS 更新/主板变化 false。</returns>
    public bool? IsCurrent(string currentFingerprint)
    {
        var record = Load();
        if (record is null) return null;
        return string.Equals(
            record.FirmwareFingerprint, currentFingerprint, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 判定并处理失效：指纹不一致时清除记录并重置人工核验表（强制重新核验）。
    /// </summary>
    /// <returns>（是否有效，处置描述）；无记录返回 (null, "从未核验")。</returns>
    public (bool? IsValid, string Detail) ValidateAndExpire(
        string currentFingerprint, ManualChecklist checklist)
    {
        ArgumentNullException.ThrowIfNull(checklist);

        var record = Load();
        if (record is null)
        {
            return (null, "本机从未做过人工核验");
        }

        if (IsCurrent(currentFingerprint) == true)
        {
            return (true, $"核验有效（{record.AdminName} 于 {record.VerifiedAt:yyyy-MM-dd} 核验）");
        }

        // BIOS 更新/主板变化 → 记录失效：清除并重置核验表
        try { File.Delete(StorePath); }
        catch (IOException ex) { _logger?.LogWarning(ex, "失效核验记录删除失败"); }
        checklist.Reset();
        _logger?.LogWarning(
            "固件指纹变化，核验记录已失效（记录 {Old} vs 当前 {New}）——人工核验表已重置",
            record.FirmwareFingerprint[..8], currentFingerprint[..8]);
        return (false,
            $"固件已变化（BIOS 更新或主板更换），{record.VerifiedAt:yyyy-MM-dd} 的核验记录自动失效，需重新人工核验");
    }
}
