using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Winknow.Core;

namespace Winknow.DeviceSecurity;

/// <summary>
/// 人工核验表（V7.0 第 11 周"人工核验表"）。
///
/// 五项固件级检查（BIOS 设置，操作系统内无法可靠自动读取）：
/// 1. BIOS 管理员密码已设置；2. USB Boot 已禁用；3. PXE 网络启动已禁用；
/// 4. Boot Order 首位为内置系统盘；5. Boot Menu 启动菜单已禁用。
///
/// 验收语义："无法自动检测的项目显示'需人工核验'，不显示为通过"——
/// 全部项默认 <see cref="CheckStatus.Pending"/>，只有管理员现场确认后
/// 才置为 Pass/Fail；Pending 恒定拉低报告等级为 NeedsManualReview。
///
/// 持久化：ProgramData\Winknow\device_security\checklist.json（核验明细随核验记录另行存储）。
/// </summary>
public sealed class ManualChecklist
{
    /// <summary>核验表检查项定义（Id/标题/权重/整改建议——与评分器共享）。</summary>
    public static readonly IReadOnlyList<CheckItem> Definitions = new List<CheckItem>
    {
        new()
        {
            Id = "bios-password", Title = "BIOS 管理员密码已设置", Category = "manual", Weight = 15,
            Remediation = "在 BIOS 中设置管理员（Supervisor）密码，防止学生修改固件设置"
        },
        new()
        {
            Id = "usb-boot", Title = "USB 外部启动已禁用", Category = "manual", Weight = 15,
            Remediation = "BIOS 中禁用 USB Storage Boot（UEFI: Disabled USB Boot Legacy/UEFI）"
        },
        new()
        {
            Id = "pxe-boot", Title = "PXE 网络启动已禁用", Category = "manual", Weight = 10,
            Remediation = "BIOS 中禁用 Network/PXE Boot 或将网卡 PXE ROM 设为 Disabled"
        },
        new()
        {
            Id = "boot-order", Title = "Boot Order 首位为内置系统盘", Category = "manual", Weight = 5,
            Remediation = "调整启动顺序：内置硬盘第一，移除网络/USB 启动优先项"
        },
        new()
        {
            Id = "boot-menu", Title = "Boot Menu（F12 一次性启动菜单）已禁用", Category = "manual", Weight = 5,
            Remediation = "BIOS 中禁用 Boot Menu / One-time Boot Menu 选项"
        }
    };

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _persistPath;
    private readonly Dictionary<string, ManualCheckResult> _results = new();

    /// <summary>
    /// 构造人工核验表。
    /// </summary>
    /// <param name="dataDir">数据目录（null 则不持久化，仅内存）。</param>
    public ManualChecklist(string? dataDir = null)
    {
        if (dataDir is not null)
        {
            _persistPath = Path.Combine(dataDir, Constants.DeviceSecurity.ChecklistFileName);
            LoadFromDisk();
        }
        else
        {
            _persistPath = string.Empty;
        }

        // 未持久化的项默认 Pending（需人工核验）
        foreach (var def in Definitions)
        {
            if (!_results.ContainsKey(def.Id))
            {
                _results[def.Id] = new ManualCheckResult { CheckId = def.Id, Status = CheckStatus.Pending };
            }
        }
    }

    /// <summary>全部核验项当前状态（定义顺序）。</summary>
    public IReadOnlyList<ManualCheckResult> CurrentResults =>
        Definitions.Select(d => _results[d.Id]).ToList();

    /// <summary>是否全部项已完成人工核验（无 Pending）。</summary>
    public bool AllVerified => _results.Values.All(r => r.Status != CheckStatus.Pending);

    /// <summary>
    /// 记录一项人工核验结果。
    /// </summary>
    /// <param name="checkId">检查项 Id。</param>
    /// <param name="status">核验结果（Pass/Fail；不允许记 Pending）。</param>
    /// <param name="verifiedBy">核验管理员。</param>
    /// <param name="note">备注。</param>
    /// <exception cref="ArgumentException">checkId 未知或 status 为 Pending。</exception>
    public void SetResult(string checkId, CheckStatus status, string verifiedBy, string note = "")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(verifiedBy);
        if (!Definitions.Any(d => d.Id == checkId))
        {
            throw new ArgumentException($"未知检查项: {checkId}", nameof(checkId));
        }
        if (status == CheckStatus.Pending)
        {
            throw new ArgumentException("人工核验结果只能是 Pass 或 Fail", nameof(status));
        }

        _results[checkId] = new ManualCheckResult
        {
            CheckId = checkId,
            Status = status,
            VerifiedBy = verifiedBy,
            VerifiedAt = DateTimeOffset.UtcNow.ToString("O"),
            Note = note
        };
        PersistToDisk();
    }

    /// <summary>
    /// 清空全部人工核验（固件变化失效后由管理员重新核验前调用）。
    /// </summary>
    public void Reset()
    {
        foreach (var def in Definitions)
        {
            _results[def.Id] = new ManualCheckResult { CheckId = def.Id, Status = CheckStatus.Pending };
        }
        PersistToDisk();
    }

    private void LoadFromDisk()
    {
        try
        {
            if (!File.Exists(_persistPath)) return;
            var saved = JsonSerializer.Deserialize<List<ManualCheckResult>>(File.ReadAllText(_persistPath));
            if (saved is null) return;
            foreach (var r in saved)
            {
                if (Definitions.Any(d => d.Id == r.CheckId))
                {
                    _results[r.CheckId] = r;
                }
            }
        }
        catch (Exception)
        {
            // 损坏按无记录处理（全部回到 Pending）
        }
    }

    private void PersistToDisk()
    {
        if (string.IsNullOrEmpty(_persistPath)) return;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_persistPath)!);
            File.WriteAllText(_persistPath, JsonSerializer.Serialize(CurrentResults.ToList(), JsonOptions));
        }
        catch (IOException)
        {
            // 持久化失败不影响内存态（下次核验会重写）
        }
    }
}
