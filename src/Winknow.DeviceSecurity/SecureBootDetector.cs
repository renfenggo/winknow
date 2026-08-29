using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Winknow.DeviceSecurity;

/// <summary>
/// Secure Boot 状态检测器（V7.0 第 11 周"Secure Boot 检测"）。
///
/// 读取 HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State：
/// - 1 → Enabled（启用，安全）
/// - 0 → Disabled（可关闭仅在 UEFI 且有权限时发生，属重大风险）
/// - 键不存在/不可读 → Unknown（Legacy 模式或异常环境）
///
/// 风险语义（供评分与报告）：
/// - Enabled：Pass
/// - Disabled：Fail（整改：BIOS 中开启 Secure Boot）
/// - Unknown：**Pending（需人工核验）**——无法自动判定绝不显示为通过；
///   Legacy 固件下 Secure Boot 不适用，由"固件类型检查项"表达风险。
/// </summary>
public sealed class SecureBootDetector
{
    private const string SecureBootStateKey = @"SYSTEM\CurrentControlSet\Control\SecureBoot";
    private readonly ILogger? _logger;

    /// <summary>
    /// 构造 Secure Boot 检测器。
    /// </summary>
    /// <param name="logger">可选日志。</param>
    public SecureBootDetector(ILogger? logger = null) => _logger = logger;

    /// <summary>Secure Boot 检测结果状态。</summary>
    public enum SecureBootState
    {
        /// <summary>已启用。</summary>
        Enabled,
        /// <summary>已禁用。</summary>
        Disabled,
        /// <summary>无法读取（键缺失/权限/异常）→ 需人工核验。</summary>
        Unknown
    }

    /// <summary>
    /// 读取当前 Secure Boot 状态（读注册表 State 值）。
    /// </summary>
    public SecureBootState Detect()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(SecureBootStateKey);
            if (key?.GetValue("State") is int state)
            {
                var result = state == 1 ? SecureBootState.Enabled : SecureBootState.Disabled;
                _logger?.LogInformation("Secure Boot 状态: {State} (State={Raw})", result, state);
                return result;
            }
            _logger?.LogWarning("Secure Boot 注册表键不可读（Legacy 模式或键缺失）");
            return SecureBootState.Unknown;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Secure Boot 状态读取异常，按 Unknown 处理");
            return SecureBootState.Unknown;
        }
    }

    /// <summary>
    /// 状态到检查项状态的映射（含整改建议文案）。
    /// </summary>
    public static (CheckStatus Status, string Detail, string Remediation) Evaluate(SecureBootState state) => state switch
    {
        SecureBootState.Enabled => (CheckStatus.Pass, "Secure Boot 已启用", string.Empty),
        SecureBootState.Disabled => (CheckStatus.Fail, "Secure Boot 已禁用",
            "在 BIOS/UEFI 设置中开启 Secure Boot（配合 UEFI 模式）"),
        _ => (CheckStatus.Pending, "无法自动读取（需在 BIOS 中人工确认）",
            "重启进入 BIOS/UEFI 确认 Secure Boot 状态为 Enabled")
    };
}
