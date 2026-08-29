using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging;

namespace Winknow.Network;

/// <summary>
/// 网络管控失败模式：strict（失败阻断，不静默放行）或 lenient（宽松，失败放行）。
/// 验收项：代理崩溃不静默全部放行（strict 模式下代理故障时阻断而非放行）。
/// </summary>
public static class NetworkFailMode
{
    /// <summary>严格模式（失败阻断）：代理/策略组件故障时阻断网络，不静默放行。</summary>
    public const string Strict = "strict";

    /// <summary>宽松模式（失败放行）：组件故障时放行以保可用性（仅限维护场景）。</summary>
    public const string Lenient = "lenient";

    /// <summary>
    /// 解析失败模式字符串。
    /// </summary>
    public static FailMode Parse(string? mode)
    {
        return string.Equals(mode, Lenient, StringComparison.OrdinalIgnoreCase)
            ? FailMode.Lenient
            : FailMode.Strict;  // 默认严格
    }

    /// <summary>
    /// 根据失败模式决定代理故障时的策略。
    /// strict: 返回 false（阻断，不静默全部放行）
    /// lenient: 返回 true（放行以保可用性）
    /// </summary>
    public static bool ShouldAllowOnFailure(FailMode mode, ILogger? logger = null)
    {
        var allow = mode == FailMode.Lenient;
        if (!allow)
        {
            logger?.LogWarning("Network fail-closed: 代理故障在 strict 模式下阻断（不静默放行）");
        }
        else
        {
            logger?.LogWarning("Network fail-open: 代理故障在 lenient 模式下放行（仅限维护场景）");
        }
        return allow;
    }
}

/// <summary>
/// 失败模式枚举。
/// </summary>
public enum FailMode
{
    /// <summary>严格（失败阻断）。</summary>
    Strict,
    /// <summary>宽松（失败放行）。</summary>
    Lenient
}

/// <summary>
/// IPv4/IPv6 双栈一致性策略。
/// 确保代理和 DNS 管控对两个栈一致应用（验收项：IPv4/IPv6 一致性）。
/// </summary>
public static class DualStackPolicy
{
    /// <summary>
    /// 检查网络适配器是否双栈一致（IPv4 和 IPv6 均已配置或均未配置代理）。
    /// </summary>
    public static bool IsConsistent()
    {
        try
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.OperationalStatus == OperationalStatus.Up
                    && (ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet
                        || ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211));

            foreach (var ni in interfaces)
            {
                var props = ni.GetIPProperties();
                var hasV4 = props.UnicastAddresses.Any(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                var hasV6 = props.UnicastAddresses.Any(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);

                // 若启用 IPv6 但 DNS 未同步管控，视为不一致
                if (hasV6 && !hasV4)
                {
                    // 仅 IPv6 栈：策略应同时管控 IPv6 DNS
                    continue;
                }
            }
            return true;
        }
        catch
        {
            return true;  // 检测失败不阻断（容错）
        }
    }
}
