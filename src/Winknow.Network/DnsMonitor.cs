using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging;
using Winknow.Core.Results;
using Winknow.Policy;

namespace Winknow.Network;

/// <summary>
/// DNS 监控器：检测异常 DNS 修改（公共 DNS、适配器配置篡改）。
/// 防止学生将 DNS 改为 8.8.8.8 等公共 DNS 以绕过 DNS 层过滤。
/// </summary>
public sealed class DnsMonitor
{
    private readonly ILogger<DnsMonitor>? _logger;
    private DnsSection _policy;
    private HashSet<string> _blockedServers;

    /// <summary>检测到异常 DNS 修改时触发（参数：适配器名，违规 DNS 列表）。</summary>
    public event Action<string, IReadOnlyList<string>>? DnsTampered;

    /// <summary>创建 DNS 监控器。</summary>
    public DnsMonitor(DnsSection policy, ILogger<DnsMonitor>? logger = null)
    {
        _policy = policy;
        _logger = logger;
        _blockedServers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        InitializeBlockedSet();
    }

    /// <summary>
    /// 立即检查所有网络适配器的 DNS 配置。
    /// </summary>
    public Result Check()
    {
        var violations = new List<(string Adapter, List<string> BadDns)>();

        try
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.OperationalStatus == OperationalStatus.Up
                    && (ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet
                        || ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211));

            foreach (var ni in interfaces)
            {
                var props = ni.GetIPProperties();
                var badDns = new List<string>();

                // 检查 IPv4 DNS
                foreach (var addr in props.DnsAddresses)
                {
                    if (IsBlocked(addr.ToString()))
                    {
                        badDns.Add(addr.ToString());
                    }
                }

                if (badDns.Count > 0)
                {
                    violations.Add((ni.Name, badDns));
                    DnsTampered?.Invoke(ni.Name, badDns);
                    _logger?.LogWarning("Adapter {Adapter} has blocked DNS: {Dns}",
                        ni.Name, string.Join(", ", badDns));
                }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to check DNS configuration");
            return Result.Failure(ErrorCode.Unknown, ex.Message);
        }

        if (violations.Count > 0)
        {
            var allBad = violations.SelectMany(v => v.BadDns).Distinct().ToList();
            return Result.Failure(ErrorCode.InvalidConfiguration,
                $"检测到 {violations.Count} 个适配器使用违规 DNS: {string.Join(", ", allBad)}");
        }

        return Result.Success();
    }

    /// <summary>
    /// 判断指定 DNS 服务器是否违规。
    /// </summary>
    public bool IsBlocked(string dnsServer)
    {
        if (string.IsNullOrWhiteSpace(dnsServer)) return false;
        if (_blockedServers.Contains(dnsServer)) return true;
        // 检查策略允许列表：若配置了允许列表且不在其中则违规
        if (_policy.AllowedServers.Count > 0
            && !_policy.AllowedServers.Contains(dnsServer, StringComparer.OrdinalIgnoreCase))
        {
            return true;
        }
        return false;
    }

    /// <summary>
    /// 刷新策略（运行时更新）。
    /// </summary>
    public void UpdatePolicy(DnsSection policy)
    {
        _policy = policy;
        InitializeBlockedSet();
    }

    private void InitializeBlockedSet()
    {
        _blockedServers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // 策略黑名单
        foreach (var s in _policy.BlockedServers)
        {
            _blockedServers.Add(s);
        }
        // 默认公共 DNS 黑名单（即使策略未配置也检测）
        var defaults = new[]
        {
            "8.8.8.8", "8.8.4.4",                // Google
            "1.1.1.1", "1.0.0.1",                // Cloudflare
            "9.9.9.9", "149.112.112.112",        // Quad9
            "208.67.222.222", "208.67.220.220"  // OpenDNS
        };
        foreach (var d in defaults)
        {
            _blockedServers.Add(d);
        }
    }
}

/// <summary>
/// DNS 适配器快照（不可变）。
/// </summary>
public sealed record DnsAdapterSnapshot(string Name, IReadOnlyList<string> DnsServers);
