using System.Diagnostics;
using System.Net.NetworkInformation;
using System.ServiceProcess;
using Microsoft.Extensions.Logging;
using Winknow.Policy;

namespace Winknow.Network;

/// <summary>
/// VPN/TUN 检测器：检测 VPN 客户端进程、服务和虚拟网卡（TUN/TAP）。
/// 防止学生通过 VPN 绕过网络管控。
/// </summary>
public sealed class VpnTunDetector
{
    private readonly ILogger<VpnTunDetector>? _logger;
    private readonly VpnDetectionSection _policy;

    /// <summary>检测到 VPN 时触发（参数：检测到的 VPN 项列表）。</summary>
    public event Action<IReadOnlyList<VpnDetectionItem>>? VpnDetected;

    /// <summary>创建 VPN/TUN 检测器。</summary>
    public VpnTunDetector(VpnDetectionSection policy, ILogger<VpnTunDetector>? logger = null)
    {
        _policy = policy;
        _logger = logger;
    }

    /// <summary>
    /// 执行一次完整检测：进程 + 服务 + 虚拟网卡。
    /// </summary>
    public VpnDetectionResult Detect()
    {
        var processes = DetectProcesses();
        var services = DetectServices();
        var adapters = _policy.DetectVirtualAdapters ? DetectVirtualAdapters() : new List<string>();

        var items = new List<VpnDetectionItem>();
        items.AddRange(processes.Select(p => new VpnDetectionItem(VpnType.Process, p)));
        items.AddRange(services.Select(s => new VpnDetectionItem(VpnType.Service, s)));
        items.AddRange(adapters.Select(a => new VpnDetectionItem(VpnType.VirtualAdapter, a)));

        if (items.Count > 0)
        {
            VpnDetected?.Invoke(items);
            _logger?.LogWarning("VPN detected: {Count} items", items.Count);
        }

        return new VpnDetectionResult(items, items.Count > 0);
    }

    /// <summary>
    /// 检测运行中的 VPN 客户端进程。
    /// </summary>
    public IReadOnlyList<string> DetectProcesses()
    {
        var found = new List<string>();
        var blocked = GetBlockedProcessNames();

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                var name = proc.ProcessName;
                if (blocked.Contains(name, StringComparer.OrdinalIgnoreCase))
                {
                    found.Add(name);
                }
            }
            catch { /* 进程可能已退出 */ }
        }

        return found;
    }

    /// <summary>
    /// 检测运行中的 VPN 服务。
    /// </summary>
    public IReadOnlyList<string> DetectServices()
    {
        var found = new List<string>();
        var blocked = _policy.BlockedServices;

        if (blocked.Count == 0) return found;

        try
        {
            foreach (var svc in ServiceController.GetServices())
            {
                if (svc.Status != ServiceControllerStatus.Running) continue;
                if (blocked.Contains(svc.ServiceName, StringComparer.OrdinalIgnoreCase)
                    || blocked.Any(b => svc.DisplayName.Contains(b, StringComparison.OrdinalIgnoreCase)))
                {
                    found.Add(svc.ServiceName);
                }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to enumerate services");
        }

        return found;
    }

    /// <summary>
    /// 检测虚拟网卡（TUN/TAP）。
    /// </summary>
    public IReadOnlyList<string> DetectVirtualAdapters()
    {
        var found = new List<string>();
        var tunKeywords = new[]
        {
            "tap", "tun", "vpn", "wireguard", "openvpn", "nordvpn",
            "virtual", "hamachi", "zero tier", "zerotier"
        };

        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                var desc = ni.Description.ToLowerInvariant();
                var name = ni.Name.ToLowerInvariant();
                if (tunKeywords.Any(k => desc.Contains(k) || name.Contains(k)))
                {
                    found.Add($"{ni.Name} ({ni.Description})");
                }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to enumerate network interfaces");
        }

        return found;
    }

    private List<string> GetBlockedProcessNames()
    {
        var names = new List<string>(_policy.BlockedProcesses);
        // 默认常见 VPN 客户端进程名
        if (names.Count == 0)
        {
            names.AddRange(new[]
            {
                "openvpn", "openvpn-gui", "nordvpn", "nordvpn-service",
                "expressvpn", "cyberghost", "surfshark", "protonvpn",
                "windscribe", "tunnelbear", "vyprvpn", "ipvanish",
                "privatevpn", "purevpn", "hidemyass", "torguard",
                "v2ray", "v2rayN", "clash", "clash-verge", "shadowsocks",
                "ssr", "trojan", "xray", "sing-box"
            });
        }
        return names;
    }
}

/// <summary>
/// VPN 检测项类型。
/// </summary>
public enum VpnType
{
    /// <summary>VPN 客户端进程。</summary>
    Process,
    /// <summary>VPN 后台服务。</summary>
    Service,
    /// <summary>虚拟网卡（TUN/TAP）。</summary>
    VirtualAdapter
}

/// <summary>
/// 单个 VPN 检测项。
/// </summary>
public sealed record VpnDetectionItem(VpnType Type, string Name);

/// <summary>
/// VPN 检测结果。
/// </summary>
public sealed record VpnDetectionResult(IReadOnlyList<VpnDetectionItem> Items, bool Detected);
