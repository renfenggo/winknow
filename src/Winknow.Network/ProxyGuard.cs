using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using Winknow.Core.Results;
using Winknow.Policy;

namespace Winknow.Network;

/// <summary>
/// 代理防绕过守卫：监控并恢复 HKCU/HKLM 代理设置，强制按策略管控。
/// 防止学生通过修改系统代理绕过 PAC/白名单。
/// </summary>
public sealed class ProxyGuard : IDisposable
{
    private readonly ILogger<ProxyGuard>? _logger;
    private readonly ProxySection _policy;
    private Timer? _periodicTimer;
    private bool _disposed;

    // HKCU Internet Settings 节点（用户级代理设置）
    private const string UserInternetSettings = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    // HKLM Internet Settings 节点（系统级代理设置）
    private const string MachineInternetSettings = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";

    /// <summary>检测到代理被篡改时触发（参数：来源 hive，篡改前值）。</summary>
    public event Action<string, ProxySnapshot>? ProxyTampered;

    /// <summary>创建代理守卫。</summary>
    /// <param name="policy">代理策略（Allowed=false 表示禁止自定义代理）。</param>
    /// <param name="logger">可选的日志记录器。</param>
    public ProxyGuard(ProxySection policy, ILogger<ProxyGuard>? logger = null)
    {
        _policy = policy;
        _logger = logger;
    }

    /// <summary>
    /// 启动 20 秒周期校验（验收项：修改系统代理后恢复）。
    /// </summary>
    public void StartMonitoring()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _periodicTimer = new Timer(_ => CheckAndRestore(), null, TimeSpan.Zero, TimeSpan.FromSeconds(20));
        _logger?.LogInformation("Proxy periodic check started (interval: 20s)");
    }

    /// <summary>
    /// 立即检查并恢复一次代理设置。
    /// </summary>
    public Result CheckAndRestore()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var result = Result.Success();

        foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        {
            var snapshot = ReadSnapshot(hive);
            if (snapshot is null) continue;

            if (IsTampered(snapshot))
            {
                ProxyTampered?.Invoke(hive.ToString(), snapshot);
                _logger?.LogWarning("Proxy tampered in {Hive}: Enable={Enable} Server={Server}",
                    hive, snapshot.ProxyEnable, snapshot.ProxyServer);
                RestoreInternal(hive);
            }
        }

        return result;
    }

    /// <summary>
    /// 获取当前代理快照（用于测试和诊断）。
    /// </summary>
    public ProxySnapshot? ReadSnapshot(RegistryHive hive)
    {
        var view = hive == RegistryHive.CurrentUser ? RegistryView.Default : RegistryView.Registry64;
        var key = hive == RegistryHive.CurrentUser
            ? Registry.CurrentUser.OpenSubKey(UserInternetSettings, writable: false)
            : Registry.LocalMachine.OpenSubKey(MachineInternetSettings, writable: false);
        if (key is null) return null;

        try
        {
            return new ProxySnapshot(
                ProxyEnable: key.GetValue("ProxyEnable") as int? ?? 0,
                ProxyServer: key.GetValue("ProxyServer") as string ?? string.Empty,
                ProxyOverride: key.GetValue("ProxyOverride") as string ?? string.Empty,
                AutoConfigUrl: key.GetValue("AutoConfigURL") as string ?? string.Empty,
                Hive: hive.ToString());
        }
        finally
        {
            key.Dispose();
        }
    }

    /// <summary>
    /// 判断快照是否违反策略。
    /// 策略：Allowed=false 时，ProxyEnable 必须=0，ProxyServer 必须空，AutoConfigURL 必须空。
    /// </summary>
    public bool IsTampered(ProxySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (_policy.Allowed) return false;

        if (snapshot.ProxyEnable != 0) return true;
        if (!string.IsNullOrWhiteSpace(snapshot.ProxyServer)) return true;
        if (!_policy.Pac.Allowed && !string.IsNullOrWhiteSpace(snapshot.AutoConfigUrl)) return true;
        if (_policy.Pac.Allowed
            && !string.IsNullOrEmpty(_policy.Pac.AutoConfigUrl)
            && !string.Equals(snapshot.AutoConfigUrl, _policy.Pac.AutoConfigUrl, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    /// <summary>
    /// 强制恢复指定 hive 的代理设置到策略合规状态。
    /// </summary>
    public Result Restore(RegistryHive hive)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RestoreInternal(hive);
        return Result.Success();
    }

    private void RestoreInternal(RegistryHive hive)
    {
        var key = hive == RegistryHive.CurrentUser
            ? Registry.CurrentUser.OpenSubKey(UserInternetSettings, writable: true)
            : Registry.LocalMachine.OpenSubKey(MachineInternetSettings, writable: true);

        if (key is null)
        {
            _logger?.LogWarning("Cannot open {Hive} Internet Settings for write", hive);
            return;
        }

        try
        {
            if (_policy.Allowed) return;

            // 强制禁用自定义代理
            key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
            if (key.GetValue("ProxyServer") is not null) key.DeleteValue("ProxyServer", false);
            if (!_policy.Pac.Allowed && key.GetValue("AutoConfigURL") is not null)
            {
                key.DeleteValue("AutoConfigURL", false);
            }
            else if (_policy.Pac.Allowed && !string.IsNullOrEmpty(_policy.Pac.AutoConfigUrl))
            {
                key.SetValue("AutoConfigURL", _policy.Pac.AutoConfigUrl, RegistryValueKind.String);
            }

            _logger?.LogInformation("Proxy restored to policy-compliant state in {Hive}", hive);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to restore proxy in {Hive}", hive);
        }
        finally
        {
            key.Dispose();
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _periodicTimer?.Dispose();
    }
}

/// <summary>
/// 代理设置快照（不可变）。
/// </summary>
public sealed record ProxySnapshot(
    int ProxyEnable,
    string ProxyServer,
    string ProxyOverride,
    string AutoConfigUrl,
    string Hive);
