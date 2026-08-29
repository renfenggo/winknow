using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using Winknow.Core.Results;
using Winknow.Policy;

namespace Winknow.Network;

/// <summary>
/// 浏览器企业策略执行器：通过注册表推送 Chrome/Edge 企业策略，
/// 禁用自定义代理、DoH、安全 DNS（验收项：浏览器自定义代理和 DoH 按策略受控）。
/// </summary>
public sealed class BrowserPolicyEnforcer
{
    private readonly ILogger<BrowserPolicyEnforcer>? _logger;

    // Chrome 企业策略注册表路径（HKLM）
    private const string ChromePolicyKey = @"SOFTWARE\Policies\Google\Chrome";
    // Edge 企业策略注册表路径（HKLM）
    private const string EdgePolicyKey = @"SOFTWARE\Policies\Microsoft\Edge";

    /// <summary>创建浏览器企业策略执行器。</summary>
    public BrowserPolicyEnforcer(ILogger<BrowserPolicyEnforcer>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// 应用 Chrome 企业策略。
    /// </summary>
    public Result ApplyChrome(BrowserPolicyTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return ApplyPolicy(ChromePolicyKey, target, "Chrome");
    }

    /// <summary>
    /// 应用 Edge 企业策略。
    /// </summary>
    public Result ApplyEdge(BrowserPolicyTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return ApplyPolicy(EdgePolicyKey, target, "Edge");
    }

    /// <summary>
    /// 应用两个浏览器的企业策略（便捷方法）。
    /// </summary>
    public Result ApplyAll(BrowserPolicySection section)
    {
        ArgumentNullException.ThrowIfNull(section);
        var chrome = ApplyChrome(section.Chrome);
        var edge = ApplyEdge(section.Edge);
        return chrome.IsSuccess && edge.IsSuccess
            ? Result.Success()
            : Result.Failure(ErrorCode.ExternalError, "应用浏览器策略失败");
    }

    private Result ApplyPolicy(string keyPath, BrowserPolicyTarget target, string browser)
    {
        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(keyPath, writable: true);

            if (target.DisableCustomProxy)
            {
                // ProxyMode=2 禁用自定义代理（强制不使用代理 / 由系统管控）
                key.SetValue("ProxyMode", "2", RegistryValueKind.String);
                key.SetValue("ProxySettings", "", RegistryValueKind.String);
                _logger?.LogInformation("{Browser} custom proxy disabled via policy", browser);
            }

            if (target.DisableDoh)
            {
                // DnsOverHttpsMode=off 禁用 DoH
                key.SetValue("DnsOverHttpsMode", "off", RegistryValueKind.String);
                _logger?.LogInformation("{Browser} DoH disabled via policy", browser);
            }

            if (target.DisableSecureDns)
            {
                // BuiltInDnsClientEnabled=false 禁用内置安全 DNS
                key.SetValue("BuiltInDnsClientEnabled", 0, RegistryValueKind.DWord);
                _logger?.LogInformation("{Browser} secure DNS disabled via policy", browser);
            }

            return Result.Success();
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to apply {Browser} enterprise policy", browser);
            return Result.Failure(ErrorCode.ExternalError, $"应用 {browser} 策略失败: {ex.Message}");
        }
    }

    /// <summary>
    /// 检查 Chrome 策略是否已应用（用于验证）。
    /// </summary>
    public bool IsChromePolicyApplied(BrowserPolicyTarget target)
    {
        return IsPolicyApplied(ChromePolicyKey, target);
    }

    /// <summary>
    /// 检查 Edge 策略是否已应用（用于验证）。
    /// </summary>
    public bool IsEdgePolicyApplied(BrowserPolicyTarget target)
    {
        return IsPolicyApplied(EdgePolicyKey, target);
    }

    private bool IsPolicyApplied(string keyPath, BrowserPolicyTarget target)
    {
        using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
        if (key is null) return false;

        if (target.DisableCustomProxy
            && (key.GetValue("ProxyMode") as string != "2")) return false;
        if (target.DisableDoh
            && (key.GetValue("DnsOverHttpsMode") as string != "off")) return false;
        if (target.DisableSecureDns
            && (key.GetValue("BuiltInDnsClientEnabled") as int? != 0)) return false;

        return true;
    }
}
