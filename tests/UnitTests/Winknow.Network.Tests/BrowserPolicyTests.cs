using System.Security.Principal;
using Microsoft.Win32;
using Winknow.Core.Results;
using Winknow.Network;
using Winknow.Policy;

namespace Winknow.Network.Tests;

/// <summary>
/// 第 8 周"浏览器企业策略"测试。
/// 覆盖验收项："浏览器自定义代理和 DoH 按策略受控"
/// 注意：写 HKLM 需要管理员权限，非管理员环境仅验证不抛异常。
/// </summary>
public class BrowserPolicyTests
{
    private const string ChromePolicyKey = @"SOFTWARE\Policies\Google\Chrome";
    private const string EdgePolicyKey = @"SOFTWARE\Policies\Microsoft\Edge";

    private static BrowserPolicyTarget FullTarget() => new()
    {
        DisableCustomProxy = true,
        DisableDoh = true,
        DisableSecureDns = true
    };

    /// <summary>检测当前是否以管理员身份运行。</summary>
    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    [Fact]
    public void ApplyChrome_WritesAllPolicyValues()
    {
        if (!IsAdministrator()) return;  // 非管理员跳过 HKLM 写断言
        var enforcer = new BrowserPolicyEnforcer();
        var r = enforcer.ApplyChrome(FullTarget());
        Assert.True(r.IsSuccess);

        using var key = Registry.LocalMachine.OpenSubKey(ChromePolicyKey, writable: false);
        Assert.NotNull(key);
        Assert.Equal("2", key.GetValue("ProxyMode") as string);
        Assert.Equal("off", key.GetValue("DnsOverHttpsMode") as string);
        Assert.Equal(0, key.GetValue("BuiltInDnsClientEnabled") as int?);
    }

    [Fact]
    public void ApplyEdge_WritesAllPolicyValues()
    {
        if (!IsAdministrator()) return;
        var enforcer = new BrowserPolicyEnforcer();
        var r = enforcer.ApplyEdge(FullTarget());
        Assert.True(r.IsSuccess);

        using var key = Registry.LocalMachine.OpenSubKey(EdgePolicyKey, writable: false);
        Assert.NotNull(key);
        Assert.Equal("2", key.GetValue("ProxyMode") as string);
        Assert.Equal("off", key.GetValue("DnsOverHttpsMode") as string);
        Assert.Equal(0, key.GetValue("BuiltInDnsClientEnabled") as int?);
    }

    [Fact]
    public void ApplyAll_BothBrowsers_Succeeds()
    {
        var enforcer = new BrowserPolicyEnforcer();
        var section = new BrowserPolicySection
        {
            Chrome = FullTarget(),
            Edge = FullTarget()
        };
        var r = enforcer.ApplyAll(section);
        // 非管理员时 ApplyAll 返回失败（ExternalError），管理员时返回成功
        if (IsAdministrator())
        {
            Assert.True(r.IsSuccess);
        }
    }

    [Fact]
    public void IsChromePolicyApplied_AfterApply_ReturnsTrue()
    {
        if (!IsAdministrator()) return;
        var enforcer = new BrowserPolicyEnforcer();
        enforcer.ApplyChrome(FullTarget());
        Assert.True(enforcer.IsChromePolicyApplied(FullTarget()));
    }

    [Fact]
    public void IsEdgePolicyApplied_AfterApply_ReturnsTrue()
    {
        if (!IsAdministrator()) return;
        var enforcer = new BrowserPolicyEnforcer();
        enforcer.ApplyEdge(FullTarget());
        Assert.True(enforcer.IsEdgePolicyApplied(FullTarget()));
    }

    [Fact]
    public void IsChromePolicyApplied_PartialTarget_ReturnsFalse()
    {
        if (!IsAdministrator()) return;
        var enforcer = new BrowserPolicyEnforcer();
        enforcer.ApplyChrome(FullTarget());
        var partialTarget = new BrowserPolicyTarget
        {
            DisableCustomProxy = false,
            DisableDoh = true,
            DisableSecureDns = true
        };
        Assert.False(enforcer.IsChromePolicyApplied(partialTarget));
    }

    [Fact]
    public void ApplyChrome_DisableDohOnly_WritesOnlyDohValue()
    {
        if (!IsAdministrator()) return;
        var target = new BrowserPolicyTarget
        {
            DisableCustomProxy = false,
            DisableDoh = true,
            DisableSecureDns = false
        };
        var enforcer = new BrowserPolicyEnforcer();
        var r = enforcer.ApplyChrome(target);
        Assert.True(r.IsSuccess);

        using var key = Registry.LocalMachine.OpenSubKey(ChromePolicyKey, writable: false);
        Assert.NotNull(key);
        Assert.Equal("off", key.GetValue("DnsOverHttpsMode") as string);
    }

    [Fact]
    public void ApplyChrome_NullTarget_Throws()
    {
        // 参数校验不需要管理员权限
        var enforcer = new BrowserPolicyEnforcer();
        Assert.Throws<ArgumentNullException>(() => enforcer.ApplyChrome(null!));
    }
}
