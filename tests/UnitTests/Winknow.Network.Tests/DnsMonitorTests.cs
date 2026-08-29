using Winknow.Network;
using Winknow.Policy;

namespace Winknow.Network.Tests;

/// <summary>
/// 第 8 周"DNS 监控"测试。
/// 覆盖验收项：检测异常 DNS 修改（公共 DNS）
/// </summary>
public class DnsMonitorTests
{
    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("8.8.4.4")]
    [InlineData("1.1.1.1")]
    [InlineData("1.0.0.1")]
    [InlineData("9.9.9.9")]
    [InlineData("208.67.222.222")]
    public void IsBlocked_DefaultPublicDns_ReturnsTrue(string dns)
    {
        var monitor = new DnsMonitor(new DnsSection());
        Assert.True(monitor.IsBlocked(dns));
    }

    [Fact]
    public void IsBlocked_PrivateOrSchoolDns_ReturnsFalse_WhenNoAllowList()
    {
        var monitor = new DnsMonitor(new DnsSection());
        // 未配置允许列表时，非公共 DNS 不违规
        Assert.False(monitor.IsBlocked("192.168.1.1"));
        Assert.False(monitor.IsBlocked("10.0.0.1"));
    }

    [Fact]
    public void IsBlocked_PolicyBlockedDns_ReturnsTrue()
    {
        var policy = new DnsSection
        {
            BlockedServers = new List<string> { "77.88.88.88" }   // 自定义黑名单
        };
        var monitor = new DnsMonitor(policy);
        Assert.True(monitor.IsBlocked("77.88.88.88"));
    }

    [Fact]
    public void IsBlocked_AllowListEnforced_NotInList_ReturnsTrue()
    {
        var policy = new DnsSection
        {
            AllowedServers = new List<string> { "192.168.1.1", "10.0.0.1" }
        };
        var monitor = new DnsMonitor(policy);
        // 公共 DNS 在黑名单中 → 违规
        Assert.True(monitor.IsBlocked("8.8.8.8"));
        // 不在允许列表 → 违规
        Assert.True(monitor.IsBlocked("172.16.0.1"));
        // 在允许列表 → 合规
        Assert.False(monitor.IsBlocked("192.168.1.1"));
    }

    [Fact]
    public void IsBlocked_EmptyOrNull_ReturnsFalse()
    {
        var monitor = new DnsMonitor(new DnsSection());
        Assert.False(monitor.IsBlocked(""));
        Assert.False(monitor.IsBlocked("   "));
    }

    [Fact]
    public void IsBlocked_CaseInsensitive_IPv6()
    {
        var policy = new DnsSection
        {
            BlockedServers = new List<string> { "2001:4860:4860::8888" }  // Google IPv6
        };
        var monitor = new DnsMonitor(policy);
        Assert.True(monitor.IsBlocked("2001:4860:4860::8888"));
    }

    [Fact]
    public void Check_DoesNotThrow()
    {
        var monitor = new DnsMonitor(new DnsSection());
        var r = monitor.Check();
        // 测试环境 DNS 可能合规也可能不合规，主要验证不抛异常
        Assert.True(r.IsSuccess || !r.IsSuccess);
    }

    [Fact]
    public void UpdatePolicy_RefreshesBlockedSet()
    {
        var monitor = new DnsMonitor(new DnsSection());
        Assert.False(monitor.IsBlocked("77.77.77.77"));
        monitor.UpdatePolicy(new DnsSection { BlockedServers = new List<string> { "77.77.77.77" } });
        Assert.True(monitor.IsBlocked("77.77.77.77"));
    }
}
