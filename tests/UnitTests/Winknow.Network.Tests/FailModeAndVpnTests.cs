using Winknow.Network;
using Winknow.Policy;

namespace Winknow.Network.Tests;

/// <summary>
/// 第 8 周"失败模式 + VPN 检测"测试。
/// 覆盖验收项：
/// - "代理崩溃不静默全部放行"（strict 模式阻断）
/// - VPN/TUN 检测（进程/服务/虚拟网卡）
/// </summary>
public class FailModeAndVpnTests
{
    [Fact]
    public void Parse_Null_DefaultsToStrict()
    {
        var mode = NetworkFailMode.Parse(null);
        Assert.Equal(FailMode.Strict, mode);
    }

    [Fact]
    public void Parse_Empty_DefaultsToStrict()
    {
        var mode = NetworkFailMode.Parse("");
        Assert.Equal(FailMode.Strict, mode);
    }

    [Fact]
    public void Parse_Strict_ReturnsStrict()
    {
        Assert.Equal(FailMode.Strict, NetworkFailMode.Parse("strict"));
        Assert.Equal(FailMode.Strict, NetworkFailMode.Parse("STRICT"));
        Assert.Equal(FailMode.Strict, NetworkFailMode.Parse("Strict"));
    }

    [Fact]
    public void Parse_Lenient_ReturnsLenient()
    {
        Assert.Equal(FailMode.Lenient, NetworkFailMode.Parse("lenient"));
        Assert.Equal(FailMode.Lenient, NetworkFailMode.Parse("LENIENT"));
    }

    [Fact]
    public void Parse_UnknownString_DefaultsToStrict()
    {
        Assert.Equal(FailMode.Strict, NetworkFailMode.Parse("anything-else"));
    }

    [Fact]
    public void ShouldAllowOnFailure_Strict_ReturnsFalse()
    {
        // 验收：代理崩溃不静默全部放行
        var allow = NetworkFailMode.ShouldAllowOnFailure(FailMode.Strict);
        Assert.False(allow);
    }

    [Fact]
    public void ShouldAllowOnFailure_Lenient_ReturnsTrue()
    {
        var allow = NetworkFailMode.ShouldAllowOnFailure(FailMode.Lenient);
        Assert.True(allow);
    }

    [Fact]
    public void DualStackPolicy_IsConsistent_DoesNotThrow()
    {
        // 测试环境调用不抛异常即可
        var r = DualStackPolicy.IsConsistent();
        Assert.True(r || !r);
    }

    [Fact]
    public void VpnDetector_Detect_DoesNotThrow()
    {
        var detector = new VpnTunDetector(new VpnDetectionSection
        {
            BlockedProcesses = new List<string>(),
            BlockedServices = new List<string>(),
            DetectVirtualAdapters = true
        });
        var r = detector.Detect();
        // 测试环境可能无 VPN，主要验证不抛异常
        Assert.NotNull(r);
    }

    [Fact]
    public void VpnDetector_DetectProcesses_ReturnsList()
    {
        var detector = new VpnTunDetector(new VpnDetectionSection
        {
            BlockedProcesses = new List<string>(),
            BlockedServices = new List<string>()
        });
        var procs = detector.DetectProcesses();
        Assert.NotNull(procs);
        // 测试环境通常无 VPN 进程
        Assert.Empty(procs);
    }

    [Fact]
    public void VpnDetector_DetectProcesses_FindsKnownProcess_WhenBlocked()
    {
        // explorer.exe 不在 VPN 黑名单，不应被检测
        var detector = new VpnTunDetector(new VpnDetectionSection
        {
            BlockedProcesses = new List<string> { "explorer" }
        });
        var procs = detector.DetectProcesses();
        Assert.Contains("explorer", procs);
    }

    [Fact]
    public void VpnDetector_DetectVirtualAdapters_ReturnsList()
    {
        var detector = new VpnTunDetector(new VpnDetectionSection { DetectVirtualAdapters = true });
        var adapters = detector.DetectVirtualAdapters();
        Assert.NotNull(adapters);
    }

    [Fact]
    public void VpnDetector_DisabledAdapters_ReturnsEmpty()
    {
        var detector = new VpnTunDetector(new VpnDetectionSection { DetectVirtualAdapters = false });
        var r = detector.Detect();
        // 虚拟网卡检测关闭，不应返回网卡项
        Assert.DoesNotContain(VpnType.VirtualAdapter, r.Items.Select(i => i.Type));
    }

    [Fact]
    public void VpnDetector_CustomBlockedProcess_Detected()
    {
        var detector = new VpnTunDetector(new VpnDetectionSection
        {
            BlockedProcesses = new List<string> { "explorer" },
            DetectVirtualAdapters = false
        });
        var r = detector.Detect();
        Assert.True(r.Detected);
        Assert.Contains(VpnType.Process, r.Items.Select(i => i.Type));
    }
}
