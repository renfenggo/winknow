using Winknow.ControlService.Sessions;

namespace Winknow.ControlService.Tests;

/// <summary>
/// P2-02 会话登记表：登记/注销与 IPC 准入判定（SessionId + UserSid 双匹配）。
/// </summary>
public sealed class SessionRegistryTests
{
    private const string StudentSid = "S-1-5-21-100-200-300-1000";
    private const string OtherSid = "S-1-5-21-999-888-777-6666";

    [Fact]
    public void Register_ThenAdmissionWithMatchingSid_ShouldAllow()
    {
        var registry = new SessionRegistry();
        registry.Register(3, StudentSid);

        Assert.True(registry.IsAdmissionAllowed(3, StudentSid));
    }

    [Fact]
    public void Admission_WithDifferentSid_ShouldDeny()
    {
        // 同会话号但 SID 不匹配（会话 ID 被复用 / 伪造声明）→ 拒绝
        var registry = new SessionRegistry();
        registry.Register(3, StudentSid);

        Assert.False(registry.IsAdmissionAllowed(3, OtherSid));
    }

    [Fact]
    public void Admission_UnregisteredSession_ShouldDeny()
    {
        var registry = new SessionRegistry();
        Assert.False(registry.IsAdmissionAllowed(7, StudentSid));
    }

    [Fact]
    public void Unregister_ThenAdmission_ShouldDeny()
    {
        var registry = new SessionRegistry();
        registry.Register(3, StudentSid);
        Assert.True(registry.Unregister(3));
        Assert.False(registry.IsAdmissionAllowed(3, StudentSid));
    }

    [Fact]
    public void TryGet_AfterRegister_ShouldReturnRecord()
    {
        var registry = new SessionRegistry();
        registry.Register(3, StudentSid);

        Assert.True(registry.TryGet(3, out var record));
        Assert.Equal(3, record!.SessionId);
        Assert.Equal(StudentSid, record.UserSid);
    }

    [Fact]
    public void Register_EmptySid_ShouldThrow()
    {
        var registry = new SessionRegistry();
        Assert.Throws<ArgumentException>(() => registry.Register(3, ""));
    }
}

/// <summary>
/// P2-02 WTS 会话监视器：轮询差异检测（登录/注销/重连/断开）。
/// </summary>
public sealed class WtsSessionMonitorTests
{
    [Fact]
    public void PollOnce_NewActiveSession_ShouldReportLoggedOn()
    {
        var api = new FakeTerminalServicesApi();
        using var monitor = new WtsSessionMonitor(api);

        var changes = monitor.PollOnce();
        Assert.Empty(changes);

        api.Sessions.Add(new WtsSession(1, WtsSessionState.Active));
        var second = monitor.PollOnce();

        var change = Assert.Single(second);
        Assert.Equal(1, change.SessionId);
        Assert.Equal(SessionChangeKind.LoggedOn, change.Kind);
    }

    [Fact]
    public void PollOnce_SessionDisappears_ShouldReportLoggedOff()
    {
        var api = new FakeTerminalServicesApi();
        api.Sessions.Add(new WtsSession(1, WtsSessionState.Active));
        using var monitor = new WtsSessionMonitor(api);

        monitor.PollOnce();
        api.Sessions.Clear();

        var change = Assert.Single(monitor.PollOnce());
        Assert.Equal(SessionChangeKind.LoggedOff, change.Kind);
    }

    [Fact]
    public void PollOnce_DisconnectedToActive_ShouldReportReconnected()
    {
        var api = new FakeTerminalServicesApi();
        api.Sessions.Add(new WtsSession(1, WtsSessionState.Disconnected));
        using var monitor = new WtsSessionMonitor(api);

        monitor.PollOnce();
        api.Sessions[0] = new WtsSession(1, WtsSessionState.Active);

        var change = Assert.Single(monitor.PollOnce());
        Assert.Equal(SessionChangeKind.Reconnected, change.Kind);
    }

    [Fact]
    public void PollOnce_ActiveToDisconnected_ShouldReportDisconnected()
    {
        var api = new FakeTerminalServicesApi();
        api.Sessions.Add(new WtsSession(1, WtsSessionState.Active));
        using var monitor = new WtsSessionMonitor(api);

        monitor.PollOnce();
        api.Sessions[0] = new WtsSession(1, WtsSessionState.Disconnected);

        var change = Assert.Single(monitor.PollOnce());
        Assert.Equal(SessionChangeKind.Disconnected, change.Kind);
    }

    [Fact]
    public void PollOnce_ServiceSessionStateListen_ShouldNotReportLogOn()
    {
        // 服务会话（Listen）不构成用户登录
        var api = new FakeTerminalServicesApi();
        using var monitor = new WtsSessionMonitor(api);

        monitor.PollOnce();
        api.Sessions.Add(new WtsSession(0, WtsSessionState.Listen));

        Assert.Empty(monitor.PollOnce());
    }

    [Fact]
    public void SessionChanged_EventShouldFire()
    {
        var api = new FakeTerminalServicesApi();
        using var monitor = new WtsSessionMonitor(api);

        SessionChange? observed = null;
        monitor.SessionChanged += c => observed = c;

        monitor.PollOnce();
        api.Sessions.Add(new WtsSession(4, WtsSessionState.Active));
        monitor.PollOnce();

        Assert.NotNull(observed);
        Assert.Equal(4, observed!.SessionId);
    }
}

/// <summary>
/// P2-02 Agent 崩溃重启限流：同会话最小间隔 + 每小时上限。
/// </summary>
public sealed class SessionLaunchThrottleTests
{
    [Fact]
    public void IsAllowed_WithinMinInterval_ShouldDeny()
    {
        var throttle = new SessionLaunchThrottle(minInterval: TimeSpan.FromSeconds(10));
        var now = DateTimeOffset.UtcNow;

        Assert.True(throttle.IsAllowed(1, now));
        throttle.Record(1, now);

        Assert.False(throttle.IsAllowed(1, now.AddSeconds(5)));
        Assert.True(throttle.IsAllowed(1, now.AddSeconds(11)));
    }

    [Fact]
    public void IsAllowed_HourlyCapExceeded_ShouldDeny()
    {
        var throttle = new SessionLaunchThrottle(minInterval: TimeSpan.FromMilliseconds(1), maxPerHour: 2);
        var now = DateTimeOffset.UtcNow;

        throttle.Record(1, now);
        throttle.Record(1, now.AddSeconds(1));

        Assert.False(throttle.IsAllowed(1, now.AddSeconds(2)));
    }

    [Fact]
    public void IsAllowed_SlidingWindowExpire_ShouldAllowAgain()
    {
        var throttle = new SessionLaunchThrottle(minInterval: TimeSpan.FromMilliseconds(1), maxPerHour: 2);
        var now = DateTimeOffset.UtcNow;

        throttle.Record(1, now);
        throttle.Record(1, now.AddSeconds(1));

        // 1 小时后窗口滑出，重新允许
        Assert.True(throttle.IsAllowed(1, now.AddHours(1).AddSeconds(2)));
    }

    [Fact]
    public void IsAllowed_PerSessionIndependent()
    {
        var throttle = new SessionLaunchThrottle(minInterval: TimeSpan.FromSeconds(10));
        var now = DateTimeOffset.UtcNow;

        throttle.Record(1, now);
        Assert.False(throttle.IsAllowed(1, now.AddSeconds(1)));
        Assert.True(throttle.IsAllowed(2, now.AddSeconds(1)));
    }

    [Fact]
    public void Constructor_InvalidParameters_ShouldThrow()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new SessionLaunchThrottle(minInterval: TimeSpan.Zero, maxPerHour: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new SessionLaunchThrottle(minInterval: TimeSpan.FromSeconds(-1)));
    }
}
