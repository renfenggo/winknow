using Winknow.Core;
using Winknow.Core.Guarding;

namespace Winknow.Guard.Tests;

/// <summary>
/// 第 10 周守护组件单元测试：指数退避 / 重启限流 / 安全降级。
/// </summary>
public sealed class GuardingComponentsTests
{
    // ───────────────────────── ExponentialBackoff ─────────────────────────

    [Fact]
    public void Backoff_FirstDelay_IsBase()
    {
        var backoff = new ExponentialBackoff(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(60));
        Assert.Equal(TimeSpan.FromSeconds(1), backoff.NextDelay());
    }

    [Fact]
    public void Backoff_Delays_DoubleProgressively()
    {
        var backoff = new ExponentialBackoff(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(60));
        var delays = new List<double>();

        for (var i = 0; i < 4; i++)
        {
            delays.Add(backoff.NextDelay().TotalSeconds);
            backoff.OnFailure();
        }

        // 1s → 2s → 4s → 8s：严格 2 的幂（未封顶区间无抖动）
        Assert.Equal(new[] { 1, 2, 4, 8 }, delays.Select(d => (int)d).ToArray());
    }

    [Fact]
    public void Backoff_Delay_CapsAtMaximum()
    {
        var backoff = new ExponentialBackoff(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(60));
        for (var i = 0; i < 10; i++) backoff.OnFailure();

        var delay = backoff.NextDelay().TotalSeconds;
        Assert.True(delay is > 60 and <= 60 * 1.25, $"封顶+抖动区间外的值: {delay}");
    }

    [Fact]
    public void Backoff_Jitter_OnlyAppliedAfterCap()
    {
        var backoff = new ExponentialBackoff(
            TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(4), jitterSource: () => 1.0);

        // 未封顶：无抖动，精确 2s
        backoff.OnFailure();
        Assert.Equal(TimeSpan.FromSeconds(2), backoff.NextDelay());

        // 封顶（attempt=2 → 4s=cap）：抖动最大 +25% → 5s
        backoff.OnFailure();
        Assert.Equal(TimeSpan.FromSeconds(5), backoff.NextDelay());
    }

    [Fact]
    public void Backoff_Reset_RestartsFromBase()
    {
        var backoff = new ExponentialBackoff(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(60));
        backoff.OnFailure();
        backoff.OnFailure();
        backoff.Reset();

        Assert.Equal(0, backoff.Attempt);
        Assert.Equal(TimeSpan.FromSeconds(1), backoff.NextDelay());
    }

    [Fact]
    public void Backoff_Constructor_RejectsInvalidRanges()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new ExponentialBackoff(TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new ExponentialBackoff(TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(1)));
    }

    // ───────────────────────── RestartThrottle ─────────────────────────

    [Fact]
    public void Throttle_AllowsRestart_Initially()
    {
        var throttle = new RestartThrottle();
        Assert.True(throttle.CanRestart());
        Assert.False(throttle.IsThrottled);
    }

    [Fact]
    public void Throttle_BlocksAfter_MaxRestarts_InWindow()
    {
        var now = DateTimeOffset.Parse("2026-01-01T10:00:00Z");
        var throttle = new RestartThrottle(
            window: TimeSpan.FromMinutes(10), maxRestarts: 5, clock: () => now);

        for (var i = 0; i < 5; i++)
        {
            Assert.True(throttle.RecordRestart());
        }

        Assert.True(throttle.IsThrottled);
        Assert.False(throttle.CanRestart());
        Assert.Equal(5, throttle.CurrentWindowCount);
    }

    [Fact]
    public void Throttle_WindowSlides_RestartsAllowedAgain()
    {
        var now = DateTimeOffset.Parse("2026-01-01T10:00:00Z");
        var throttle = new RestartThrottle(
            window: TimeSpan.FromMinutes(10), maxRestarts: 5, clock: () => now);

        for (var i = 0; i < 5; i++) throttle.RecordRestart();
        Assert.True(throttle.IsThrottled);

        // 时间前进 10.5 分钟：窗口滑出，限流解除
        now = now.AddMinutes(10).AddSeconds(30);
        Assert.False(throttle.IsThrottled);
        Assert.True(throttle.CanRestart());
        Assert.True(throttle.WindowElapsed());
    }

    [Fact]
    public void Throttle_PartialExpiry_KeepsRecentRestarts()
    {
        var now = DateTimeOffset.Parse("2026-01-01T10:00:00Z");
        var throttle = new RestartThrottle(
            window: TimeSpan.FromMinutes(10), maxRestarts: 5, clock: () => now);

        // 10:00 两次，10:08 三次
        throttle.RecordRestart();
        throttle.RecordRestart();
        now = now.AddMinutes(8);
        throttle.RecordRestart();
        throttle.RecordRestart();
        throttle.RecordRestart();

        // 10:15：最早的两次滑出，剩 3 次 → 不再限流
        now = now.AddMinutes(7);
        Assert.Equal(3, throttle.CurrentWindowCount);
        Assert.False(throttle.IsThrottled);
    }

    [Fact]
    public void Throttle_RecordRestart_RejectedWhenThrottled()
    {
        var now = DateTimeOffset.Parse("2026-01-01T10:00:00Z");
        var throttle = new RestartThrottle(
            window: TimeSpan.FromMinutes(10), maxRestarts: 2, clock: () => now);

        Assert.True(throttle.RecordRestart());
        Assert.True(throttle.RecordRestart());
        Assert.False(throttle.RecordRestart()); // 超阈值拒绝记录
        Assert.Equal(2, throttle.CurrentWindowCount);
    }

    [Fact]
    public void Throttle_Clear_ResetsAll()
    {
        var throttle = new RestartThrottle();
        throttle.RecordRestart();
        throttle.Clear();
        Assert.Equal(0, throttle.CurrentWindowCount);
        Assert.True(throttle.CanRestart());
    }

    // ───────────────────────── SafeDegradedMode ─────────────────────────

    [Fact]
    public void Degraded_InitiallyNormal()
    {
        var mode = new SafeDegradedMode();
        Assert.False(mode.IsDegraded);
        Assert.False(mode.ShouldKeepMinimumControl);
    }

    [Fact]
    public void Degraded_Enter_SetsReason()
    {
        var mode = new SafeDegradedMode();
        mode.EnterDegraded("ControlService", "5 次重启超阈值");

        Assert.True(mode.IsDegraded);
        Assert.True(mode.ShouldKeepMinimumControl);
        Assert.Equal("ControlService", mode.Reason!.Component);
        Assert.Equal(1, mode.TotalDegradedCount);
    }

    [Fact]
    public void Degraded_EnterIsIdempotent_KeepsFirstReason()
    {
        var mode = new SafeDegradedMode();
        mode.EnterDegraded("ControlService", "第一次原因");
        mode.EnterDegraded("ControlService", "第二次原因");

        Assert.Equal("第一次原因", mode.Reason!.Detail);
        Assert.Equal(1, mode.TotalDegradedCount);
    }

    [Fact]
    public void Degraded_ExitBlocked_DuringCooldown()
    {
        var now = DateTimeOffset.Parse("2026-01-01T10:00:00Z");
        var mode = new SafeDegradedMode(recoveryCooldown: TimeSpan.FromMinutes(2), clock: () => now);

        mode.EnterDegraded("ControlService", "超阈值");
        now = now.AddMinutes(1); // 冷却期内

        Assert.False(mode.TryExitDegraded());
        Assert.True(mode.IsDegraded);
    }

    [Fact]
    public void Degraded_ExitSucceeds_AfterCooldown()
    {
        var now = DateTimeOffset.Parse("2026-01-01T10:00:00Z");
        var mode = new SafeDegradedMode(recoveryCooldown: TimeSpan.FromMinutes(2), clock: () => now);

        mode.EnterDegraded("ControlService", "超阈值");
        now = now.AddMinutes(3);

        Assert.True(mode.TryExitDegraded());
        Assert.False(mode.IsDegraded);
        Assert.Null(mode.DegradedSince);
    }

    [Fact]
    public void Degraded_MinimumControl_IsFailClosed()
    {
        // 验收"恢复失败时不自动全部放行"：
        // 降级语义恒等于"保持最低管控"，绝不映射为"放行"
        var mode = new SafeDegradedMode();
        mode.EnterDegraded("x", "y");
        Assert.True(mode.ShouldKeepMinimumControl);

        // 全生命周期检查：任何时刻 IsDegraded ⇒ ShouldKeepMinimumControl
        Assert.Equal(mode.IsDegraded, mode.ShouldKeepMinimumControl);
    }

    // ───────────────────────── 常量一致性 ─────────────────────────

    [Fact]
    public void GuardConstants_MatchPlanRequirements()
    {
        // 计划书第 10 周崩溃循环测试要求连续 20 次
        Assert.Equal(20, Constants.Guard.CrashLoopTestIterations);
        // 心跳 5s、租约超时 15s（3 个周期）、限流 10 分钟 5 次
        Assert.Equal(5, Constants.Guard.HeartbeatIntervalSeconds);
        Assert.Equal(15, Constants.Guard.LeaseTimeoutSeconds);
        Assert.Equal(10, Constants.Guard.ThrottleWindowMinutes);
        Assert.Equal(5, Constants.Guard.MaxRestartsPerWindow);
    }
}
