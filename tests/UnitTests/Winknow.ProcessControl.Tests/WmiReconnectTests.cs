using Winknow.ProcessControl;

namespace Winknow.ProcessControl.Tests;

/// <summary>
/// WMI watcher 重连策略测试（第 13 周综合测试范围 #5"WMI 丢事件和重连"）。
/// </summary>
public sealed class WmiReconnectTests
{
    // ─────────────────── WatcherReconnectPolicy（纯逻辑） ───────────────────

    [Fact]
    public void Failure_BackoffDoublesProgressively()
    {
        var policy = new WatcherReconnectPolicy(
            baseDelay: TimeSpan.FromSeconds(1),
            maxDelay: TimeSpan.FromSeconds(60));

        Assert.Equal(TimeSpan.FromSeconds(1), policy.OnWatcherFailure()); // 第 1 次：1s
        Assert.Equal(TimeSpan.FromSeconds(2), policy.OnWatcherFailure()); // 第 2 次：2s
        Assert.Equal(TimeSpan.FromSeconds(4), policy.OnWatcherFailure()); // 第 3 次：4s
        Assert.Equal(TimeSpan.FromSeconds(8), policy.OnWatcherFailure()); // 第 4 次：8s
    }

    [Fact]
    public void Failure_CapsAtMaxDelay()
    {
        var policy = new WatcherReconnectPolicy(
            baseDelay: TimeSpan.FromSeconds(1),
            maxDelay: TimeSpan.FromSeconds(10));

        for (var i = 0; i < 8; i++)
        {
            policy.OnWatcherFailure();
        }
        // 2^7=128s > 封顶 10s
        Assert.Equal(TimeSpan.FromSeconds(10), policy.OnWatcherFailure());
    }

    [Fact]
    public void Success_ResetsBackoffButNotReconnectCount()
    {
        var policy = new WatcherReconnectPolicy();
        policy.OnWatcherFailure();
        policy.OnWatcherFailure();
        Assert.Equal(2, policy.ReconnectCount);

        policy.OnSuccess();
        Assert.Equal(0, policy.ConsecutiveFailures);

        // 恢复后再故障：退避从头开始（1s），但累计重连数继续增长
        Assert.Equal(TimeSpan.FromSeconds(1), policy.OnWatcherFailure());
        Assert.Equal(3, policy.ReconnectCount);
    }

    [Fact]
    public void PersistentFailure_DetectedByThreshold()
    {
        var policy = new WatcherReconnectPolicy();
        Assert.False(policy.IsPersistentlyFailing());

        for (var i = 0; i < 5; i++)
        {
            policy.OnWatcherFailure();
        }
        Assert.True(policy.IsPersistentlyFailing()); // 灰度监控上报阈值

        policy.OnSuccess();
        Assert.False(policy.IsPersistentlyFailing());
    }

    [Fact]
    public void Constructor_RejectsInvalidDelays()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new WatcherReconnectPolicy(baseDelay: TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new WatcherReconnectPolicy(
                baseDelay: TimeSpan.FromSeconds(10),
                maxDelay: TimeSpan.FromSeconds(1)));
    }

    // ─────────────────── WmiProcessMonitor（真实 WMI 烟测） ───────────────────

    [Fact]
    public void Monitor_StartStop_CleanLifecycle_NeverThrows()
    {
        // 无论当前进程是否有 WMI 事件订阅权限（ProcessStartTrace 需管理员），
        // Start/Stop 生命周期必须干净：成功启动或进入退避重连，绝不抛异常。
        using var monitor = new WmiProcessMonitor();
        monitor.Start();
        monitor.Stop();
        monitor.Dispose();
    }

    [Fact]
    public void Monitor_ExposeReconnectCounters()
    {
        using var monitor = new WmiProcessMonitor();
        Assert.Equal(0, monitor.ReconnectCount);
        Assert.Equal(0, monitor.ConsecutiveFailures);
    }

    [Fact]
    public void Monitor_DoubleDisposeSafe()
    {
        var monitor = new WmiProcessMonitor();
        monitor.Dispose();
        monitor.Dispose();
    }
}
