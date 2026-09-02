using Winknow.Ipc;

namespace Winknow.Ipc.Tests;

/// <summary>
/// P2-01 连接级 RequestId 防重放：严格递增；重连产生新连接即重置基线。
/// </summary>
public sealed class IpcConnectionGuardTests
{
    [Fact]
    public void Track_StrictlyIncreasingIds_ShouldAllPass()
    {
        var guard = new IpcConnectionGuard();
        Assert.True(guard.Track(1));
        Assert.True(guard.Track(2));
        Assert.True(guard.Track(100));
    }

    [Fact]
    public void Track_ReplayedRequestId_ShouldReject()
    {
        var guard = new IpcConnectionGuard();
        Assert.True(guard.Track(5));
        Assert.False(guard.Track(5));
    }

    [Fact]
    public void Track_LowerRequestId_ShouldReject()
    {
        var guard = new IpcConnectionGuard();
        Assert.True(guard.Track(10));
        Assert.False(guard.Track(9));
    }

    [Fact]
    public void Track_NewGuard_ShouldResetBaseline()
    {
        // 重连产生新连接即重置：新连接允许从头计数
        var first = new IpcConnectionGuard();
        Assert.True(first.Track(1000));

        var second = new IpcConnectionGuard();
        Assert.True(second.Track(1));
    }

    [Fact]
    public void LastRequestId_ShouldTrackHighestAccepted()
    {
        var guard = new IpcConnectionGuard();
        guard.Track(7);
        guard.Track(3); // 拒绝，不影响水位
        Assert.Equal(7, guard.LastRequestId);
    }
}

/// <summary>
/// P2-03 断线重连指数退避：翻倍增长、封顶、成功归位。
/// </summary>
public sealed class ReconnectBackoffTests
{
    [Fact]
    public void Next_ConsecutiveFailures_ShouldDouble()
    {
        var backoff = new ReconnectBackoff(initialMs: 1000, maxMs: 60_000);
        Assert.Equal(1000, backoff.Next().TotalMilliseconds);
        Assert.Equal(2000, backoff.Next().TotalMilliseconds);
        Assert.Equal(4000, backoff.Next().TotalMilliseconds);
    }

    [Fact]
    public void Next_ShouldCapAtMax()
    {
        var backoff = new ReconnectBackoff(initialMs: 30_000, maxMs: 60_000);
        Assert.Equal(30_000, backoff.Next().TotalMilliseconds);
        Assert.Equal(60_000, backoff.Next().TotalMilliseconds);
        Assert.Equal(60_000, backoff.Next().TotalMilliseconds);
    }

    [Fact]
    public void Reset_AfterSuccess_ShouldReturnToInitial()
    {
        var backoff = new ReconnectBackoff(initialMs: 1000, maxMs: 60_000);
        backoff.Next();
        backoff.Next();

        backoff.Reset();

        Assert.Equal(1000, backoff.Next().TotalMilliseconds);
    }

    [Fact]
    public void Constructor_InvalidParameters_ShouldThrow()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ReconnectBackoff(initialMs: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ReconnectBackoff(initialMs: 100, maxMs: 50));
    }
}

/// <summary>
/// P2-01 固定时间比较：长度不同仍返回 false 且不提前泄露。
/// </summary>
public sealed class FixedTimeEqualsTests
{
    [Theory]
    [InlineData("S-1-5-21-1", "S-1-5-21-1", true)]
    [InlineData("S-1-5-21-1", "S-1-5-21-2", false)]
    [InlineData("", "", true)]
    [InlineData("abc", "abd", false)]
    public void FixedTimeEquals_Strings_ShouldCompare(string left, string right, bool expected)
    {
        Assert.Equal(expected, Winknow.Core.SecurityUtils.FixedTimeEquals(left, right));
    }

    [Fact]
    public void FixedTimeEquals_DifferentLengths_ShouldReturnFalse()
    {
        var left = new byte[] { 1, 2, 3 };
        var right = new byte[] { 1, 2 };
        Assert.False(Winknow.Core.SecurityUtils.FixedTimeEquals(left, right));
        Assert.False(Winknow.Core.SecurityUtils.FixedTimeEquals("short", "much-longer-string"));
    }

    [Fact]
    public void FixedTimeEquals_NullArguments_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(
            () => Winknow.Core.SecurityUtils.FixedTimeEquals((byte[])null!, new byte[1]));
    }
}
