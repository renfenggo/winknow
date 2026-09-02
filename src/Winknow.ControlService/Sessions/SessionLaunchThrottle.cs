namespace Winknow.ControlService.Sessions;

/// <summary>
/// Agent 崩溃重启限流（P2-02）：防止 Agent 反复崩溃导致拉起风暴。
/// 规则：同一会话两次启动间隔不小于 <see cref="MinInterval"/>，
/// 且滑动 1 小时窗口内启动次数不超过 <see cref="MaxPerHour"/>；超限放弃并交由上层审计。
/// 纯逻辑类，便于单元测试。
/// </summary>
public sealed class SessionLaunchThrottle
{
    /// <summary>同会话最小重启间隔。</summary>
    public TimeSpan MinInterval { get; }

    /// <summary>滑动 1 小时窗口内同会话最大启动次数。</summary>
    public int MaxPerHour { get; }

    private readonly Dictionary<int, DateTimeOffset> _lastLaunch = new();
    private readonly Dictionary<int, Queue<DateTimeOffset>> _recentLaunches = new();

    /// <summary>创建限流器（默认同会话 10 秒间隔、每小时 6 次上限）。</summary>
    public SessionLaunchThrottle(TimeSpan? minInterval = null, int maxPerHour = 6)
    {
        MinInterval = minInterval ?? TimeSpan.FromSeconds(10);
        MaxPerHour = maxPerHour;
        if (MinInterval <= TimeSpan.Zero || MaxPerHour <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(minInterval), "Throttle parameters must be positive.");
        }
    }

    /// <summary>是否允许在当前时刻启动；通过后需调用 <see cref="Record"/> 记账。</summary>
    public bool IsAllowed(int sessionId, DateTimeOffset now)
    {
        if (_lastLaunch.TryGetValue(sessionId, out var last) && now - last < MinInterval)
        {
            return false;
        }

        if (_recentLaunches.TryGetValue(sessionId, out var queue))
        {
            EvictExpired(queue, now);
            if (queue.Count >= MaxPerHour)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>记录一次启动（记账）。</summary>
    public void Record(int sessionId, DateTimeOffset now)
    {
        _lastLaunch[sessionId] = now;

        if (!_recentLaunches.TryGetValue(sessionId, out var queue))
        {
            queue = new Queue<DateTimeOffset>();
            _recentLaunches[sessionId] = queue;
        }

        EvictExpired(queue, now);
        queue.Enqueue(now);
    }

    private static void EvictExpired(Queue<DateTimeOffset> queue, DateTimeOffset now)
    {
        while (queue.Count > 0 && now - queue.Peek() >= TimeSpan.FromHours(1))
        {
            queue.Dequeue();
        }
    }
}
