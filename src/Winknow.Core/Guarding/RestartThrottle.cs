namespace Winknow.Core.Guarding;

/// <summary>
/// 重启限流器（滑动窗口内最大重启次数）。
///
/// 用途：V7.0 第 10 周"重启阈值——单位时间最大次数"。
/// 满足验收"不出现重启风暴"：滑动窗口（默认 10 分钟）内最多重启 5 次，
/// 超出后 <see cref="CanRestart"/> 返回 false，调用方应转入 Safe Degraded Mode。
///
/// 与指数退避的关系：退避控制"两次重启之间等多久"，限流控制"窗口内最多重启几次"。
/// 两者叠加构成完整的重启风暴防线。
///
/// 时间源可注入，便于测试。
/// </summary>
public sealed class RestartThrottle
{
    private readonly TimeSpan _window;
    private readonly int _maxRestarts;
    private readonly Func<DateTimeOffset> _clock;
    private readonly List<DateTimeOffset> _restarts = new();

    /// <summary>
    /// 构造重启限流器。
    /// </summary>
    /// <param name="window">滑动窗口（默认 10 分钟）。</param>
    /// <param name="maxRestarts">窗口内最大重启次数（默认 5）。</param>
    /// <param name="clock">时间源（默认 UtcNow，测试注入）。</param>
    public RestartThrottle(
        TimeSpan? window = null,
        int? maxRestarts = null,
        Func<DateTimeOffset>? clock = null)
    {
        _window = window ?? TimeSpan.FromMinutes(Constants.Guard.ThrottleWindowMinutes);
        _maxRestarts = maxRestarts ?? Constants.Guard.MaxRestartsPerWindow;
        _clock = clock ?? (static () => DateTimeOffset.UtcNow);

        if (_window <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(window));
        if (_maxRestarts <= 0) throw new ArgumentOutOfRangeException(nameof(maxRestarts));
    }

    /// <summary>当前窗口内已记录的重启次数。</summary>
    public int CurrentWindowCount => PruneExpired().Count;

    /// <summary>窗口内剩余可用重启次数。</summary>
    public int RemainingAllowance => Math.Max(0, _maxRestarts - CurrentWindowCount);

    /// <summary>是否已超阈值（当前窗口重启次数达到上限）。</summary>
    public bool IsThrottled => CurrentWindowCount >= _maxRestarts;

    /// <summary>
    /// 判断此刻是否允许重启。未超阈值返回 true。
    /// 只读操作，不记录。
    /// </summary>
    public bool CanRestart() => !IsThrottled;

    /// <summary>
    /// 记录一次重启。超阈值时返回 false 且不记录（调用方应先检查 CanRestart）。
    /// </summary>
    /// <returns>记录成功返回 true；已超阈值返回 false。</returns>
    public bool RecordRestart()
    {
        if (IsThrottled) return false;
        _restarts.Add(_clock());
        return true;
    }

    /// <summary>
    /// 判断窗口是否已滑出（最早的记录已过期），可用于降级模式的周期性复核。
    /// </summary>
    public bool WindowElapsed()
    {
        var active = PruneExpired();
        return active.Count == 0;
    }

    /// <summary>清空记录（服务手动恢复或管理员干预后调用）。</summary>
    public void Clear() => _restarts.Clear();

    private List<DateTimeOffset> PruneExpired()
    {
        var now = _clock();
        _restarts.RemoveAll(t => now - t >= _window);
        return _restarts;
    }
}
