namespace Winknow.ProcessControl;

/// <summary>
/// WMI watcher 重连策略（V7.0 第 13 周"WMI 丢事件和重连"）。
///
/// 纯逻辑决策器（时间可注入）：watcher 失败（Stopped 事件/启动异常）后
/// 按指数退避重建（1s→2s→4s→…→60s 封顶），事件正常到达即视为恢复归零。
/// ReconnectCount 供灰度观察指标"WMI 重连次数"采集。
///
/// 设计依据：Win32_ProcessStartTrace watcher 在 WMI 服务重启/系统压力下会
/// 收到 Stopped 事件而静默失效——原实现永不重建，仅靠周期扫描兜底；
/// 本策略配合 WmiProcessMonitor 的重建循环使实时监听自愈。
/// </summary>
public sealed class WatcherReconnectPolicy
{
    private readonly TimeSpan _baseDelay;
    private readonly TimeSpan _maxDelay;
    private readonly Func<DateTimeOffset> _clock;
    private int _consecutiveFailures;

    /// <summary>
    /// 构造重连策略。
    /// </summary>
    /// <param name="baseDelay">首次重连延迟（默认 1 秒）。</param>
    /// <param name="maxDelay">延迟封顶（默认 60 秒）。</param>
    /// <param name="clock">时间源（测试注入）。</param>
    public WatcherReconnectPolicy(
        TimeSpan? baseDelay = null,
        TimeSpan? maxDelay = null,
        Func<DateTimeOffset>? clock = null)
    {
        _baseDelay = baseDelay ?? TimeSpan.FromSeconds(1);
        _maxDelay = maxDelay ?? TimeSpan.FromSeconds(60);
        if (_baseDelay <= TimeSpan.Zero || _maxDelay < _baseDelay)
        {
            throw new ArgumentOutOfRangeException(nameof(baseDelay), "延迟参数需满足 0 < base ≤ max");
        }
        _clock = clock ?? (static () => DateTimeOffset.UtcNow);
    }

    /// <summary>累计重连次数（观察指标，只增不减直到进程重启）。</summary>
    public int ReconnectCount { get; private set; }

    /// <summary>当前连续失败次数（0 表示健康）。</summary>
    public int ConsecutiveFailures => _consecutiveFailures;

    /// <summary>
    /// watcher 失败时调用：递增失败计数，返回本次重连应等待的延迟。
    /// </summary>
    public TimeSpan OnWatcherFailure()
    {
        _consecutiveFailures++;
        ReconnectCount++;
        var exp = _baseDelay.TotalMilliseconds * Math.Pow(2, _consecutiveFailures - 1);
        var capped = Math.Min(exp, _maxDelay.TotalMilliseconds);
        return TimeSpan.FromMilliseconds(capped);
    }

    /// <summary>
    /// watcher 成功启动或事件正常到达时调用：连续失败归零。
    /// </summary>
    public void OnSuccess() => _consecutiveFailures = 0;

    /// <summary>
    /// 当前是否处于持续故障（连续失败达到阈值，供监控上报）。
    /// </summary>
    public bool IsPersistentlyFailing(int threshold = 5) => _consecutiveFailures >= threshold;

    /// <summary>当前时间（测试可见）。</summary>
    public DateTimeOffset Now => _clock();
}
