namespace Winknow.Core.Guarding;

/// <summary>
/// 指数退避计算器（重启间隔控制）。
///
/// 用途：V7.0 第 10 周"指数退避——重启间隔控制"。
/// 满足验收"不出现重启风暴"：连续重启时间隔按 base×2^n 递增并封顶，
/// 使崩溃循环的 CPU/IO 占用收敛而非放大。
///
/// 设计：
/// - 时间源可注入（Func&lt;DateTimeOffset&gt;），便于单元测试确定性验证。
/// - 封顶值防止无限增长导致服务长时间不可监控。
/// - Attempt 计数由调用方在成功重启后 Reset。
/// </summary>
public sealed class ExponentialBackoff
{
    private readonly TimeSpan _baseDelay;
    private readonly TimeSpan _capDelay;
    private readonly Func<double> _jitterSource;

    /// <summary>当前连续失败次数（从 0 开始）。</summary>
    public int Attempt { get; private set; }

    /// <summary>
    /// 构造指数退避器。
    /// </summary>
    /// <param name="baseDelay">首次延迟（默认 1 秒）。</param>
    /// <param name="capDelay">延迟上限（默认 60 秒）。</param>
    /// <param name="jitterSource">抖动因子源，返回 [0,1)（默认随机，测试注入固定值）。</param>
    public ExponentialBackoff(
        TimeSpan? baseDelay = null,
        TimeSpan? capDelay = null,
        Func<double>? jitterSource = null)
    {
        _baseDelay = baseDelay ?? TimeSpan.FromSeconds(Constants.Guard.BackoffBaseSeconds);
        _capDelay = capDelay ?? TimeSpan.FromSeconds(Constants.Guard.BackoffCapSeconds);
        _jitterSource = jitterSource ?? (() => Random.Shared.NextDouble());

        if (_baseDelay <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(baseDelay));
        if (_capDelay < _baseDelay) throw new ArgumentOutOfRangeException(nameof(capDelay), "上限不得小于基准延迟");
    }

    /// <summary>
    /// 计算下一次等待延迟（不递增计数）：base×2^attempt，封顶后加 0-25% 抖动。
    /// 抖动防止多台机器同步重启形成共振负载。
    /// </summary>
    public TimeSpan NextDelay()
    {
        // base×2^attempt，用 double 避免大 attempt 位溢出
        var seconds = _baseDelay.TotalSeconds * Math.Pow(2, Math.Min(Attempt, 30));
        if (seconds > _capDelay.TotalSeconds)
        {
            seconds = _capDelay.TotalSeconds;
        }

        // 封顶后叠加 0-25% 抖动；未封顶时严格按 2 的幂保持可预测的递增序列
        if (Attempt >= CapAttempt)
        {
            seconds *= 1.0 + _jitterSource() * 0.25;
        }

        return TimeSpan.FromSeconds(seconds);
    }

    /// <summary>延迟封顶对应的 attempt 次数。</summary>
    public int CapAttempt => (int)Math.Ceiling(Math.Log2(_capDelay.TotalSeconds / _baseDelay.TotalSeconds));

    /// <summary>记录一次失败，attempt+1。</summary>
    public void OnFailure() => Attempt++;

    /// <summary>重启成功后归零，下次失败重新从基准延迟开始。</summary>
    public void Reset() => Attempt = 0;
}
