namespace Winknow.Ipc;

/// <summary>
/// 断线重连指数退避计算器（P2-03：Agent 重连使用）。
/// 每次失败翻倍，封顶 MaxBackoff；成功后 Reset 归位。
/// </summary>
public sealed class ReconnectBackoff
{
    private readonly int _initialMs;
    private readonly int _maxMs;
    private int _currentMs;

    /// <summary>创建退避计算器（默认 1s 起、60s 封顶，见 IpcConstants）。</summary>
    public ReconnectBackoff(int? initialMs = null, int? maxMs = null)
    {
        _initialMs = initialMs ?? IpcConstants.ReconnectInitialBackoffMs;
        _maxMs = maxMs ?? IpcConstants.ReconnectMaxBackoffMs;
        if (_initialMs <= 0 || _maxMs < _initialMs)
        {
            throw new ArgumentOutOfRangeException(nameof(initialMs), "Backoff parameters must be positive and max >= initial.");
        }
        _currentMs = _initialMs;
    }

    /// <summary>获取下一次等待时长；连续失败时按指数增长。</summary>
    public TimeSpan Next()
    {
        var delay = _currentMs;
        _currentMs = (int)Math.Min((long)_currentMs * 2, _maxMs);
        return TimeSpan.FromMilliseconds(delay);
    }

    /// <summary>当前退避档位（毫秒），便于测试与日志。</summary>
    public int CurrentMs => _currentMs;

    /// <summary>连接成功后调用，退避归位到初始值。</summary>
    public void Reset() => _currentMs = _initialMs;
}
