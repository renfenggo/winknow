namespace Winknow.Ipc;

/// <summary>
/// 连接级 RequestId 防重放守卫（ADR-001/TD-05）。
///
/// RequestId 单调性以"单个连接"为边界：
/// - 同一连接内 RequestId 必须严格递增（防重放/乱序重放）；
/// - 断线重连建立新连接即重置基线，正常重连不会因 RequestId 回退被永久拒绝。
/// </summary>
public sealed class IpcConnectionGuard
{
    private long _lastRequestId = -1;
    private readonly object _lock = new();

    /// <summary>
    /// 记录并校验 RequestId 单调性（线程安全）。
    /// </summary>
    /// <returns>true = 合法递增；false = 重放或回退，应拒绝并审计。</returns>
    public bool Track(uint requestId)
    {
        lock (_lock)
        {
            if (requestId <= _lastRequestId)
            {
                return false;
            }
            _lastRequestId = requestId;
            return true;
        }
    }

    /// <summary>当前已接受的最大 RequestId（-1 表示尚未收到消息）。</summary>
    public long LastRequestId
    {
        get { lock (_lock) { return _lastRequestId; } }
    }
}
