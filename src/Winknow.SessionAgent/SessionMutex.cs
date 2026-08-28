using System.Threading;

namespace Winknow.SessionAgent;

/// <summary>
/// SessionAgent 互斥锁，确保每个用户会话只有一个 Agent 实例。
/// </summary>
internal sealed class SessionMutex : IDisposable
{
    private readonly Mutex _mutex;
    private readonly bool _acquired;

    /// <summary>
    /// 创建并尝试获取会话级互斥锁。
    /// </summary>
    /// <param name="sessionId">当前会话 ID。</param>
    public SessionMutex(int sessionId)
    {
        var mutexName = $"Global\\Winknow_SessionAgent_Session_{sessionId}";
        _mutex = new Mutex(initiallyOwned: true, name: mutexName, createdNew: out _acquired);
    }

    /// <summary>
    /// 是否成功获取互斥锁（即本会话是否已有 Agent 运行）。
    /// </summary>
    public bool IsAcquired => _acquired;

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_acquired)
        {
            try
            {
                _mutex.ReleaseMutex();
            }
            catch (ApplicationException)
            {
                // 线程退出时未持有锁，忽略
            }
        }
        _mutex.Dispose();
    }
}
