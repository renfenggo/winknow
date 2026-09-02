using Microsoft.Extensions.Logging;

namespace Winknow.ControlService.Sessions;

/// <summary>
/// WTS 会话监视器（P2-02）：轮询 WTSEnumerateSessions 做差异检测，
/// 产出登录/注销/重连/断开事件。
///
/// 选择轮询而非 WTSRegisterSessionNotification 的原因：
/// - 轮询便于注入 ITerminalServicesApi fake 做单元测试；
/// - 服务（非 UI）上下文中通知注册需额外窗口/句柄机制，复杂度不成比例；
/// - 阶段 2 不依赖锁屏/解锁事件粒度。
/// </summary>
public sealed class WtsSessionMonitor : IDisposable
{
    private readonly ITerminalServicesApi _api;
    private readonly ILogger<WtsSessionMonitor>? _logger;
    private readonly TimeSpan _pollInterval;
    private readonly object _stateLock = new();
    private Dictionary<int, WtsSessionState> _lastSnapshot = new();
    private CancellationTokenSource? _cts;
    private Task? _pollTask;

    /// <summary>检测到会话登录/重连/注销/断开时触发。</summary>
    public event Action<SessionChange>? SessionChanged;

    /// <summary>默认轮询间隔（2 秒）。</summary>
    public static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(2);

    /// <summary>创建会话监视器。</summary>
    public WtsSessionMonitor(
        ITerminalServicesApi api,
        TimeSpan? pollInterval = null,
        ILogger<WtsSessionMonitor>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(api);
        _api = api;
        _pollInterval = pollInterval ?? DefaultPollInterval;
        _logger = logger;
    }

    /// <summary>启动轮询循环。</summary>
    public void Start()
    {
        if (_pollTask is not null)
        {
            return;
        }

        _cts = new CancellationTokenSource();
        _pollTask = Task.Run(() => PollLoopAsync(_cts.Token));
        _logger?.LogInformation("WTS session monitor started (interval: {Interval}ms)", _pollInterval.TotalMilliseconds);
    }

    /// <summary>停止轮询循环并等待退出。</summary>
    public void Stop()
    {
        _cts?.Cancel();
        try
        {
            _pollTask?.Wait(TimeSpan.FromSeconds(5));
        }
        catch (AggregateException)
        {
            // 轮询退出期间的异常可忽略
        }

        _pollTask = null;
        _cts?.Dispose();
        _cts = null;
    }

    /// <summary>
    /// 单次差异检测（供测试直接调用；运行期由轮询循环驱动）。
    /// </summary>
    public IReadOnlyList<SessionChange> PollOnce()
    {
        var changes = new List<SessionChange>();
        var current = _api.EnumerateSessions()
            .GroupBy(s => s.SessionId)
            .ToDictionary(g => g.Key, g => g.First().State);

        Dictionary<int, WtsSessionState> previous;
        lock (_stateLock)
        {
            previous = _lastSnapshot;
            _lastSnapshot = current;
        }

        // 新出现或状态迁移。
        // 注意：WtsSessionState.Active == 0，TryGetValue 失败时 out 参数为 default(Active)，
        // 必须先用 ContainsKey 区分"新会话"与"状态迁移"，否则新登录会被误判为原本就是 Active。
        foreach (var (sessionId, state) in current)
        {
            if (!previous.ContainsKey(sessionId))
            {
                if (state == WtsSessionState.Active)
                {
                    changes.Add(new SessionChange(sessionId, SessionChangeKind.LoggedOn));
                }

                continue;
            }

            var oldState = previous[sessionId];
            if (oldState != WtsSessionState.Active && state == WtsSessionState.Active)
            {
                changes.Add(new SessionChange(sessionId, SessionChangeKind.Reconnected));
            }
            else if (oldState == WtsSessionState.Active && state == WtsSessionState.Disconnected)
            {
                changes.Add(new SessionChange(sessionId, SessionChangeKind.Disconnected));
            }
        }

        // 会话消失（注销）
        foreach (var sessionId in previous.Keys)
        {
            if (!current.ContainsKey(sessionId))
            {
                changes.Add(new SessionChange(sessionId, SessionChangeKind.LoggedOff));
            }
        }

        if (changes.Count > 0)
        {
            _logger?.LogDebug("Session changes: {Changes}",
                string.Join(", ", changes.Select(c => $"{c.SessionId}:{c.Kind}")));
        }

        foreach (var change in changes)
        {
            SessionChanged?.Invoke(change);
        }

        return changes;
    }

    private async Task PollLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                PollOnce();
                await Task.Delay(_pollInterval, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            // 正常停止
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "WTS session monitor loop terminated unexpectedly");
        }
    }

    /// <inheritdoc/>
    public void Dispose() => Stop();
}
