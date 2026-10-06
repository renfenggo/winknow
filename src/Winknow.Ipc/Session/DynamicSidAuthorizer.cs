using Microsoft.Extensions.Logging;

namespace Winknow.Ipc.Session;

/// <summary>WTS 会话变更通知种类（与 WTSSessionNotification 常量对齐）。</summary>
public enum WtsSessionChangeKind
{
    /// <summary>控制台会话连接。</summary>
    ConsoleConnect = 1,

    /// <summary>控制台会话断开。</summary>
    ConsoleDisconnect = 2,

    /// <summary>远程会话连接。</summary>
    RemoteConnect = 3,

    /// <summary>远程会话断开。</summary>
    RemoteDisconnect = 4,

    /// <summary>用户登录。</summary>
    SessionLogon = 5,

    /// <summary>用户注销。</summary>
    SessionLogoff = 6,

    /// <summary>会话锁定。</summary>
    SessionLock = 7,

    /// <summary>会话解锁。</summary>
    SessionUnlock = 8,

    /// <summary>会话进入/退出远程控制。</summary>
    SessionRemoteControl = 9,
}

/// <summary>
/// 学生 SID 动态授权编排器（ADR-002）：
/// 登录会话建立 → AllowSid（绑定设备会话、TTL 截断至 8 小时）；
/// 注销 → RevokeSid；锁定/断开不撤销（授权与会话同生命周期，断开可重连）。
/// SID 解析（WTSQueryUserToken）通过注入的解析器完成，本类保持纯逻辑可测。
/// </summary>
public sealed class DynamicSidAuthorizer
{
    /// <summary>单次授权 TTL 上限（ADR-002：≤8 小时）。</summary>
    public static readonly TimeSpan MaxSessionTtl = TimeSpan.FromHours(8);

    private readonly IpcAuthenticator _authenticator;
    private readonly Func<int, string?>? _resolveSessionUserSid;
    private readonly ILogger<DynamicSidAuthorizer>? _logger;
    private readonly object _lock = new();
    private readonly Dictionary<int, string> _sidBySessionId = new();

    /// <summary>创建动态 SID 授权编排器。</summary>
    /// <param name="authenticator">帧级身份验证器（授权写入目标）。</param>
    /// <param name="resolveSessionUserSid">会话 ID → 用户 SID 解析器（服务环境由 WTS 提供）。</param>
    /// <param name="logger">日志记录器。</param>
    public DynamicSidAuthorizer(
        IpcAuthenticator authenticator,
        Func<int, string?>? resolveSessionUserSid = null,
        ILogger<DynamicSidAuthorizer>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(authenticator);
        _authenticator = authenticator;
        _resolveSessionUserSid = resolveSessionUserSid;
        _logger = logger;
    }

    /// <summary>单次会话授权 TTL（默认 8 小时，自动截断至上限）。</summary>
    public TimeSpan SessionTtl { get; set; } = MaxSessionTtl;

    /// <summary>授权会话用户 SID（登录路径；TTL 截断至上限）。</summary>
    /// <param name="sessionId">WTS 会话 ID。</param>
    /// <param name="sid">会话用户 SID。</param>
    public void AuthorizeSession(int sessionId, string sid)
    {
        ArgumentException.ThrowIfNullOrEmpty(sid);

        var ttl = SessionTtl > MaxSessionTtl ? MaxSessionTtl : SessionTtl;
        _authenticator.AllowSid(sid, ttl);
        lock (_lock)
        {
            _sidBySessionId[sessionId] = sid;
        }

        _logger?.LogInformation(
            "Session {SessionId} SID {Sid} authorized for {Ttl:0}h (dynamic grant)",
            sessionId, sid, ttl.TotalHours);
    }

    /// <summary>撤销会话授权（注销路径；优先使用登录时记录的 SID）。</summary>
    /// <param name="sessionId">WTS 会话 ID。</param>
    public void RevokeSession(int sessionId)
    {
        string? sid;
        lock (_lock)
        {
            if (!_sidBySessionId.Remove(sessionId, out sid))
            {
                sid = null;
            }
        }

        // 注销瞬间令牌查询大概率失败：先记录后撤销保证映射命中
        sid ??= _resolveSessionUserSid?.Invoke(sessionId);
        if (sid is null)
        {
            _logger?.LogDebug("Session {SessionId} logoff: no recorded SID to revoke", sessionId);
            return;
        }

        _authenticator.RevokeSid(sid);
        _logger?.LogInformation("Session {SessionId} SID {Sid} revoked (logoff)", sessionId, sid);
    }

    /// <summary>处理 WTS 会话变更通知（登录授权/注销撤销，其余忽略）。</summary>
    /// <param name="kind">变更种类。</param>
    /// <param name="sessionId">WTS 会话 ID。</param>
    public void HandleSessionChange(WtsSessionChangeKind kind, int sessionId)
    {
        switch (kind)
        {
            case WtsSessionChangeKind.SessionLogon:
            {
                string? sid;
                lock (_lock)
                {
                    _sidBySessionId.TryGetValue(sessionId, out var recorded);
                    sid = recorded;
                }

                sid ??= _resolveSessionUserSid?.Invoke(sessionId);
                if (sid is null)
                {
                    _logger?.LogWarning(
                        "Session {SessionId} logon: user SID could not be resolved, no dynamic grant issued",
                        sessionId);
                    return;
                }

                AuthorizeSession(sessionId, sid);
                break;
            }

            case WtsSessionChangeKind.SessionLogoff:
                RevokeSession(sessionId);
                break;

            default:
                // 锁定/解锁/连接/断开：授权与会话同生命周期，不撤销
                break;
        }
    }
}
