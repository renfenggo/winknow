using System.Collections.Concurrent;
using Winknow.Core;

namespace Winknow.ControlService.Sessions;

/// <summary>
/// 会话登记记录：一个已登录用户会话的准入信息。
/// </summary>
/// <param name="SessionId">WTS 会话 ID。</param>
/// <param name="UserSid">登录用户 SID（IPC 准入比对凭证）。</param>
/// <param name="RegisteredAt">登记时间。</param>
public sealed record SessionRecord(int SessionId, string UserSid, DateTimeOffset RegisteredAt);

/// <summary>
/// 会话登记表（P2-02）：SessionManager 启动 Agent 前登记会话，
/// IpcServer 握手准入回调按 SessionId + UserSid 比对（ADR-001/TD-05 应用层准入）。
/// 非严格安全边界：真实身份仍以管道 Impersonation 取得的真实 SID 为准。
/// </summary>
public sealed class SessionRegistry
{
    private readonly ConcurrentDictionary<int, SessionRecord> _sessions = new();

    /// <summary>登记（或刷新）一个会话。</summary>
    public void Register(int sessionId, string userSid)
    {
        ArgumentException.ThrowIfNullOrEmpty(userSid);
        _sessions[sessionId] = new SessionRecord(sessionId, userSid, DateTimeOffset.UtcNow);
    }

    /// <summary>注销一个会话（用户注销时）。</summary>
    public bool Unregister(int sessionId) => _sessions.TryRemove(sessionId, out _);

    /// <summary>查询登记记录。</summary>
    public bool TryGet(int sessionId, out SessionRecord? record) => _sessions.TryGetValue(sessionId, out record);

    /// <summary>当前登记数。</summary>
    public int Count => _sessions.Count;

    /// <summary>登记快照（监控/测试用）。</summary>
    public IReadOnlyList<SessionRecord> Snapshot() => _sessions.Values.ToList();

    /// <summary>
    /// IPC 握手准入判定：会话已登记 且 声明会话与登记一致 且 真实 SID 与登记 SID 一致
    /// （固定时间比较，防时序侧信道）。
    /// </summary>
    public bool IsAdmissionAllowed(int sessionId, string realSid)
    {
        if (!_sessions.TryGetValue(sessionId, out var record) || record is null)
        {
            return false;
        }

        return SecurityUtils.FixedTimeEquals(realSid, record.UserSid);
    }
}
