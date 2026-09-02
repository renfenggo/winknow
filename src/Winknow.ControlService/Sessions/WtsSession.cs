namespace Winknow.ControlService.Sessions;

/// <summary>
/// WTS 会话状态（WTSEnumerateSessions 返回的连接状态子集）。
/// </summary>
public enum WtsSessionState
{
    /// <summary>活动（用户在桌面）。</summary>
    Active,

    /// <summary>已连接（无用户会话的连接过渡态）。</summary>
    Connected,

    /// <summary>已断开（会话仍在，用户不在桌面）。</summary>
    Disconnected,

    /// <summary>空闲（等待客户端连接）。</summary>
    Idle,

    /// <summary>监听（服务端等待连接，如 session 0）。</summary>
    Listen,

    /// <summary>其他（Reset/Down/Init 等）。</summary>
    Other
}

/// <summary>
/// 单个 WTS 会话的快照信息。
/// </summary>
/// <param name="SessionId">WTS 会话 ID。</param>
/// <param name="State">连接状态。</param>
public sealed record WtsSession(int SessionId, WtsSessionState State);

/// <summary>
/// 会话差异变化事件（轮询 diff 产出）。
/// </summary>
public enum SessionChangeKind
{
    /// <summary>新登录（上次快照无此会话 → 本次 Active）。</summary>
    LoggedOn,

    /// <summary>注销（上次存在 → 本次消失）。</summary>
    LoggedOff,

    /// <summary>重连（Disconnected → Active）。</summary>
    Reconnected,

    /// <summary>断开（Active → Disconnected，会话与 Agent 仍保留）。</summary>
    Disconnected
}

/// <summary>
/// 会话差异变化记录。
/// </summary>
/// <param name="SessionId">WTS 会话 ID。</param>
/// <param name="Kind">变化类型。</param>
public sealed record SessionChange(int SessionId, SessionChangeKind Kind);
