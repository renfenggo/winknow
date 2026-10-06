namespace Winknow.Ipc.Session;

/// <summary>
/// 单个 IPC 连接的会话状态（握手后填充）。
/// 业务帧只有握手完成后才被分发，且仅能调用已协商 capability 覆盖的方法。
/// </summary>
public sealed class IpcConnectionSession
{
    /// <summary>握手是否已完成。</summary>
    public bool HandshakeCompleted { get; internal set; }

    /// <summary>已协商授予的能力集合。</summary>
    public IReadOnlySet<string> GrantedCapabilities { get; internal set; } =
        new HashSet<string>(StringComparer.Ordinal);

    /// <summary>客户端会话 ID。</summary>
    public string SessionId { get; internal set; } = string.Empty;

    /// <summary>调用方 SID（来自帧头，经管道模拟验证）。</summary>
    public string CallerSid { get; internal set; } = string.Empty;

    /// <summary>组件类型（bridge/admin_tool/test_client/session_agent）。</summary>
    public string Component { get; internal set; } = string.Empty;
}
