namespace Winknow.Ipc;

/// <summary>
/// IPC 模块常量（见《V7.0 组件架构设计》第六节）。
/// </summary>
public static class IpcConstants
{
    /// <summary>ControlService 主 Named Pipe 名称。</summary>
    public const string ControlPipeName = "Winknow_Control";

    /// <summary>时间戳允许偏差（±60 秒）。</summary>
    public const int TimestampToleranceMs = 60_000;

    /// <summary>Nonce 缓存有效期（5 分钟）。</summary>
    public const int NonceCacheTtlMs = 5 * 60_000;

    /// <summary>Nonce 缓存最大条目数。</summary>
    public const int NonceCacheMaxEntries = 10_000;

    /// <summary>连接超时（毫秒）。</summary>
    public const int ConnectionTimeoutMs = 5_000;

    /// <summary>请求超时（毫秒）。</summary>
    public const int RequestTimeoutMs = 30_000;

    /// <summary>最大消息长度（1 MB，防止恶意超大消息）。</summary>
    public const int MaxMessageLength = 1 * 1024 * 1024;

    /// <summary>心跳消息类型。</summary>
    public const ushort MessageTypeHeartbeat = 0x0001;

    /// <summary>握手请求（连接建立后首条消息，身份与版本协商）。</summary>
    public const ushort MessageTypeHello = 0x0002;

    /// <summary>握手应答（服务端授予/拒绝 + 服务端随机挑战）。</summary>
    public const ushort MessageTypeHelloAck = 0x0003;

    /// <summary>策略下发消息类型。</summary>
    public const ushort MessageTypePolicyUpdate = 0x0010;

    /// <summary>策略查询请求。</summary>
    public const ushort MessageTypePolicyQuery = 0x0011;

    /// <summary>会话状态上报。</summary>
    public const ushort MessageTypeSessionStatus = 0x0020;

    /// <summary>Agent 状态查询（请求-响应，RequestId 与请求一致）。</summary>
    public const ushort MessageTypeStatus = 0x0021;

    /// <summary>Agent 状态查询应答。</summary>
    public const ushort MessageTypeStatusAck = 0x0022;

    /// <summary>显示锁屏遮罩（payload: LockPayload）。</summary>
    public const ushort MessageTypeShowLock = 0x0030;

    /// <summary>隐藏锁屏遮罩（已授权解锁）。</summary>
    public const ushort MessageTypeHideLock = 0x0031;

    /// <summary>管理命令。</summary>
    public const ushort MessageTypeAdminCommand = 0x0100;

    /// <summary>维护模式通知。</summary>
    public const ushort MessageTypeMaintenanceMode = 0x0101;

    /// <summary>Agent 退出通知（旧名，保留兼容）。</summary>
    public const ushort MessageTypeAgentExit = 0x0102;

    /// <summary>命令 Agent 优雅退出（注销/更新/维护）。</summary>
    public const ushort MessageTypeShutdown = 0x0103;

    /// <summary>错误响应。</summary>
    public const ushort MessageTypeError = 0xFFFF;

    /// <summary>握手超时（连接建立后未收到 Hello 即断开并审计）。</summary>
    public const int HandshakeTimeoutMs = 10_000;

    /// <summary>握手消息（Hello/HelloAck）最大载荷字节数。</summary>
    public const int MaxHandshakePayloadBytes = 4 * 1024;

    /// <summary>心跳间隔（Agent → Service，秒）。</summary>
    public const int HeartbeatIntervalSeconds = 30;

    /// <summary>断线重连初始退避（毫秒，指数增长）。</summary>
    public const int ReconnectInitialBackoffMs = 1_000;

    /// <summary>断线重连最大退避（毫秒）。</summary>
    public const int ReconnectMaxBackoffMs = 60_000;
}
