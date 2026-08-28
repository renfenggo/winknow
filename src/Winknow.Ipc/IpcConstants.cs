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

    /// <summary>策略下发消息类型。</summary>
    public const ushort MessageTypePolicyUpdate = 0x0010;

    /// <summary>策略查询请求。</summary>
    public const ushort MessageTypePolicyQuery = 0x0011;

    /// <summary>会话状态上报。</summary>
    public const ushort MessageTypeSessionStatus = 0x0020;

    /// <summary>管理命令。</summary>
    public const ushort MessageTypeAdminCommand = 0x0100;

    /// <summary>维护模式通知。</summary>
    public const ushort MessageTypeMaintenanceMode = 0x0101;

    /// <summary>Agent 退出通知。</summary>
    public const ushort MessageTypeAgentExit = 0x0102;

    /// <summary>错误响应。</summary>
    public const ushort MessageTypeError = 0xFFFF;
}
