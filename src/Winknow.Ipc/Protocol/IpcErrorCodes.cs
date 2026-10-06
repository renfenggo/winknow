namespace Winknow.Ipc.Protocol;

/// <summary>
/// IPC payload 层错误码（contracts/errors/error_codes.md v1，只增不删）。
/// 帧级错误仍使用 Winknow.Core.Results.ErrorCode；本注册表仅用于 JSON payload。
/// </summary>
public static class IpcErrorCodes
{
    /// <summary>成功（仅内部使用，线上错误对象不含）。</summary>
    public const string Ok = "OK";

    /// <summary>服务端内部错误（retryable）。</summary>
    public const string InternalError = "INTERNAL_ERROR";

    /// <summary>参数 schema 校验失败。</summary>
    public const string InvalidArgument = "INVALID_ARGUMENT";

    /// <summary>未认证/凭证失效。</summary>
    public const string Unauthenticated = "UNAUTHENTICATED";

    /// <summary>已认证但无权限（caller role 不足）。</summary>
    public const string PermissionDenied = "PERMISSION_DENIED";

    /// <summary>资源不存在。</summary>
    public const string NotFound = "NOT_FOUND";

    /// <summary>超时（retryable）。</summary>
    public const string Timeout = "TIMEOUT";

    /// <summary>下游/服务不可用（retryable）。</summary>
    public const string Unavailable = "UNAVAILABLE";

    /// <summary>契约已注册但实现未开放。</summary>
    public const string NotImplemented = "NOT_IMPLEMENTED";

    /// <summary>协议/组件版本不兼容（details: expected/actual）。</summary>
    public const string IpcVersionMismatch = "IPC_VERSION_MISMATCH";

    /// <summary>握手前发送了业务帧。</summary>
    public const string IpcHandshakeRequired = "IPC_HANDSHAKE_REQUIRED";

    /// <summary>命令所需 capability 未协商。</summary>
    public const string IpcCapabilityMismatch = "IPC_CAPABILITY_MISMATCH";

    /// <summary>方法不在白名单注册表。</summary>
    public const string IpcUnknownMethod = "IPC_UNKNOWN_METHOD";

    /// <summary>发送方 SID 不在授权集。</summary>
    public const string IpcSidNotAuthorized = "IPC_SID_NOT_AUTHORIZED";

    /// <summary>动态 SID 授权已过期。</summary>
    public const string IpcSidExpired = "IPC_SID_EXPIRED";

    /// <summary>重放攻击嫌疑。</summary>
    public const string IpcReplayDetected = "IPC_REPLAY_DETECTED";

    /// <summary>可重试错误码集合（error_codes.md retryable 列）。</summary>
    public static readonly IReadOnlySet<string> RetryableCodes = new HashSet<string>(StringComparer.Ordinal)
    {
        InternalError,
        Timeout,
        Unavailable,
    };
}
