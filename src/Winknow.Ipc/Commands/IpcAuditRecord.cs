namespace Winknow.Ipc.Commands;

/// <summary>
/// IPC 跨边界调用审计记录（指导书 04 第 6 节 / method_registry.md audit 列）：
/// 每次命令分发（成功或拒绝）各产出一条，由分发器统一写入 IIpcAuditSink。
/// </summary>
public sealed class IpcAuditRecord
{
    /// <summary>记录时间（UTC）。</summary>
    public DateTimeOffset Timestamp { get; init; }

    /// <summary>调用方 trace_id（可空，来自请求信封）。</summary>
    public string? TraceId { get; init; }

    /// <summary>帧级请求号（IpcMessage.RequestId，单调递增；分发入口透传）。</summary>
    public uint RequestId { get; init; }

    /// <summary>请求方法名（未知方法路径记录原始请求名）。</summary>
    public string Method { get; init; } = string.Empty;

    /// <summary>调用方 SID（帧级认证身份）。</summary>
    public string? CallerSid { get; init; }

    /// <summary>解析出的调用方角色。</summary>
    public IpcCallerRole Role { get; init; }

    /// <summary>调用是否成功。</summary>
    public bool Ok { get; init; }

    /// <summary>结果码：成功为 "OK"，失败为契约错误码（IpcErrorCodes）。</summary>
    public string ResultCode { get; init; } = string.Empty;

    /// <summary>分发耗时（毫秒，向上取整不小于 0）。</summary>
    public long LatencyMs { get; init; }

    /// <summary>拒绝原因（授权/超时拒绝时来自错误 details.denied_reason；其余为 null）。</summary>
    public string? DeniedReason { get; init; }

    /// <summary>审计级：meta/full（spec 声明）或 denied（未知方法与携带 denied_reason 的拒绝）。</summary>
    public string AuditLevel { get; init; } = string.Empty;
}

/// <summary>
/// IPC 审计输出端。Write 在分发路径上同步调用，
/// 实现方须自行吞掉副作用异常（分发器另有兜底，审计绝不阻断命令分发）。
/// </summary>
public interface IIpcAuditSink
{
    /// <summary>写入一条审计记录。</summary>
    /// <param name="record">审计记录。</param>
    void Write(IpcAuditRecord record);
}
