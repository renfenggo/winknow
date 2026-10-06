using Microsoft.Extensions.Logging;
using Winknow.Ipc.Commands;
using Winknow.Logging;

namespace Winknow.ControlService;

/// <summary>
/// ControlService 侧 IPC 审计输出（指导书 04 第 6 节）：
/// 每条跨边界调用记录写入结构化日志（拒绝/失败 Warning，成功按审计级 full→Information、meta→Debug），
/// 拒绝/失败记录同时双写 Windows 事件日志安全锚点（EventLogAnchor）。
/// </summary>
internal sealed class IpcAuditSink : IIpcAuditSink
{
    private readonly ILogger<IpcAuditSink> _logger;
    private readonly EventLogAnchor? _eventLogAnchor;

    /// <summary>创建审计输出端。</summary>
    /// <param name="logger">日志记录器。</param>
    /// <param name="eventLogAnchor">事件日志锚点（拒绝记录双写；null 时仅结构化日志）。</param>
    public IpcAuditSink(ILogger<IpcAuditSink> logger, EventLogAnchor? eventLogAnchor)
    {
        _logger = logger;
        _eventLogAnchor = eventLogAnchor;
    }

    /// <summary>写入一条审计记录（EventLogAnchor 失败自行吞掉，不影响分发）。</summary>
    /// <param name="record">审计记录。</param>
    public void Write(IpcAuditRecord record)
    {
        if (record.Ok)
        {
            if (string.Equals(record.AuditLevel, "full", StringComparison.Ordinal))
            {
                _logger.LogInformation(
                    "IPC audit: method={Method} request_id={RequestId} trace_id={TraceId} caller_sid={CallerSid} role={Role} result=OK latency_ms={LatencyMs} audit_level={AuditLevel}",
                    record.Method, record.RequestId, record.TraceId, record.CallerSid, record.Role,
                    record.LatencyMs, record.AuditLevel);
            }
            else
            {
                _logger.LogDebug(
                    "IPC audit: method={Method} request_id={RequestId} trace_id={TraceId} caller_sid={CallerSid} role={Role} result=OK latency_ms={LatencyMs} audit_level={AuditLevel}",
                    record.Method, record.RequestId, record.TraceId, record.CallerSid, record.Role,
                    record.LatencyMs, record.AuditLevel);
            }

            return;
        }

        _logger.LogWarning(
            "IPC audit DENIED: method={Method} request_id={RequestId} trace_id={TraceId} caller_sid={CallerSid} role={Role} result={ResultCode} latency_ms={LatencyMs} reason={DeniedReason} audit_level={AuditLevel}",
            record.Method, record.RequestId, record.TraceId, record.CallerSid, record.Role,
            record.ResultCode, record.LatencyMs, record.DeniedReason, record.AuditLevel);

        _eventLogAnchor?.WriteSecurityAnchor(
            "IpcCommandDenied",
            $"method={record.Method} caller_sid={record.CallerSid} result={record.ResultCode} reason={record.DeniedReason ?? "-"}");
    }
}
