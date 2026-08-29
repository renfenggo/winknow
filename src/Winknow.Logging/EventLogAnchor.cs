using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Winknow.Core.Results;

namespace Winknow.Logging;

/// <summary>
/// Windows Event Log 锚点：关键事件双写到 Windows 事件日志。
/// 用途：即使审计数据库被删除，关键事件仍可在 Windows Event Log 中追溯。
/// </summary>
public sealed class EventLogAnchor : IDisposable
{
    private readonly ILogger<EventLogAnchor>? _logger;
    private readonly string _sourceName;
    private readonly string _logName;
    private EventLog? _eventLog;
    private bool _disposed;

    /// <summary>
    /// 创建 Event Log 锚点。
    /// </summary>
    /// <param name="sourceName">事件源名称（需管理员权限注册）。</param>
    /// <param name="logName">日志名称（默认 Application）。</param>
    /// <param name="logger">可选日志。</param>
    public EventLogAnchor(string sourceName, string logName = "Application", ILogger<EventLogAnchor>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceName);
        _sourceName = sourceName;
        _logName = logName;
        _logger = logger;
    }

    /// <summary>
    /// 初始化：注册事件源（需管理员权限）。
    /// </summary>
    public Result Initialize()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        try
        {
            // 检查事件源是否已存在，不存在则创建
            if (!EventLog.SourceExists(_sourceName))
            {
                // 创建事件源需要管理员权限
                var ced = new EventSourceCreationData(_sourceName, _logName);
                EventLog.CreateEventSource(ced);
                _logger?.LogInformation("Event source created: {Source}", _sourceName);
            }

            _eventLog = new EventLog(_logName, ".", _sourceName);
            _logger?.LogInformation("Event log anchor initialized: {Source}/{Log}", _sourceName, _logName);
            return Result.Success();
        }
        catch (Exception ex)
        {
            // 非管理员权限或安全策略限制时降级（仅日志，不阻断）
            _logger?.LogWarning(ex, "Event source creation failed (may need admin), anchoring degraded");
            return Result.Failure(ErrorCode.ExternalError, ex.Message);
        }
    }

    /// <summary>
    /// 写入关键事件到 Windows Event Log（双写锚点）。
    /// </summary>
    /// <param name="message">事件消息。</param>
    /// <param name="eventId">事件 ID（自定义标识）。</param>
    /// <param name="entryType">事件类型（Information/Warning/Error）。</param>
    public Result WriteAnchor(string message, int eventId = 1, EventLogEntryType entryType = EventLogEntryType.Information)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(message);

        if (_eventLog is null)
        {
            // 未初始化（可能非管理员），尝试直接写入
            var init = Initialize();
            if (!init.IsSuccess)
            {
                return init;  // 降级：无法写入 Event Log，但不阻断主流程
            }
        }

        try
        {
            _eventLog?.WriteEntry(message, entryType, eventId);
            _logger?.LogDebug("Event anchor written: ID={Id}, Type={Type}", eventId, entryType);
            return Result.Success();
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to write event anchor (degraded mode)");
            return Result.Failure(ErrorCode.ExternalError, ex.Message);
        }
    }

    /// <summary>
    /// 写入关键安全事件锚点（预设事件 ID）。
    /// </summary>
    public Result WriteSecurityAnchor(string action, string detail)
    {
        var message = $"[Winknow Security] {action}: {detail}";
        return WriteAnchor(message, eventId: 9001, entryType: EventLogEntryType.Warning);
    }

    /// <summary>
    /// 写入维护模式事件锚点。
    /// </summary>
    public Result WriteMaintenanceAnchor(string action, string actor)
    {
        var message = $"[Winknow Maintenance] {action} by {actor}";
        return WriteAnchor(message, eventId: 9002, entryType: EventLogEntryType.Information);
    }

    /// <summary>
    /// 写入更新事件锚点。
    /// </summary>
    public Result WriteUpdateAnchor(string action, string version)
    {
        var message = $"[Winknow Update] {action} to version {version}";
        return WriteAnchor(message, eventId: 9003, entryType: EventLogEntryType.Information);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _eventLog?.Dispose();
    }
}
