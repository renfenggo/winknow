using System.Text.Json;
using System.Text.Json.Serialization;

namespace Winknow.Telemetry;

/// <summary>
/// 云端遥测配置（appsettings.json "Telemetry" 节；BaseUrl 为空 = 整体禁用）。
/// 凭据支持环境变量覆盖（WINKNOW_TELEMETRY__USERNAME 等，Host 原生前缀规则）。
/// </summary>
public sealed class TelemetryOptions
{
    /// <summary>platform 根地址（如 https://platform.example.com）；空 = 遥测禁用。</summary>
    public string BaseUrl { get; set; } = string.Empty;

    /// <summary>上报账号（platform 教师或管理角色；student 无设备心跳权限）。</summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>上报账号密码。</summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>心跳间隔秒（默认 60；远低于服务端按用户限流配额）。</summary>
    public int HeartbeatIntervalSeconds { get; set; } = 60;

    /// <summary>待上报事件队列上限（溢出丢最旧——管控功能绝不因云端阻塞而退化）。</summary>
    public int MaxQueueSize { get; set; } = 1000;
}

/// <summary>教室机心跳载荷（POST /v1/devices/heartbeat，契约 HeartbeatIn）。</summary>
public sealed record HeartbeatPayload
{
    /// <summary>Winknow DeviceId.Generate() 产物（全局唯一，稳定跨重装）。</summary>
    public string DeviceId { get; init; } = string.Empty;

    /// <summary>设备显示名（缺省由服务端用 device_id 兜底）。</summary>
    public string? DisplayName { get; init; }

    /// <summary>online/offline/recovering/error（缺省由服务端定）。</summary>
    public string? Status { get; init; }

    /// <summary>客户端版本号（Constants.Version）。</summary>
    public string? ClientVersion { get; init; }

    /// <summary>当前生效策略版本（PolicyFile.Version；未加载为 null）。</summary>
    public string? PolicyVersion { get; init; }
}

/// <summary>
/// 统一分析事件（POST /v1/events，EventEnvelope v1 子集）。
/// event_name 必须在 platform 白名单内（TelemetryEvents 工厂保证）。
/// </summary>
public sealed record TelemetryEvent
{
    /// <summary>客户端事件标识（全局唯一，服务端幂等去重键）。</summary>
    public string EventId { get; init; } = string.Empty;

    /// <summary>事件名（platform EVENT_NAMES 白名单之一）。</summary>
    public string EventName { get; init; } = string.Empty;

    /// <summary>事件发生时刻（UTC；服务端按此时间做保留期治理）。</summary>
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>会话标识（课堂事件用 classroom_id）。</summary>
    public string? SessionId { get; init; }

    /// <summary>本机设备标识（DeviceId.Generate()）。</summary>
    public string? DeviceId { get; init; }

    /// <summary>来源标记（win_bridge / control_service）。</summary>
    public string Platform { get; init; } = "win_bridge";

    /// <summary>客户端版本号。</summary>
    public string? AppVersion { get; init; }

    /// <summary>链路追踪 ID（IPC 请求信封透传）。</summary>
    public string? TraceId { get; init; }

    /// <summary>非敏感属性（禁止携带源码/完整对话——platform FORBIDDEN_PROPERTY_KEYS 会 422）。</summary>
    public IReadOnlyDictionary<string, object?>? Properties { get; init; }
}

/// <summary>事件入队端（ControlCommandHost/Worker 挂载点；TelemetryCollector 实现）。</summary>
public interface ITelemetrySink
{
    /// <summary>事件入队（永不阻塞、永不抛）。</summary>
    void Enqueue(TelemetryEvent evt);
}

/// <summary>白名单事件工厂（platform EVENT_NAMES 对齐；event_id 每次新生成）。</summary>
public static class TelemetryEvents
{
    /// <summary>策略下发/生效结果事件名。</summary>
    public const string PolicyResultName = "device.policy_result";

    /// <summary>代码编译结果事件名。</summary>
    public const string CompileResultName = "runner.compile_result";

    /// <summary>代码运行结果事件名。</summary>
    public const string RunResultName = "runner.run_result";

    /// <summary>课堂开始事件名。</summary>
    public const string ClassroomBeginName = "classroom.begin";

    /// <summary>课堂结束事件名。</summary>
    public const string ClassroomEndName = "classroom.end";

    private static string NewId() => Guid.NewGuid().ToString("N");

    /// <summary>策略下发结果事件（成功与失败都上报；reason 截断 200 字符）。</summary>
    /// <param name="policyId">策略 ID（失败时 null）。</param>
    /// <param name="policyVersion">策略版本（失败时 null）。</param>
    /// <param name="success">是否生效成功（P1 生效链：须为执行器真实应用结果，而非仅落盘）。</param>
    /// <param name="reason">失败原因（成功为 null；部分执行器失败时为错误清单）。</param>
    /// <param name="deviceId">设备标识。</param>
    /// <param name="appVersion">客户端版本。</param>
    /// <param name="traceId">链路追踪 ID。</param>
    /// <param name="saved">是否落盘成功（P1 生效链：区分"保存成功/应用失败"与"拒绝"；null 省略，兼容旧语义）。</param>
    /// <returns>白名单事件。</returns>
    public static TelemetryEvent PolicyResult(
        string? policyId, string? policyVersion, bool success, string? reason,
        string? deviceId = null, string? appVersion = null, string? traceId = null,
        bool? saved = null) => new()
    {
        EventId = NewId(),
        EventName = PolicyResultName,
        DeviceId = deviceId,
        AppVersion = appVersion,
        TraceId = traceId,
        Properties = new Dictionary<string, object?>
        {
            ["policy_id"] = policyId,
            ["policy_version"] = policyVersion,
            ["success"] = success,
            ["saved"] = saved,
            ["reason"] = reason is null ? null : (reason.Length > 200 ? reason[..200] : reason),
        },
    };

    /// <summary>编译结果事件（status 为契约大写下划线：COMPILED_OK/COMPILE_FAILED）。</summary>
    /// <param name="requestId">Runner 请求标识。</param>
    /// <param name="status">契约状态字符串。</param>
    /// <param name="elapsedMs">端到端耗时毫秒。</param>
    /// <param name="compileExitCode">编译退出码。</param>
    /// <param name="deviceId">设备标识。</param>
    /// <param name="appVersion">客户端版本。</param>
    /// <param name="traceId">链路追踪 ID。</param>
    /// <returns>白名单事件。</returns>
    public static TelemetryEvent CompileResult(
        string requestId, string status, long elapsedMs, int? compileExitCode,
        string? deviceId = null, string? appVersion = null, string? traceId = null) => new()
    {
        EventId = NewId(),
        EventName = CompileResultName,
        DeviceId = deviceId,
        AppVersion = appVersion,
        TraceId = traceId,
        Properties = new Dictionary<string, object?>
        {
            ["request_id"] = requestId,
            ["status"] = status,
            ["elapsed_ms"] = elapsedMs,
            ["compile_exit_code"] = compileExitCode,
        },
    };

    /// <summary>运行结果事件（RUN_OK/RUN_FAILED/RUN_TIMEOUT/RESOURCE_LIMIT）。</summary>
    /// <param name="requestId">Runner 请求标识。</param>
    /// <param name="status">契约状态字符串。</param>
    /// <param name="elapsedMs">端到端耗时毫秒。</param>
    /// <param name="runExitCode">运行退出码。</param>
    /// <param name="peakMemoryKb">峰值内存 KB（Job Object 记账）。</param>
    /// <param name="timedOut">是否超时终止。</param>
    /// <param name="deviceId">设备标识。</param>
    /// <param name="appVersion">客户端版本。</param>
    /// <param name="traceId">链路追踪 ID。</param>
    /// <returns>白名单事件。</returns>
    public static TelemetryEvent RunResult(
        string requestId, string status, long elapsedMs, int? runExitCode,
        long peakMemoryKb = 0, bool timedOut = false,
        string? deviceId = null, string? appVersion = null, string? traceId = null) => new()
    {
        EventId = NewId(),
        EventName = RunResultName,
        DeviceId = deviceId,
        AppVersion = appVersion,
        TraceId = traceId,
        Properties = new Dictionary<string, object?>
        {
            ["request_id"] = requestId,
            ["status"] = status,
            ["elapsed_ms"] = elapsedMs,
            ["run_exit_code"] = runExitCode,
            ["peak_memory_kb"] = peakMemoryKb,
            ["timed_out"] = timedOut,
        },
    };

    /// <summary>课堂开始事件。</summary>
    /// <param name="classroomId">课堂标识（同时映射 session_id）。</param>
    /// <param name="deviceId">设备标识。</param>
    /// <param name="appVersion">客户端版本。</param>
    /// <returns>白名单事件。</returns>
    public static TelemetryEvent ClassroomBegin(
        string classroomId, string? deviceId = null, string? appVersion = null) => new()
    {
        EventId = NewId(),
        EventName = ClassroomBeginName,
        SessionId = string.IsNullOrEmpty(classroomId) ? null : classroomId,
        DeviceId = deviceId,
        AppVersion = appVersion,
    };

    /// <summary>课堂结束事件（携带时长秒）。</summary>
    /// <param name="classroomId">课堂标识（同时映射 session_id）。</param>
    /// <param name="durationSeconds">课堂时长秒。</param>
    /// <param name="deviceId">设备标识。</param>
    /// <param name="appVersion">客户端版本。</param>
    /// <returns>白名单事件。</returns>
    public static TelemetryEvent ClassroomEnd(
        string classroomId, long durationSeconds,
        string? deviceId = null, string? appVersion = null) => new()
    {
        EventId = NewId(),
        EventName = ClassroomEndName,
        SessionId = string.IsNullOrEmpty(classroomId) ? null : classroomId,
        DeviceId = deviceId,
        AppVersion = appVersion,
        Properties = new Dictionary<string, object?>
        {
            ["duration_s"] = durationSeconds,
        },
    };
}

/// <summary>契约对齐序列化（snake_case；null 字段省略）。</summary>
public static class TelemetryJson
{
    /// <summary>序列化选项单例（TelemetryEvent/HeartbeatPayload 与 platform 契约字段名对齐）。</summary>
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}
