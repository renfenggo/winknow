using System.Text.Json;
using Microsoft.Extensions.Logging;
using Winknow.CodeRunner;
using Winknow.Core.Results;
using Winknow.Ipc.Commands;
using Winknow.Ipc.Protocol;
using Winknow.Ipc.Session;
using Winknow.Policy;
using Winknow.Telemetry;

namespace Winknow.ControlService;

/// <summary>
/// policy.apply / policy.restore 的两段执行结果（P1 生效链）：
/// 落盘+重载成功（Result.IsSuccess）后，运行中执行器的刷新可能部分失败
/// （ApplyErrors 非空）。响应与遥测须如实区分"保存成功"与"应用成功"，
/// 不再以 applied=true 掩盖执行器未更新的状态。
/// </summary>
internal sealed record PolicyApplyOutcome(PolicyFile Policy, IReadOnlyList<string> ApplyErrors)
{
    /// <summary>全部执行器刷新成功。</summary>
    public bool Applied => ApplyErrors.Count == 0;
}

/// <summary>
/// ControlService 命令宿主：构建 method_registry.md 白名单对应的命令注册表，
/// 并提供各方法 handler。分发语义（白名单/角色/能力/超时）由 IpcCommandRegistry 承担，
/// 本类只负责业务语义，保持可单测的薄层。
/// </summary>
internal sealed class ControlCommandHost
{
    private const string SystemGetStatus = "system.get_status";
    private const string SystemShutdown = "system.shutdown";
    private const string DeviceGetState = "device.get_state";
    private const string ClassroomBegin = "classroom.begin";
    private const string ClassroomEnd = "classroom.end";
    private const string PolicyApply = "policy.apply";
    private const string PolicyRestore = "policy.restore";
    private const string RunnerGetCapabilities = "runner.get_capabilities";
    private const string RunnerExecute = "runner.execute";

    private readonly ILogger<ControlCommandHost>? _logger;
    private readonly string _deviceId;
    private readonly string _componentVersion;
    private readonly DateTimeOffset _startedAt = DateTimeOffset.UtcNow;
    private readonly ITelemetrySink? _telemetry;

    // 课堂会话状态（classroom.begin/end 管理的内存态，仅 system 角色可变）
    private readonly object _classroomLock = new();
    private bool _classroomActive;
    private string _classroomId = string.Empty;
    private long _classroomStartedAtUnix;

    /// <summary>创建命令宿主并注册 method_registry.md v1 全部方法。</summary>
    /// <param name="logger">日志记录器。</param>
    /// <param name="deviceId">本机设备 ID。</param>
    /// <param name="componentVersion">ControlService 组件版本。</param>
    /// <param name="isSystemSid">系统 SID（LocalSystem/Administrators）判定谓词。</param>
    /// <param name="auditSink">IPC 审计输出端（M2-5；null 表示不落审计）。</param>
    /// <param name="telemetrySink">云端事件入队端（M8 Lane W；null 表示遥测未启用）。</param>
    public ControlCommandHost(
        ILogger<ControlCommandHost>? logger,
        string deviceId,
        string componentVersion,
        Func<string, bool> isSystemSid,
        IIpcAuditSink? auditSink = null,
        ITelemetrySink? telemetrySink = null)
    {
        _logger = logger;
        _deviceId = deviceId;
        _componentVersion = componentVersion;
        _telemetry = telemetrySink;

        Registry = new IpcCommandRegistry(isSystemSid, auditSink);
        RegisterAll();
    }

    /// <summary>命令注册表（Worker 将 RequestReceived 转发至此）。</summary>
    public IpcCommandRegistry Registry { get; }

    /// <summary>当前策略快照读取器（Worker 绑定；null 时报告策略未加载）。</summary>
    internal Func<PolicyFile?>? PolicySnapshot { private get; set; }

    /// <summary>策略应用回调（Worker 绑定：验证、备份、落盘+重载，并将策略应用到运行中的执行器）。</summary>
    internal Func<string, Result<PolicyApplyOutcome>>? PolicyApplier { private get; set; }

    /// <summary>策略恢复回调（Worker 绑定：从备份恢复、重载并应用到运行中的执行器）。</summary>
    internal Func<Result<PolicyApplyOutcome>>? PolicyRestorer { private get; set; }

    /// <summary>Runner 执行器（Worker 绑定；null 时 runner.* 返回 UNAVAILABLE）。</summary>
    internal RunnerExecutor? Runner { private get; set; }

    /// <summary>分发请求（转发到注册表；信封解析失败由调用方处理）。</summary>
    /// <param name="request">请求信封。</param>
    /// <param name="session">连接会话。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    /// <param name="requestId">帧级请求号（透传至审计记录）。</param>
    /// <returns>响应信封。</returns>
    public Task<ResponseEnvelope> DispatchAsync(
        RequestEnvelope request, IpcConnectionSession session, CancellationToken cancellationToken,
        uint requestId = 0) =>
        Registry.DispatchAsync(request, session, cancellationToken, requestId);

    private void RegisterAll()
    {
        Registry.Register(new IpcCommandSpec
        {
            Method = SystemGetStatus,
            RequiredCapability = "status.read",
            AllowedRoles = new HashSet<IpcCallerRole> { IpcCallerRole.Bridge, IpcCallerRole.System },
            Timeout = TimeSpan.FromSeconds(5),
            AuditLevel = "meta",
            Handler = GetStatusAsync,
        });

        Registry.Register(new IpcCommandSpec
        {
            Method = SystemShutdown,
            RequiredCapability = "system.control",
            AllowedRoles = new HashSet<IpcCallerRole> { IpcCallerRole.System },
            Timeout = TimeSpan.FromSeconds(10),
            AuditLevel = "full",
            Handler = null, // M2 保留：服务停止走 SCM 恢复链路，不经 IPC 开放
        });

        Registry.Register(new IpcCommandSpec
        {
            Method = DeviceGetState,
            RequiredCapability = "device.read",
            AllowedRoles = new HashSet<IpcCallerRole> { IpcCallerRole.Bridge, IpcCallerRole.System },
            Timeout = TimeSpan.FromSeconds(5),
            AuditLevel = "meta",
            Handler = GetDeviceStateAsync,
        });

        Registry.Register(new IpcCommandSpec
        {
            Method = ClassroomBegin,
            RequiredCapability = "classroom.control",
            AllowedRoles = new HashSet<IpcCallerRole> { IpcCallerRole.System },
            Timeout = TimeSpan.FromSeconds(15),
            AuditLevel = "full",
            Handler = BeginClassroomAsync,
        });

        Registry.Register(new IpcCommandSpec
        {
            Method = ClassroomEnd,
            RequiredCapability = "classroom.control",
            AllowedRoles = new HashSet<IpcCallerRole> { IpcCallerRole.System },
            Timeout = TimeSpan.FromSeconds(15),
            AuditLevel = "full",
            Handler = EndClassroomAsync,
        });

        Registry.Register(new IpcCommandSpec
        {
            Method = PolicyApply,
            RequiredCapability = "policy.control",
            AllowedRoles = new HashSet<IpcCallerRole> { IpcCallerRole.System },
            Timeout = TimeSpan.FromSeconds(15),
            AuditLevel = "full",
            Handler = ApplyPolicyAsync,
        });

        Registry.Register(new IpcCommandSpec
        {
            Method = PolicyRestore,
            RequiredCapability = "policy.control",
            AllowedRoles = new HashSet<IpcCallerRole> { IpcCallerRole.System },
            Timeout = TimeSpan.FromSeconds(15),
            AuditLevel = "full",
            Handler = RestorePolicyAsync,
        });

        Registry.Register(new IpcCommandSpec
        {
            Method = RunnerGetCapabilities,
            RequiredCapability = "runner.read",
            AllowedRoles = new HashSet<IpcCallerRole> { IpcCallerRole.Bridge, IpcCallerRole.System },
            Timeout = TimeSpan.FromSeconds(5),
            AuditLevel = "meta",
            Handler = GetRunnerCapabilitiesAsync,
        });

        Registry.Register(new IpcCommandSpec
        {
            Method = RunnerExecute,
            RequiredCapability = "runner.execute",
            AllowedRoles = new HashSet<IpcCallerRole> { IpcCallerRole.Bridge },
            // 命令级超时须覆盖契约最坏窗口：编译 ≤30s + 墙钟 ≤60s（method_registry.md
            // v1 原 60s 默认不覆盖编译窗口，已随 M3-5 实装同步契约为 90s）
            Timeout = TimeSpan.FromSeconds(90),
            AuditLevel = "meta",
            Handler = ExecuteRunnerAsync,
        });
    }

    private Task<ResponseEnvelope> GetStatusAsync(IpcCommandContext context, CancellationToken cancellationToken)
    {
        var policy = PolicySnapshot?.Invoke();
        bool classroomActive;
        lock (_classroomLock)
        {
            classroomActive = _classroomActive;
        }

        return Task.FromResult(ResponseEnvelope.FromResult(new
        {
            component = "control_service",
            service_version = _componentVersion,
            device_id = _deviceId,
            uptime_s = (long)(DateTimeOffset.UtcNow - _startedAt).TotalSeconds,
            policy_id = policy?.PolicyId,
            policy_version = policy?.Version,
            classroom_active = classroomActive,
        }));
    }

    private Task<ResponseEnvelope> GetDeviceStateAsync(IpcCommandContext context, CancellationToken cancellationToken)
    {
        var policy = PolicySnapshot?.Invoke();
        return Task.FromResult(ResponseEnvelope.FromResult(new
        {
            device_id = _deviceId,
            service_version = _componentVersion,
            uptime_s = (long)(DateTimeOffset.UtcNow - _startedAt).TotalSeconds,
            policy_loaded = policy is not null,
            policy_id = policy?.PolicyId,
        }));
    }

    private Task<ResponseEnvelope> BeginClassroomAsync(IpcCommandContext context, CancellationToken cancellationToken)
    {
        string classroomId = string.Empty;
        if (context.Request.Params is JsonElement paramElement
            && paramElement.ValueKind == JsonValueKind.Object
            && paramElement.TryGetProperty("classroom_id", out var classroomElement)
            && classroomElement.ValueKind == JsonValueKind.String)
        {
            classroomId = classroomElement.GetString() ?? string.Empty;
        }

        long startedAt;
        lock (_classroomLock)
        {
            _classroomActive = true;
            _classroomId = classroomId;
            _classroomStartedAtUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            startedAt = _classroomStartedAtUnix;
        }

        _logger?.LogInformation("Classroom session begun (id={ClassroomId}, caller={CallerSid})",
            classroomId, context.Session.CallerSid);
        _telemetry?.Enqueue(TelemetryEvents.ClassroomBegin(
            classroomId, _deviceId, _componentVersion));

        return Task.FromResult(ResponseEnvelope.FromResult(new
        {
            active = true,
            classroom_id = classroomId,
            started_at_unix = startedAt,
        }));
    }

    private Task<ResponseEnvelope> EndClassroomAsync(IpcCommandContext context, CancellationToken cancellationToken)
    {
        string classroomId;
        long startedAt;
        lock (_classroomLock)
        {
            classroomId = _classroomId;
            startedAt = _classroomStartedAtUnix;
            _classroomActive = false;
            _classroomId = string.Empty;
        }

        _logger?.LogInformation("Classroom session ended (id={ClassroomId}, caller={CallerSid})",
            classroomId, context.Session.CallerSid);
        var endedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        _telemetry?.Enqueue(TelemetryEvents.ClassroomEnd(
            classroomId, Math.Max(0, endedAt - startedAt), _deviceId, _componentVersion));

        return Task.FromResult(ResponseEnvelope.FromResult(new
        {
            active = false,
            classroom_id = classroomId,
            started_at_unix = startedAt,
            ended_at_unix = endedAt,
        }));
    }

    private Task<ResponseEnvelope> ApplyPolicyAsync(IpcCommandContext context, CancellationToken cancellationToken)
    {
        if (PolicyApplier is null)
        {
            return Task.FromResult(Error(
                IpcErrorCodes.Unavailable, "policy persistence is not bound on this host.", context.Request.TraceId));
        }

        if (context.Request.Params is not JsonElement element || element.ValueKind != JsonValueKind.Object
            || !element.TryGetProperty("policy_json", out var policyElement)
            || policyElement.ValueKind != JsonValueKind.String)
        {
            return Task.FromResult(Error(
                IpcErrorCodes.InvalidArgument,
                "params.policy_json (string, PolicyFile JSON) is required.",
                context.Request.TraceId));
        }

        var policyJson = policyElement.GetString() ?? string.Empty;
        var result = PolicyApplier(policyJson);
        if (!result.IsSuccess)
        {
            // 阶段一失败：验证/落盘被拒——success=false、saved=false（未保存）
            _telemetry?.Enqueue(TelemetryEvents.PolicyResult(
                null, null, success: false, result.ErrorMessage,
                _deviceId, _componentVersion, context.Request.TraceId, saved: false));
            _logger?.LogWarning("Policy apply rejected: {Error} (caller={CallerSid})",
                result.ErrorMessage, context.Session.CallerSid);
            return Task.FromResult(Error(
                IpcErrorCodes.InvalidArgument,
                $"policy rejected: {result.ErrorMessage}",
                context.Request.TraceId));
        }

        // 阶段二结果：落盘已成功（saved=true），执行器应用可能部分失败——
        // 响应仍 ok=true（策略文件已生效），applied/apply_errors 如实上报
        var outcome = result.Data!;
        _telemetry?.Enqueue(TelemetryEvents.PolicyResult(
            outcome.Policy.PolicyId, outcome.Policy.Version,
            success: outcome.Applied,
            reason: outcome.Applied ? null : string.Join("; ", outcome.ApplyErrors),
            _deviceId, _componentVersion, context.Request.TraceId, saved: true));
        if (!outcome.Applied)
        {
            _logger?.LogError(
                "Policy {PolicyId} v{Version} saved but {Errors} executor(s) failed to apply: {Detail} (caller={CallerSid})",
                outcome.Policy.PolicyId, outcome.Policy.Version, outcome.ApplyErrors.Count,
                string.Join("; ", outcome.ApplyErrors), context.Session.CallerSid);
        }
        else
        {
            _logger?.LogInformation("Policy {PolicyId} v{Version} saved and applied to all executors (caller={CallerSid})",
                outcome.Policy.PolicyId, outcome.Policy.Version, context.Session.CallerSid);
        }

        return Task.FromResult(ResponseEnvelope.FromResult(new
        {
            policy_id = outcome.Policy.PolicyId,
            policy_version = outcome.Policy.Version,
            saved = true,
            applied = outcome.Applied,
            apply_errors = outcome.ApplyErrors,
        }));
    }

    private Task<ResponseEnvelope> RestorePolicyAsync(IpcCommandContext context, CancellationToken cancellationToken)
    {
        if (PolicyRestorer is null)
        {
            return Task.FromResult(Error(
                IpcErrorCodes.Unavailable, "policy persistence is not bound on this host.", context.Request.TraceId));
        }

        var result = PolicyRestorer();
        if (!result.IsSuccess)
        {
            _logger?.LogWarning("Policy restore rejected: {Error} (caller={CallerSid})",
                result.ErrorMessage, context.Session.CallerSid);
            return Task.FromResult(Error(
                IpcErrorCodes.NotFound,
                $"policy restore failed: {result.ErrorMessage}",
                context.Request.TraceId));
        }

        // 与 policy.apply 同构：恢复落盘成功后，执行器刷新结果如实上报
        var outcome = result.Data!;
        if (!outcome.Applied)
        {
            _logger?.LogError(
                "Policy {PolicyId} v{Version} restored but {Errors} executor(s) failed to apply: {Detail} (caller={CallerSid})",
                outcome.Policy.PolicyId, outcome.Policy.Version, outcome.ApplyErrors.Count,
                string.Join("; ", outcome.ApplyErrors), context.Session.CallerSid);
        }
        else
        {
            _logger?.LogInformation("Policy {PolicyId} v{Version} restored and applied to all executors (caller={CallerSid})",
                outcome.Policy.PolicyId, outcome.Policy.Version, context.Session.CallerSid);
        }

        return Task.FromResult(ResponseEnvelope.FromResult(new
        {
            policy_id = outcome.Policy.PolicyId,
            policy_version = outcome.Policy.Version,
            restored = true,
            saved = true,
            applied = outcome.Applied,
            apply_errors = outcome.ApplyErrors,
        }));
    }

    private Task<ResponseEnvelope> GetRunnerCapabilitiesAsync(IpcCommandContext context, CancellationToken cancellationToken)
    {
        if (Runner is null)
        {
            return Task.FromResult(Error(
                IpcErrorCodes.Unavailable, "runner executor is not bound on this host.", context.Request.TraceId));
        }

        var capabilities = Runner.GetCapabilities();
        return Task.FromResult(ResponseEnvelope.FromRawJson(
            JsonSerializer.Serialize(capabilities, RunnerJson.Options)));
    }

    private async Task<ResponseEnvelope> ExecuteRunnerAsync(IpcCommandContext context, CancellationToken cancellationToken)
    {
        if (Runner is null)
        {
            return Error(
                IpcErrorCodes.Unavailable, "runner executor is not bound on this host.", context.Request.TraceId);
        }

        if (context.Request.Params is not JsonElement element || element.ValueKind != JsonValueKind.Object)
        {
            return Error(
                IpcErrorCodes.InvalidArgument,
                "params must be a RunnerRequest JSON object (contracts/runner/runner.schema.json).",
                context.Request.TraceId);
        }

        RunnerRequest request;
        try
        {
            request = element.Deserialize<RunnerRequest>(RunnerJson.Options)
                ?? throw new JsonException("deserialized to null.");
        }
        catch (JsonException ex)
        {
            return Error(
                IpcErrorCodes.InvalidArgument,
                $"params is not a valid RunnerRequest: {ex.Message}",
                context.Request.TraceId);
        }

        // 信封 trace_id 回填（请求未自带时）：结果审计可跨层关联
        if (string.IsNullOrEmpty(request.TraceId) && !string.IsNullOrEmpty(context.Request.TraceId))
        {
            request = request with { TraceId = context.Request.TraceId };
        }

        var result = await Runner.ExecuteAsync(request, cancellationToken).ConfigureAwait(false);
        _logger?.LogInformation("Runner execute: {RequestId} -> {Status} ({ElapsedMs}ms, caller={CallerSid})",
            result.RequestId, result.Status, result.ElapsedMs, context.Session.CallerSid);
        EnqueueRunnerTelemetry(result);
        return ResponseEnvelope.FromRawJson(JsonSerializer.Serialize(result, RunnerJson.Options));
    }

    /// <summary>
    /// Runner 结果转云端分析事件（platform 白名单语义）：
    /// 编译阶段恒发 compile_result；进入运行阶段再发 run_result；
    /// REJECTED/INTERNAL_ERROR 属请求级/内部失败（无学习分析价值）不发声学事件。
    /// </summary>
    private void EnqueueRunnerTelemetry(RunnerResult result)
    {
        if (_telemetry is null)
        {
            return;
        }

        var status = StatusText(result.Status);
        switch (result.Status)
        {
            case RunnerStatus.CompiledOk:
            case RunnerStatus.CompileFailed:
                _telemetry.Enqueue(TelemetryEvents.CompileResult(
                    result.RequestId, status, result.ElapsedMs, result.CompileExitCode,
                    _deviceId, _componentVersion, result.TraceId));
                break;

            case RunnerStatus.RunOk:
            case RunnerStatus.RunFailed:
            case RunnerStatus.RunTimeout:
            case RunnerStatus.ResourceLimit:
                _telemetry.Enqueue(TelemetryEvents.CompileResult(
                    result.RequestId, StatusText(RunnerStatus.CompiledOk),
                    result.ElapsedMs, result.CompileExitCode,
                    _deviceId, _componentVersion, result.TraceId));
                _telemetry.Enqueue(TelemetryEvents.RunResult(
                    result.RequestId, status, result.ElapsedMs, result.RunExitCode,
                    result.PeakMemoryKb, result.TimedOut,
                    _deviceId, _componentVersion, result.TraceId));
                break;
        }
    }

    /// <summary>RunnerStatus → 契约大写下划线字符串（与 runner.schema.json 对齐）。</summary>
    private static string StatusText(RunnerStatus status) => status switch
    {
        RunnerStatus.CompiledOk => "COMPILED_OK",
        RunnerStatus.CompileFailed => "COMPILE_FAILED",
        RunnerStatus.RunOk => "RUN_OK",
        RunnerStatus.RunFailed => "RUN_FAILED",
        RunnerStatus.RunTimeout => "RUN_TIMEOUT",
        RunnerStatus.ResourceLimit => "RESOURCE_LIMIT",
        RunnerStatus.InternalError => "INTERNAL_ERROR",
        RunnerStatus.Rejected => "REJECTED",
        _ => status.ToString(),
    };

    private static ResponseEnvelope Error(string code, string message, string? traceId) =>
        ResponseEnvelope.FromError(ErrorEnvelope.Create(code, message, traceId));
}
