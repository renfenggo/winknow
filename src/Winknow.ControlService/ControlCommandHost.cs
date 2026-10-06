using System.Text.Json;
using Microsoft.Extensions.Logging;
using Winknow.Core.Results;
using Winknow.Ipc.Commands;
using Winknow.Ipc.Protocol;
using Winknow.Ipc.Session;
using Winknow.Policy;

namespace Winknow.ControlService;

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

    private readonly ILogger<ControlCommandHost>? _logger;
    private readonly string _deviceId;
    private readonly string _componentVersion;
    private readonly DateTimeOffset _startedAt = DateTimeOffset.UtcNow;

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
    public ControlCommandHost(
        ILogger<ControlCommandHost>? logger,
        string deviceId,
        string componentVersion,
        Func<string, bool> isSystemSid,
        IIpcAuditSink? auditSink = null)
    {
        _logger = logger;
        _deviceId = deviceId;
        _componentVersion = componentVersion;

        Registry = new IpcCommandRegistry(isSystemSid, auditSink);
        RegisterAll();
    }

    /// <summary>命令注册表（Worker 将 RequestReceived 转发至此）。</summary>
    public IpcCommandRegistry Registry { get; }

    /// <summary>当前策略快照读取器（Worker 绑定；null 时报告策略未加载）。</summary>
    internal Func<PolicyFile?>? PolicySnapshot { private get; set; }

    /// <summary>策略应用回调（Worker 绑定：验证、备份并落盘+重载）。</summary>
    internal Func<string, Result<PolicyFile>>? PolicyApplier { private get; set; }

    /// <summary>策略恢复回调（Worker 绑定：从备份恢复并重载）。</summary>
    internal Func<Result<PolicyFile>>? PolicyRestorer { private get; set; }

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
            Handler = null, // M2 占位，M3 实装（method_registry.md）
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

        return Task.FromResult(ResponseEnvelope.FromResult(new
        {
            active = false,
            classroom_id = classroomId,
            started_at_unix = startedAt,
            ended_at_unix = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
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
            _logger?.LogWarning("Policy apply rejected: {Error} (caller={CallerSid})",
                result.ErrorMessage, context.Session.CallerSid);
            return Task.FromResult(Error(
                IpcErrorCodes.InvalidArgument,
                $"policy rejected: {result.ErrorMessage}",
                context.Request.TraceId));
        }

        var policy = result.Data!;
        _logger?.LogInformation("Policy applied: {PolicyId} v{Version} (caller={CallerSid})",
            policy.PolicyId, policy.Version, context.Session.CallerSid);

        return Task.FromResult(ResponseEnvelope.FromResult(new
        {
            policy_id = policy.PolicyId,
            policy_version = policy.Version,
            applied = true,
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

        var policy = result.Data!;
        _logger?.LogInformation("Policy restored: {PolicyId} v{Version} (caller={CallerSid})",
            policy.PolicyId, policy.Version, context.Session.CallerSid);

        return Task.FromResult(ResponseEnvelope.FromResult(new
        {
            policy_id = policy.PolicyId,
            policy_version = policy.Version,
            restored = true,
        }));
    }

    private static ResponseEnvelope Error(string code, string message, string? traceId) =>
        ResponseEnvelope.FromError(ErrorEnvelope.Create(code, message, traceId));
}
