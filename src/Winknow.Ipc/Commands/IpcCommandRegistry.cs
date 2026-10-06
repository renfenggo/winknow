using System.Diagnostics;
using Winknow.Ipc.Protocol;
using Winknow.Ipc.Session;

namespace Winknow.Ipc.Commands;

/// <summary>
/// 调用方角色（method_registry.md 允许 caller role）。
/// 帧级认证（IpcAuthenticator）决定"能否连上来"；角色决定"能调用哪些方法"。
/// </summary>
public enum IpcCallerRole
{
    /// <summary>SYSTEM/Administrators 静态白名单身份。</summary>
    System,

    /// <summary>DesktopBridge 组件身份（handshake component=bridge）。</summary>
    Bridge,

    /// <summary>动态 SID 会话授权的学生身份（M2-4 起可判定）。</summary>
    Student,

    /// <summary>已通过帧级认证但不属于任何已知角色（无方法可调用）。</summary>
    Unknown,
}

/// <summary>命令处理上下文（方法、会话与角色已由注册表校验）。</summary>
public sealed class IpcCommandContext
{
    /// <summary>解析后的请求信封。</summary>
    public required RequestEnvelope Request { get; init; }

    /// <summary>连接会话（能力、身份、组件）。</summary>
    public required IpcConnectionSession Session { get; init; }

    /// <summary>解析出的调用方角色。</summary>
    public required IpcCallerRole Role { get; init; }

    /// <summary>命中的命令注册项。</summary>
    public required IpcCommandSpec Spec { get; init; }
}

/// <summary>命令处理器：返回 ResponseEnvelope（由 IpcServer 回写为响应帧）。</summary>
/// <param name="context">命令上下文。</param>
/// <param name="cancellationToken">含命令级超时的取消令牌。</param>
/// <returns>响应信封。</returns>
public delegate Task<ResponseEnvelope> IpcCommandHandler(IpcCommandContext context, CancellationToken cancellationToken);

/// <summary>
/// 单条命令的注册项：方法白名单五要素
/// （schema 即方法名+params 语义、required capability、allowed caller role、timeout、audit level）。
/// Handler 为 null 表示已注册未实现（返回 NOT_IMPLEMENTED，见 method_registry.md）。
/// </summary>
public sealed class IpcCommandSpec
{
    /// <summary>方法名（必须在 method_registry.md 白名单内）。</summary>
    public required string Method { get; init; }

    /// <summary>调用该方法所需的最小 capability（必须已在握手中协商授予）。</summary>
    public required string RequiredCapability { get; init; }

    /// <summary>允许的调用方角色集合。</summary>
    public required IReadOnlySet<IpcCallerRole> AllowedRoles { get; init; }

    /// <summary>命令级超时。</summary>
    public required TimeSpan Timeout { get; init; }

    /// <summary>审计级（meta/full，见 method_registry.md audit 列）。</summary>
    public required string AuditLevel { get; init; }

    /// <summary>处理器（null 表示注册未实现）。</summary>
    public IpcCommandHandler? Handler { get; init; }
}

/// <summary>
/// IPC 命令注册表与分发器（method_registry.md 白名单的唯一代码化身）。
///
/// 分发顺序（未通过即返回错误信封，details 携带 denied_reason 供审计）：
/// 1. 方法名格式与注册查询 → 未注册返回 IPC_UNKNOWN_METHOD；
/// 2. 角色检查 → 不允许返回 IPC_SID_NOT_AUTHORIZED；
/// 3. capability 检查 → 未协商返回 IPC_CAPABILITY_MISMATCH；
/// 4. 未实现 → NOT_IMPLEMENTED；
/// 5. 执行（命令级超时：超时返回 TIMEOUT，异常返回 INTERNAL_ERROR）。
/// </summary>
public sealed class IpcCommandRegistry
{
    private readonly Dictionary<string, IpcCommandSpec> _methods = new(StringComparer.Ordinal);
    private readonly Func<string, bool>? _isSystemSid;
    private readonly IIpcAuditSink? _auditSink;

    /// <summary>创建命令注册表。</summary>
    /// <param name="isSystemSid">系统 SID 判定谓词（LocalSystem/Administrators 静态身份，非动态白名单）。</param>
    /// <param name="auditSink">审计输出端（null 表示不落审计；仅测试/诊断场景）。</param>
    public IpcCommandRegistry(Func<string, bool>? isSystemSid = null, IIpcAuditSink? auditSink = null)
    {
        _isSystemSid = isSystemSid;
        _auditSink = auditSink;
    }

    /// <summary>已注册方法数。</summary>
    public int Count => _methods.Count;

    /// <summary>已注册命令（只读快照）。</summary>
    public IEnumerable<IpcCommandSpec> Specs => _methods.Values;

    /// <summary>注册命令；方法重复或非法抛出异常（启动期错误，禁止静默吞掉）。</summary>
    /// <param name="spec">命令注册项。</param>
    public void Register(IpcCommandSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);

        if (string.IsNullOrEmpty(spec.Method) || !RequestEnvelope.IsValidMethodName(spec.Method))
        {
            throw new ArgumentException($"method '{spec.Method}' is not a valid registry method name.", nameof(spec));
        }

        if (spec.RequiredCapability.Length == 0)
        {
            throw new ArgumentException($"method '{spec.Method}' must declare a required capability.", nameof(spec));
        }

        if (spec.AllowedRoles.Count == 0)
        {
            throw new ArgumentException($"method '{spec.Method}' must declare at least one allowed role.", nameof(spec));
        }

        if (_methods.ContainsKey(spec.Method))
        {
            throw new InvalidOperationException($"IPC method '{spec.Method}' is already registered.");
        }

        _methods[spec.Method] = spec;
    }

    /// <summary>
    /// 解析调用方角色：系统 SID → System；bridge 组件 → Bridge；
    /// 其余（含动态学生 SID，M2-4 起接入）→ Student/Unknown。
    /// </summary>
    /// <param name="session">连接会话。</param>
    /// <returns>调用方角色。</returns>
    public IpcCallerRole ResolveRole(IpcConnectionSession session)
    {
        ArgumentNullException.ThrowIfNull(session);

        if (!string.IsNullOrEmpty(session.CallerSid) && _isSystemSid?.Invoke(session.CallerSid) == true)
        {
            return IpcCallerRole.System;
        }

        if (string.Equals(session.Component, "bridge", StringComparison.Ordinal))
        {
            return IpcCallerRole.Bridge;
        }

        return IpcCallerRole.Unknown;
    }

    /// <summary>
    /// 按白名单分发请求（校验顺序见类注释；绝不抛出，失败返回错误信封），
    /// 并对每次调用（成功或拒绝）写一条审计记录（指导书 04 第 6 节）。
    /// </summary>
    /// <param name="request">请求信封。</param>
    /// <param name="session">连接会话。</param>
    /// <param name="cancellationToken">连接级取消令牌。</param>
    /// <param name="requestId">帧级请求号（IpcMessage.RequestId；0 表示未知来源）。</param>
    /// <returns>响应信封。</returns>
    public async Task<ResponseEnvelope> DispatchAsync(
        RequestEnvelope request, IpcConnectionSession session, CancellationToken cancellationToken,
        uint requestId = 0)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(session);

        long startTimestamp = Stopwatch.GetTimestamp();
        var response = await DispatchCoreAsync(request, session, cancellationToken).ConfigureAwait(false);
        WriteAudit(request, session, requestId, response, Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds);
        return response;
    }

    private async Task<ResponseEnvelope> DispatchCoreAsync(
        RequestEnvelope request, IpcConnectionSession session, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(request.Method) || !RequestEnvelope.IsValidMethodName(request.Method)
            || !_methods.TryGetValue(request.Method, out var spec))
        {
            return Error(
                IpcErrorCodes.IpcUnknownMethod,
                $"method '{request.Method}' is not registered.",
                request.TraceId,
                new Dictionary<string, object?>
                {
                    ["method"] = request.Method,
                    ["denied_reason"] = "unknown_method",
                });
        }

        var role = ResolveRole(session);
        if (!spec.AllowedRoles.Contains(role))
        {
            return Error(
                IpcErrorCodes.IpcSidNotAuthorized,
                $"caller role {role} is not allowed for '{spec.Method}'.",
                request.TraceId,
                new Dictionary<string, object?>
                {
                    ["method"] = spec.Method,
                    ["role"] = role.ToString(),
                    ["denied_reason"] = "role_not_allowed",
                });
        }

        if (!session.GrantedCapabilities.Contains(spec.RequiredCapability))
        {
            return Error(
                IpcErrorCodes.IpcCapabilityMismatch,
                $"capability '{spec.RequiredCapability}' was not granted for '{spec.Method}'.",
                request.TraceId,
                new Dictionary<string, object?>
                {
                    ["method"] = spec.Method,
                    ["required_capability"] = spec.RequiredCapability,
                    ["granted_capabilities"] = string.Join(",", session.GrantedCapabilities),
                    ["denied_reason"] = "capability_not_granted",
                });
        }

        if (spec.Handler is null)
        {
            return Error(
                IpcErrorCodes.NotImplemented,
                $"'{spec.Method}' is registered but not implemented.",
                request.TraceId);
        }

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(spec.Timeout);
            var context = new IpcCommandContext
            {
                Request = request,
                Session = session,
                Role = role,
                Spec = spec,
            };
            return await spec.Handler(context, timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Error(
                IpcErrorCodes.Timeout,
                $"'{spec.Method}' exceeded timeout of {spec.Timeout.TotalSeconds:0}s.",
                request.TraceId,
                new Dictionary<string, object?>
                {
                    ["timeout_s"] = spec.Timeout.TotalSeconds,
                    ["denied_reason"] = "timeout",
                });
        }
        catch (Exception)
        {
            // 处理器异常不外泄细节（内部日志由宿主记录）
            return Error(
                IpcErrorCodes.InternalError,
                $"'{spec.Method}' handler failed.",
                request.TraceId);
        }
    }

    /// <summary>
    /// 写审计记录（M2-5）：结果码取响应错误码（成功为 OK）；
    /// denied_reason 取错误 details.denied_reason；审计级——未知方法或携带
    /// denied_reason 的拒绝为 "denied"，其余（成功、handler 业务错误）取 spec.AuditLevel。
    /// sink 异常一律吞掉：审计绝不阻断分发。
    /// </summary>
    private void WriteAudit(
        RequestEnvelope request, IpcConnectionSession session, uint requestId,
        ResponseEnvelope response, double latencyMs)
    {
        if (_auditSink is null)
        {
            return;
        }

        try
        {
            string? deniedReason = null;
            if (!response.Ok && response.Error?.Details is { } details
                && details.TryGetValue("denied_reason", out var reason) && reason is not null)
            {
                deniedReason = reason.ToString();
            }

            IpcCommandSpec? spec = null;
            var registered = !string.IsNullOrEmpty(request.Method) && _methods.TryGetValue(request.Method, out spec);
            var auditLevel = !registered || (!response.Ok && deniedReason is not null)
                ? "denied"
                : spec!.AuditLevel;

            _auditSink.Write(new IpcAuditRecord
            {
                Timestamp = DateTimeOffset.UtcNow,
                TraceId = request.TraceId,
                RequestId = requestId,
                Method = request.Method ?? string.Empty,
                CallerSid = session.CallerSid,
                Role = ResolveRole(session),
                Ok = response.Ok,
                ResultCode = response.Ok ? "OK" : (response.Error?.Code ?? IpcErrorCodes.InternalError),
                LatencyMs = Math.Max(0, (long)latencyMs),
                DeniedReason = deniedReason,
                AuditLevel = auditLevel,
            });
        }
        catch
        {
            // 审计写入失败不得影响命令分发
        }
    }

    private static ResponseEnvelope Error(string code, string message, string? traceId,
        IReadOnlyDictionary<string, object?>? details = null) =>
        ResponseEnvelope.FromError(ErrorEnvelope.Create(code, message, traceId, details));
}
