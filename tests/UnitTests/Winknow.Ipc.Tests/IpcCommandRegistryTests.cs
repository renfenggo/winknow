using Winknow.Ipc.Commands;
using Winknow.Ipc.Protocol;
using Winknow.Ipc.Session;

namespace Winknow.Ipc.Tests;

/// <summary>
/// M2-3 命令注册表测试（method_registry.md 白名单分发语义）：
/// 未知方法/角色拒绝/能力不匹配/未实现/超时/异常全部返回契约错误信封而非抛出。
/// </summary>
public sealed class IpcCommandRegistryTests
{
    private const string SystemSid = "S-1-5-18";
    private const string BridgeSid = "S-1-5-21-3623811015-3361044348-30300820-1013";

    private static IpcConnectionSession CreateSession(
        string component = "bridge",
        string callerSid = BridgeSid,
        params string[] capabilities) => new()
    {
        HandshakeCompleted = true,
        Component = component,
        CallerSid = callerSid,
        GrantedCapabilities = new HashSet<string>(capabilities, StringComparer.Ordinal),
    };

    private static IpcCommandRegistry CreateRegistry() => new(sid => sid == SystemSid);

    private static IpcCommandSpec Spec(
        string method = "system.get_status",
        string capability = "status.read",
        IpcCallerRole[]? roles = null,
        IpcCommandHandler? handler = null,
        TimeSpan? timeout = null) => new()
    {
        Method = method,
        RequiredCapability = capability,
        AllowedRoles = new HashSet<IpcCallerRole>(roles ?? new[] { IpcCallerRole.Bridge, IpcCallerRole.System }),
        Timeout = timeout ?? TimeSpan.FromSeconds(5),
        AuditLevel = "meta",
        Handler = handler,
    };

    private static Task<ResponseEnvelope> OkHandler(IpcCommandContext context, CancellationToken ct) =>
        Task.FromResult(ResponseEnvelope.FromResult(new { echoed = context.Request.Method, role = context.Role.ToString() }));

    [Fact]
    public async Task Dispatch_UnknownMethod_ReturnsIpcUnknownMethod()
    {
        var registry = CreateRegistry();
        registry.Register(Spec());

        var response = await registry.DispatchAsync(
            new RequestEnvelope { Method = "system.no_such" }, CreateSession(), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcUnknownMethod, response.Error!.Code);
        Assert.False(response.Error.Retryable);
        Assert.Equal("unknown_method", response.Error.Details!["denied_reason"]);
    }

    [Fact]
    public async Task Dispatch_MalformedMethodName_ReturnsIpcUnknownMethod()
    {
        var registry = CreateRegistry();

        var response = await registry.DispatchAsync(
            new RequestEnvelope { Method = "not-a-method" }, CreateSession(), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcUnknownMethod, response.Error!.Code);
    }

    [Fact]
    public async Task Dispatch_RegisteredWithoutHandler_ReturnsNotImplemented()
    {
        var registry = CreateRegistry();
        registry.Register(Spec(method: "runner.get_capabilities", capability: "runner.read", handler: null));

        var response = await registry.DispatchAsync(
            new RequestEnvelope { Method = "runner.get_capabilities" },
            CreateSession(capabilities: "runner.read"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.NotImplemented, response.Error!.Code);
    }

    [Fact]
    public async Task Dispatch_CapabilityNotGranted_ReturnsIpcCapabilityMismatch()
    {
        var registry = CreateRegistry();
        registry.Register(Spec());

        // 会话协商了其他能力但未协商 status.read
        var response = await registry.DispatchAsync(
            new RequestEnvelope { Method = "system.get_status" },
            CreateSession(capabilities: "device.read"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcCapabilityMismatch, response.Error!.Code);
        Assert.Equal("status.read", response.Error.Details!["required_capability"]);
        Assert.Equal("capability_not_granted", response.Error.Details!["denied_reason"]);
    }

    [Fact]
    public async Task Dispatch_RoleNotAllowed_ReturnsIpcSidNotAuthorized()
    {
        var registry = CreateRegistry();
        // 仅 system 角色可调用（classroom.begin 语义）
        registry.Register(Spec(method: "classroom.begin", capability: "classroom.control",
            roles: new[] { IpcCallerRole.System }));

        var response = await registry.DispatchAsync(
            new RequestEnvelope { Method = "classroom.begin" },
            CreateSession(component: "bridge", capabilities: "classroom.control"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcSidNotAuthorized, response.Error!.Code);
        Assert.Equal("role_not_allowed", response.Error.Details!["denied_reason"]);
        Assert.Equal("Bridge", response.Error.Details!["role"]);
    }

    [Fact]
    public async Task Dispatch_SystemSidResolvesSystemRole_CallsSystemOnlyMethod()
    {
        var registry = CreateRegistry();
        IpcCallerRole? observedRole = null;
        registry.Register(Spec(method: "classroom.begin", capability: "classroom.control",
            roles: new[] { IpcCallerRole.System },
            handler: (ctx, _) =>
            {
                observedRole = ctx.Role;
                return Task.FromResult(ResponseEnvelope.FromResult(new { active = true }));
            }));

        // 组件为 admin_tool 但 SID 是 LocalSystem → System 角色
        var response = await registry.DispatchAsync(
            new RequestEnvelope { Method = "classroom.begin" },
            CreateSession(component: "admin_tool", callerSid: SystemSid, capabilities: "classroom.control"),
            CancellationToken.None);

        Assert.True(response.Ok);
        Assert.Equal(IpcCallerRole.System, observedRole);
    }

    [Fact]
    public async Task Dispatch_AllowedBridgeMethod_ReturnsHandlerResult()
    {
        var registry = CreateRegistry();
        registry.Register(Spec(handler: OkHandler));

        var request = new RequestEnvelope { Method = "system.get_status", TraceId = "trace-1" };
        var response = await registry.DispatchAsync(
            request, CreateSession(capabilities: "status.read"), CancellationToken.None);

        Assert.True(response.Ok);
        Assert.NotNull(response.Result);
        Assert.Equal("system.get_status", response.Result!.Value.GetProperty("echoed").GetString());
        Assert.Equal("Bridge", response.Result.Value.GetProperty("role").GetString());
    }

    [Fact]
    public async Task Dispatch_HandlerThrows_ReturnsInternalError()
    {
        var registry = CreateRegistry();
        registry.Register(Spec(handler: (_, _) => throw new InvalidOperationException("boom")));

        var response = await registry.DispatchAsync(
            new RequestEnvelope { Method = "system.get_status" },
            CreateSession(capabilities: "status.read"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.InternalError, response.Error!.Code);
        Assert.True(response.Error.Retryable);
        Assert.DoesNotContain("boom", response.Error.Message);
    }

    [Fact]
    public async Task Dispatch_HandlerExceedsTimeout_ReturnsTimeout()
    {
        var registry = CreateRegistry();
        registry.Register(Spec(
            timeout: TimeSpan.FromMilliseconds(50),
            handler: async (_, ct) =>
            {
                await Task.Delay(TimeSpan.FromSeconds(5), ct);
                return ResponseEnvelope.FromResult(new { });
            }));

        var response = await registry.DispatchAsync(
            new RequestEnvelope { Method = "system.get_status" },
            CreateSession(capabilities: "status.read"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.Timeout, response.Error!.Code);
        Assert.True(response.Error.Retryable);
    }

    [Fact]
    public async Task Dispatch_UnknownRoleSession_DeniedForAllMethods()
    {
        var registry = CreateRegistry();
        registry.Register(Spec());

        // 非系统 SID、非 bridge 组件（如学生自写程序假冒组件名之外的身份）→ Unknown 角色
        var response = await registry.DispatchAsync(
            new RequestEnvelope { Method = "system.get_status" },
            CreateSession(component: "unknown_tool", capabilities: "status.read"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcSidNotAuthorized, response.Error!.Code);
    }

    [Fact]
    public async Task Dispatch_TraceIdPropagatedToErrors()
    {
        var registry = CreateRegistry();

        var response = await registry.DispatchAsync(
            new RequestEnvelope { Method = "system.missing", TraceId = "trace-42" },
            CreateSession(), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal("trace-42", response.Error!.TraceId);
    }

    [Fact]
    public void Register_DuplicateMethod_Throws()
    {
        var registry = CreateRegistry();
        registry.Register(Spec());

        Assert.Throws<InvalidOperationException>(() => registry.Register(Spec()));
    }

    [Fact]
    public void Register_InvalidMethodName_Throws()
    {
        var registry = CreateRegistry();

        Assert.Throws<ArgumentException>(() => registry.Register(Spec(method: "noDots")));
        Assert.Throws<ArgumentException>(() => registry.Register(Spec(method: "")));
    }

    [Fact]
    public void Register_NoRoles_Throws()
    {
        var registry = CreateRegistry();

        Assert.Throws<ArgumentException>(() => registry.Register(Spec(roles: Array.Empty<IpcCallerRole>())));
    }

    [Fact]
    public void ResolveRole_BridgeComponent_ReturnsBridge()
    {
        var registry = CreateRegistry();

        Assert.Equal(IpcCallerRole.Bridge, registry.ResolveRole(CreateSession(component: "bridge")));
    }
}
