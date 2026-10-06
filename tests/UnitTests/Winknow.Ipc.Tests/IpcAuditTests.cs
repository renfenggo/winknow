using Winknow.Ipc.Commands;
using Winknow.Ipc.Protocol;
using Winknow.Ipc.Session;

namespace Winknow.Ipc.Tests;

/// <summary>
/// M2-5 审计/追踪测试（指导书 04 第 6 节）：
/// 每次跨边界调用（成功或拒绝）产出一条记录，字段含
/// trace_id/request_id/command/caller_sid/result_code/latency/denied_reason；
/// sink 异常不得影响分发。
/// </summary>
public sealed class IpcAuditTests
{
    private const string SystemSid = "S-1-5-18";
    private const string BridgeSid = "S-1-5-21-3623811015-3361044348-30300820-1013";

    private sealed class RecordingAuditSink : IIpcAuditSink
    {
        public List<IpcAuditRecord> Records { get; } = new();

        public void Write(IpcAuditRecord record) => Records.Add(record);
    }

    private sealed class ThrowingAuditSink : IIpcAuditSink
    {
        public void Write(IpcAuditRecord record) => throw new InvalidOperationException("sink boom");
    }

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

    private static IpcCommandSpec Spec(
        string method = "system.get_status",
        string capability = "status.read",
        string auditLevel = "meta",
        IpcCallerRole[]? roles = null,
        IpcCommandHandler? handler = null,
        TimeSpan? timeout = null) => new()
    {
        Method = method,
        RequiredCapability = capability,
        AllowedRoles = new HashSet<IpcCallerRole>(roles ?? new[] { IpcCallerRole.Bridge, IpcCallerRole.System }),
        Timeout = timeout ?? TimeSpan.FromSeconds(5),
        AuditLevel = auditLevel,
        Handler = handler,
    };

    private static Task<ResponseEnvelope> OkHandler(IpcCommandContext context, CancellationToken ct) =>
        Task.FromResult(ResponseEnvelope.FromResult(new { echoed = context.Request.Method }));

    [Fact]
    public async Task Audit_SuccessfulCall_RecordsAllFields()
    {
        var sink = new RecordingAuditSink();
        var registry = new IpcCommandRegistry(sid => sid == SystemSid, sink);
        registry.Register(Spec(handler: OkHandler));

        var response = await registry.DispatchAsync(
            new RequestEnvelope { Method = "system.get_status", TraceId = "trace-7" },
            CreateSession(callerSid: BridgeSid, capabilities: "status.read"),
            CancellationToken.None, requestId: 42);

        Assert.True(response.Ok);
        var record = Assert.Single(sink.Records);
        Assert.Equal("trace-7", record.TraceId);
        Assert.Equal(42u, record.RequestId);
        Assert.Equal("system.get_status", record.Method);
        Assert.Equal(BridgeSid, record.CallerSid);
        Assert.Equal(IpcCallerRole.Bridge, record.Role);
        Assert.True(record.Ok);
        Assert.Equal("OK", record.ResultCode);
        Assert.True(record.LatencyMs >= 0);
        Assert.Null(record.DeniedReason);
        Assert.Equal("meta", record.AuditLevel);
        Assert.True(record.Timestamp <= DateTimeOffset.UtcNow.AddSeconds(5));
    }

    [Fact]
    public async Task Audit_UnknownMethod_RecordsDeniedWithReason()
    {
        var sink = new RecordingAuditSink();
        var registry = new IpcCommandRegistry(sid => sid == SystemSid, sink);

        await registry.DispatchAsync(
            new RequestEnvelope { Method = "system.no_such", TraceId = "trace-x" },
            CreateSession(), CancellationToken.None, requestId: 7);

        var record = Assert.Single(sink.Records);
        Assert.False(record.Ok);
        Assert.Equal(IpcErrorCodes.IpcUnknownMethod, record.ResultCode);
        Assert.Equal("unknown_method", record.DeniedReason);
        Assert.Equal("denied", record.AuditLevel);
        Assert.Equal("system.no_such", record.Method);
        Assert.Equal(7u, record.RequestId);
    }

    [Fact]
    public async Task Audit_RoleDenied_RecordsDeniedReason()
    {
        var sink = new RecordingAuditSink();
        var registry = new IpcCommandRegistry(sid => sid == SystemSid, sink);
        registry.Register(Spec(method: "classroom.begin", capability: "classroom.control",
            roles: new[] { IpcCallerRole.System }));

        await registry.DispatchAsync(
            new RequestEnvelope { Method = "classroom.begin" },
            CreateSession(component: "bridge", capabilities: "classroom.control"), CancellationToken.None);

        var record = Assert.Single(sink.Records);
        Assert.False(record.Ok);
        Assert.Equal(IpcErrorCodes.IpcSidNotAuthorized, record.ResultCode);
        Assert.Equal("role_not_allowed", record.DeniedReason);
        Assert.Equal("denied", record.AuditLevel);
    }

    [Fact]
    public async Task Audit_CapabilityMismatch_RecordsDeniedReason()
    {
        var sink = new RecordingAuditSink();
        var registry = new IpcCommandRegistry(sid => sid == SystemSid, sink);
        registry.Register(Spec());

        await registry.DispatchAsync(
            new RequestEnvelope { Method = "system.get_status" },
            CreateSession(capabilities: "device.read"), CancellationToken.None);

        var record = Assert.Single(sink.Records);
        Assert.Equal(IpcErrorCodes.IpcCapabilityMismatch, record.ResultCode);
        Assert.Equal("capability_not_granted", record.DeniedReason);
        Assert.Equal("denied", record.AuditLevel);
    }

    [Fact]
    public async Task Audit_Timeout_RecordsTimeoutReason()
    {
        var sink = new RecordingAuditSink();
        var registry = new IpcCommandRegistry(sid => sid == SystemSid, sink);
        registry.Register(Spec(
            auditLevel: "full",
            timeout: TimeSpan.FromMilliseconds(50),
            handler: async (_, ct) =>
            {
                await Task.Delay(TimeSpan.FromSeconds(5), ct);
                return ResponseEnvelope.FromResult(new { });
            }));

        await registry.DispatchAsync(
            new RequestEnvelope { Method = "system.get_status" },
            CreateSession(capabilities: "status.read"), CancellationToken.None);

        var record = Assert.Single(sink.Records);
        Assert.Equal(IpcErrorCodes.Timeout, record.ResultCode);
        Assert.Equal("timeout", record.DeniedReason);
        Assert.Equal("denied", record.AuditLevel);
    }

    [Fact]
    public async Task Audit_HandlerThrows_RecordsInternalError()
    {
        var sink = new RecordingAuditSink();
        var registry = new IpcCommandRegistry(sid => sid == SystemSid, sink);
        registry.Register(Spec(handler: (_, _) => throw new InvalidOperationException("boom")));

        await registry.DispatchAsync(
            new RequestEnvelope { Method = "system.get_status" },
            CreateSession(capabilities: "status.read"), CancellationToken.None);

        var record = Assert.Single(sink.Records);
        Assert.False(record.Ok);
        Assert.Equal(IpcErrorCodes.InternalError, record.ResultCode);
        Assert.Null(record.DeniedReason);
        // 处理器异常属内部错误，审计级仍取 spec 声明（full）
        Assert.Equal("meta", record.AuditLevel);
    }

    [Fact]
    public async Task Audit_NotImplemented_KeepsSpecAuditLevel()
    {
        var sink = new RecordingAuditSink();
        var registry = new IpcCommandRegistry(sid => sid == SystemSid, sink);
        registry.Register(Spec(method: "runner.get_capabilities", capability: "runner.read",
            auditLevel: "meta", handler: null));

        await registry.DispatchAsync(
            new RequestEnvelope { Method = "runner.get_capabilities" },
            CreateSession(capabilities: "runner.read"), CancellationToken.None);

        var record = Assert.Single(sink.Records);
        Assert.Equal(IpcErrorCodes.NotImplemented, record.ResultCode);
        Assert.Equal("meta", record.AuditLevel);
    }

    [Fact]
    public async Task Audit_SinkThrows_DoesNotAffectDispatch()
    {
        var registry = new IpcCommandRegistry(sid => sid == SystemSid, new ThrowingAuditSink());
        registry.Register(Spec(handler: OkHandler));

        var response = await registry.DispatchAsync(
            new RequestEnvelope { Method = "system.get_status" },
            CreateSession(capabilities: "status.read"), CancellationToken.None);

        Assert.True(response.Ok);
        Assert.Equal("system.get_status", response.Result!.Value.GetProperty("echoed").GetString());
    }

    [Fact]
    public async Task Audit_NoSink_DispatchStillWorks()
    {
        var registry = new IpcCommandRegistry(sid => sid == SystemSid);
        registry.Register(Spec(handler: OkHandler));

        var response = await registry.DispatchAsync(
            new RequestEnvelope { Method = "system.get_status" },
            CreateSession(capabilities: "status.read"), CancellationToken.None);

        Assert.True(response.Ok);
    }

    [Fact]
    public async Task Audit_SystemRole_ResolvedFromSystemSid()
    {
        var sink = new RecordingAuditSink();
        var registry = new IpcCommandRegistry(sid => sid == SystemSid, sink);
        registry.Register(Spec(auditLevel: "full",
            roles: new[] { IpcCallerRole.System }, handler: OkHandler));

        await registry.DispatchAsync(
            new RequestEnvelope { Method = "system.get_status" },
            CreateSession(component: "admin_tool", callerSid: SystemSid, capabilities: "status.read"),
            CancellationToken.None, requestId: uint.MaxValue);

        var record = Assert.Single(sink.Records);
        Assert.Equal(IpcCallerRole.System, record.Role);
        Assert.Equal("full", record.AuditLevel);
        Assert.Equal(uint.MaxValue, record.RequestId);
    }
}
