using System.Text.Json;
using Winknow.ControlService;
using Winknow.Core.Results;
using Winknow.Ipc.Commands;
using Winknow.Ipc.Protocol;
using Winknow.Ipc.Session;
using Winknow.Policy;
using Winknow.Telemetry;

namespace Winknow.ControlService.Tests;

/// <summary>
/// P1（2026-10-08）策略生效链 + 课堂会话 IPC 行为测试：ControlCommandHost
/// 直连注册表分发（无管道），验证：
/// - policy.apply / policy.restore 响应三态（saved / applied / apply_errors），
///   不再以 applied=true 掩盖执行器未刷新的状态；
/// - device.policy_result 遥测 success=执行器真实应用结果、saved 区分拒绝与应用失败；
/// - classroom.begin / end 会话状态机与 system 角色限制。
/// </summary>
public sealed class PolicyAndClassroomIpcTests
{
    private const string SystemSid = "S-1-5-18";
    private const string BridgeSid = "S-1-5-21-3623811015-3361044348-30300820-1013";

    private sealed class RecordingTelemetrySink : ITelemetrySink
    {
        public List<TelemetryEvent> Events { get; } = new();

        public void Enqueue(TelemetryEvent evt) => Events.Add(evt);
    }

    private static ControlCommandHost CreateHost(RecordingTelemetrySink? telemetry = null) =>
        new(null, "device-test-0001", "test", sid => sid == SystemSid, telemetrySink: telemetry);

    private static IpcConnectionSession SystemSession(params string[] capabilities) => new()
    {
        HandshakeCompleted = true,
        Component = "admin_tool",
        CallerSid = SystemSid,
        GrantedCapabilities = new HashSet<string>(capabilities, StringComparer.Ordinal),
    };

    private static IpcConnectionSession BridgeSession(params string[] capabilities) => new()
    {
        HandshakeCompleted = true,
        Component = "bridge",
        CallerSid = BridgeSid,
        GrantedCapabilities = new HashSet<string>(capabilities, StringComparer.Ordinal),
    };

    private static RequestEnvelope Request(string method, object? @params = null, string? traceId = null) => new()
    {
        Method = method,
        Params = @params is null ? null
            : JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(@params)),
        TraceId = traceId,
    };

    private static PolicyFile NewPolicy(string id = "p-1", string version = "7.0.1") =>
        new() { PolicyId = id, Version = version };

    [Fact]
    public void PolicyAndClassroomSpecs_MatchMethodRegistry()
    {
        // method_registry.md v1 五要素对齐（policy/classroom 四方法）
        var host = CreateHost();
        var specs = host.Registry.Specs.ToDictionary(s => s.Method, StringComparer.Ordinal);

        foreach (var method in new[] { "policy.apply", "policy.restore", "classroom.begin", "classroom.end" })
        {
            var spec = specs[method];
            Assert.Equal(IpcCallerRole.System, Assert.Single(spec.AllowedRoles));
            Assert.Equal(TimeSpan.FromSeconds(15), spec.Timeout);
            Assert.Equal("full", spec.AuditLevel);
            Assert.NotNull(spec.Handler);
        }

        Assert.Equal("policy.control", specs["policy.apply"].RequiredCapability);
        Assert.Equal("policy.control", specs["policy.restore"].RequiredCapability);
        Assert.Equal("classroom.control", specs["classroom.begin"].RequiredCapability);
        Assert.Equal("classroom.control", specs["classroom.end"].RequiredCapability);
    }

    [Fact]
    public async Task ApplyPolicy_WithoutApplier_ReturnsUnavailable()
    {
        var host = CreateHost();

        var response = await host.DispatchAsync(
            Request("policy.apply", new { policy_json = "{}" }),
            SystemSession("policy.control"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.Unavailable, response.Error!.Code);
    }

    [Fact]
    public async Task ApplyPolicy_MissingPolicyJson_ReturnsInvalidArgument()
    {
        var host = CreateHost();
        host.PolicyApplier = _ => Result<PolicyApplyOutcome>.Success(
            new PolicyApplyOutcome(NewPolicy(), Array.Empty<string>()));

        var response = await host.DispatchAsync(
            Request("policy.apply", new { other = 1 }),
            SystemSession("policy.control"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.InvalidArgument, response.Error!.Code);
    }

    [Fact]
    public async Task ApplyPolicy_Rejected_ReturnsErrorAndHonestTelemetry()
    {
        // 问题复现：验签失败时旧实现遥测 success=false 但无法区分"未保存"；
        // 现语义：saved=false（策略未落盘，当前生效文件不受影响）
        var telemetry = new RecordingTelemetrySink();
        var host = CreateHost(telemetry);
        host.PolicyApplier = _ => Result<PolicyApplyOutcome>.Failure(
            ErrorCode.InvalidConfiguration, "signature verification failed");

        var response = await host.DispatchAsync(
            Request("policy.apply", new { policy_json = "not-signed" }, traceId: "trace-reject"),
            SystemSession("policy.control"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.InvalidArgument, response.Error!.Code);
        Assert.Contains("policy rejected", response.Error.Message, StringComparison.Ordinal);

        var evt = Assert.Single(telemetry.Events)!;
        var props = evt.Properties!;
        Assert.Equal(TelemetryEvents.PolicyResultName, evt.EventName);
        Assert.Equal("trace-reject", evt.TraceId);
        Assert.False((bool)props["success"]!);
        Assert.False((bool)props["saved"]!); // 未保存
        Assert.Contains("signature", Assert.IsType<string>(props["reason"]), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ApplyPolicy_AllExecutorsRefreshed_ReturnsAppliedTrue()
    {
        var telemetry = new RecordingTelemetrySink();
        var host = CreateHost(telemetry);
        host.PolicyApplier = json =>
        {
            Assert.Equal("signed-json", json);
            return Result<PolicyApplyOutcome>.Success(
                new PolicyApplyOutcome(NewPolicy("p-2", "7.0.2"), Array.Empty<string>()));
        };

        var response = await host.DispatchAsync(
            Request("policy.apply", new { policy_json = "signed-json" }, traceId: "trace-ok"),
            SystemSession("policy.control"), CancellationToken.None);

        Assert.True(response.Ok);
        var result = response.Result!.Value;
        Assert.Equal("p-2", result.GetProperty("policy_id").GetString());
        Assert.Equal("7.0.2", result.GetProperty("policy_version").GetString());
        Assert.True(result.GetProperty("saved").GetBoolean());
        Assert.True(result.GetProperty("applied").GetBoolean());
        Assert.Empty(result.GetProperty("apply_errors").EnumerateArray());

        var evt = Assert.Single(telemetry.Events)!;
        var props = evt.Properties!;
        Assert.True((bool)props["success"]!);
        Assert.True((bool)props["saved"]!);
        Assert.Null(props["reason"]);
    }

    [Fact]
    public async Task ApplyPolicy_ExecutorErrors_ReportSavedNotApplied()
    {
        // 问题复现：旧实现仅落盘即恒报 applied=true——执行器（浏览器策略等）
        // 刷新失败被掩盖。现语义：saved=true + applied=false + apply_errors 如实上报
        var telemetry = new RecordingTelemetrySink();
        var host = CreateHost(telemetry);
        host.PolicyApplier = _ => Result<PolicyApplyOutcome>.Success(
            new PolicyApplyOutcome(NewPolicy(), new[] { "browser_policy: registry access denied" }));

        var response = await host.DispatchAsync(
            Request("policy.apply", new { policy_json = "signed-json" }),
            SystemSession("policy.control"), CancellationToken.None);

        // 策略文件已生效：响应仍 ok，仅 applied=false + apply_errors
        Assert.True(response.Ok);
        var result = response.Result!.Value;
        Assert.True(result.GetProperty("saved").GetBoolean());
        Assert.False(result.GetProperty("applied").GetBoolean());
        var errors = result.GetProperty("apply_errors").EnumerateArray()
            .Select(e => e.GetString()).ToArray();
        Assert.Single(errors);
        Assert.Contains("browser_policy", errors[0], StringComparison.Ordinal);

        var evt = Assert.Single(telemetry.Events)!;
        var props = evt.Properties!;
        Assert.False((bool)props["success"]!); // 生效失败（非落盘失败）
        Assert.True((bool)props["saved"]!); // 已保存
        Assert.Contains("browser_policy", Assert.IsType<string>(props["reason"]), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ApplyPolicy_BridgeRoleDenied_EvenWithCapability()
    {
        // policy.apply 仅 system 角色：bridge 即使协商了 policy.control 也拒绝
        var host = CreateHost();
        host.PolicyApplier = _ => Result<PolicyApplyOutcome>.Success(
            new PolicyApplyOutcome(NewPolicy(), Array.Empty<string>()));

        var response = await host.DispatchAsync(
            Request("policy.apply", new { policy_json = "signed-json" }),
            BridgeSession("policy.control"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcSidNotAuthorized, response.Error!.Code);
    }

    [Fact]
    public async Task RestorePolicy_ExecutorErrors_ReportedHonestly()
    {
        var telemetry = new RecordingTelemetrySink();
        var host = CreateHost(telemetry);
        host.PolicyRestorer = () => Result<PolicyApplyOutcome>.Success(
            new PolicyApplyOutcome(NewPolicy("p-backup", "7.0.0"), new[] { "usb_controller: denied" }));

        var response = await host.DispatchAsync(
            Request("policy.restore"),
            SystemSession("policy.control"), CancellationToken.None);

        Assert.True(response.Ok);
        var result = response.Result!.Value;
        Assert.True(result.GetProperty("restored").GetBoolean());
        Assert.True(result.GetProperty("saved").GetBoolean());
        Assert.False(result.GetProperty("applied").GetBoolean());
        Assert.Single(result.GetProperty("apply_errors").EnumerateArray());
    }

    [Fact]
    public async Task RestorePolicy_NoBackup_ReturnsNotFound()
    {
        var host = CreateHost();
        host.PolicyRestorer = () => Result<PolicyApplyOutcome>.Failure(
            ErrorCode.PathNotFound, "no policy backup available.");

        var response = await host.DispatchAsync(
            Request("policy.restore"),
            SystemSession("policy.control"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.NotFound, response.Error!.Code);
    }

    [Fact]
    public async Task Classroom_BeginThenEnd_LifecycleAndTelemetry()
    {
        var telemetry = new RecordingTelemetrySink();
        var host = CreateHost(telemetry);

        var begin = await host.DispatchAsync(
            Request("classroom.begin", new { classroom_id = "cls-42" }),
            SystemSession("classroom.control", "status.read"), CancellationToken.None);
        Assert.True(begin.Ok);
        Assert.True(begin.Result!.Value.GetProperty("active").GetBoolean());
        Assert.Equal("cls-42", begin.Result!.Value.GetProperty("classroom_id").GetString());
        Assert.True(begin.Result!.Value.GetProperty("started_at_unix").GetInt64() > 0);

        // get_status 如实反映课堂进行中
        var status = await host.DispatchAsync(
            Request("system.get_status"),
            SystemSession("status.read"), CancellationToken.None);
        Assert.True(status.Ok);
        Assert.True(status.Result!.Value.GetProperty("classroom_active").GetBoolean());

        var end = await host.DispatchAsync(
            Request("classroom.end"),
            SystemSession("classroom.control", "status.read"), CancellationToken.None);
        Assert.True(end.Ok);
        Assert.False(end.Result!.Value.GetProperty("active").GetBoolean());
        Assert.True(end.Result!.Value.GetProperty("ended_at_unix").GetInt64()
            >= end.Result!.Value.GetProperty("started_at_unix").GetInt64());

        // 结束后状态回落
        var statusAfter = await host.DispatchAsync(
            Request("system.get_status"),
            SystemSession("status.read"), CancellationToken.None);
        Assert.False(statusAfter.Result!.Value.GetProperty("classroom_active").GetBoolean());

        var names = telemetry.Events.Select(e => e.EventName).ToArray();
        Assert.Contains(TelemetryEvents.ClassroomBeginName, names);
        Assert.Contains(TelemetryEvents.ClassroomEndName, names);
    }

    [Fact]
    public async Task Classroom_Begin_BridgeRoleDenied()
    {
        // 课堂控制仅 system 角色：bridge 即使协商了 classroom.control 也拒绝
        var host = CreateHost();

        var response = await host.DispatchAsync(
            Request("classroom.begin", new { classroom_id = "cls-1" }),
            BridgeSession("classroom.control"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcSidNotAuthorized, response.Error!.Code);
    }
}
