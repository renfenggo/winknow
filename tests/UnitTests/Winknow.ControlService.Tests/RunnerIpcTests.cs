using System.Text.Json;
using Winknow.CodeRunner;
using Winknow.CodeRunner.Compilation;
using Winknow.ControlService;
using Winknow.Ipc.Commands;
using Winknow.Ipc.Protocol;
using Winknow.Ipc.Session;

namespace Winknow.ControlService.Tests;

/// <summary>
/// M3-5 runner.* IPC 实装测试：ControlCommandHost 直连注册表分发（无管道），
/// 验证 method_registry.md 五要素、参数校验、执行器未绑定降级与真实执行链。
/// 本机无 g++ 时真实执行用例静默通过（环境自适应）。
/// </summary>
public sealed class RunnerIpcTests
{
    private const string SystemSid = "S-1-5-18";
    private const string BridgeSid = "S-1-5-21-3623811015-3361044348-30300820-1013";

    private static readonly Lazy<GppToolchain?> Toolchain = new(GppToolchain.Discover);

    private static ControlCommandHost CreateHost(RunnerExecutor? runner = null)
    {
        var host = new ControlCommandHost(null, "device-test-0001", "test", sid => sid == SystemSid);
        if (runner is not null)
        {
            host.Runner = runner;
        }

        return host;
    }

    private static RunnerExecutor CreateExecutor() =>
        new(Toolchain.Value, Path.Combine(Path.GetTempPath(), "wk-runner-ipc-tests"));

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

    private static RequestEnvelope Request(string method, object? @params = null, string? traceId = null) => new()
    {
        Method = method,
        Params = @params is null ? null
            : JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(@params, RunnerJson.Options)),
        TraceId = traceId,
    };

    private static object HelloWorldRequest(string requestId = "ipc-hello") => new
    {
        request_id = requestId,
        language = "cpp14",
        source = "#include <iostream>\nint main() { std::cout << \"hello ipc\" << std::endl; return 0; }",
        limits = new
        {
            wall_clock_ms = 10_000,
            cpu_ms = 8_000,
            memory_mb = 128,
            process_count = 1,
            output_bytes = 65_536,
            file_bytes = 1_024,
        },
    };

    [Fact]
    public void Registry_RunnerSpecs_MatchMethodRegistry()
    {
        // method_registry.md v1 五要素：get_capabilities（bridge/system + runner.read）、
        // execute（仅 bridge + runner.execute + 90s 编译/墙钟窗口）
        var host = CreateHost();
        var specs = host.Registry.Specs.ToDictionary(s => s.Method, StringComparer.Ordinal);

        var capabilities = specs["runner.get_capabilities"];
        Assert.Equal("runner.read", capabilities.RequiredCapability);
        Assert.Contains(IpcCallerRole.Bridge, capabilities.AllowedRoles);
        Assert.Contains(IpcCallerRole.System, capabilities.AllowedRoles);
        Assert.NotNull(capabilities.Handler);

        var execute = specs["runner.execute"];
        Assert.Equal("runner.execute", execute.RequiredCapability);
        Assert.Equal(IpcCallerRole.Bridge, Assert.Single(execute.AllowedRoles));
        Assert.Equal(TimeSpan.FromSeconds(90), execute.Timeout);
        Assert.NotNull(execute.Handler);
    }

    [Fact]
    public async Task GetCapabilities_WithoutExecutor_ReturnsUnavailable()
    {
        var host = CreateHost();

        var response = await host.DispatchAsync(
            Request("runner.get_capabilities"), CreateSession(capabilities: "runner.read"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.Unavailable, response.Error!.Code);
    }

    [Fact]
    public async Task Execute_WithoutExecutor_ReturnsUnavailable()
    {
        var host = CreateHost();

        var response = await host.DispatchAsync(
            Request("runner.execute", HelloWorldRequest()),
            CreateSession(capabilities: "runner.execute"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.Unavailable, response.Error!.Code);
    }

    [Fact]
    public async Task Execute_MissingParams_ReturnsInvalidArgument()
    {
        var host = CreateHost(CreateExecutor());

        var response = await host.DispatchAsync(
            Request("runner.execute"), CreateSession(capabilities: "runner.execute"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.InvalidArgument, response.Error!.Code);
    }

    [Fact]
    public async Task Execute_MalformedParams_ReturnsInvalidArgument()
    {
        // JSON 可解析但类型错误（language 非枚举）：IPC 参数层拒绝
        var host = CreateHost(CreateExecutor());

        var response = await host.DispatchAsync(
            Request("runner.execute", new
            {
                request_id = "bad-language",
                language = "python3",
                source = "print('hi')",
                limits = new
                {
                    wall_clock_ms = 10_000,
                    cpu_ms = 8_000,
                    memory_mb = 128,
                    process_count = 1,
                    output_bytes = 65_536,
                    file_bytes = 1_024,
                },
            }),
            CreateSession(capabilities: "runner.execute"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.InvalidArgument, response.Error!.Code);
    }

    [Fact]
    public async Task Execute_InvalidLimits_ReturnsRejectedResult()
    {
        // limits 超契约范围（memory_mb=8 < 16）：JSON 合法，由管线校验器拒绝 →
        // ok=true + result.status=REJECTED（RunnerResult 契约的校验失败语义）
        var host = CreateHost(CreateExecutor());

        var response = await host.DispatchAsync(
            Request("runner.execute", new
            {
                request_id = "bad-limits",
                language = "cpp14",
                source = "int main() { return 0; }",
                limits = new
                {
                    wall_clock_ms = 10_000,
                    cpu_ms = 8_000,
                    memory_mb = 8,
                    process_count = 1,
                    output_bytes = 65_536,
                    file_bytes = 1_024,
                },
            }),
            CreateSession(capabilities: "runner.execute"), CancellationToken.None);

        Assert.True(response.Ok);
        var result = response.Result!.Value;
        Assert.Equal("REJECTED", result.GetProperty("status").GetString());
        Assert.Equal("bad-limits", result.GetProperty("request_id").GetString());
    }

    [Fact]
    public async Task Execute_CapabilityNotGranted_ReturnsMismatch()
    {
        // 桥已协商 runner.read 但未协商 runner.execute → IPC_CAPABILITY_MISMATCH
        var host = CreateHost(CreateExecutor());

        var response = await host.DispatchAsync(
            Request("runner.execute", HelloWorldRequest()),
            CreateSession(capabilities: "runner.read"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcCapabilityMismatch, response.Error!.Code);
    }

    [Fact]
    public async Task Execute_SystemRoleNotAllowed_ReturnsSidNotAuthorized()
    {
        // runner.execute 仅 bridge：system 角色（LocalSystem SID）也拒绝
        var host = CreateHost(CreateExecutor());

        var response = await host.DispatchAsync(
            Request("runner.execute", HelloWorldRequest()),
            CreateSession(component: "admin_tool", callerSid: SystemSid, capabilities: "runner.execute"),
            CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcSidNotAuthorized, response.Error!.Code);
        Assert.Equal("role_not_allowed", response.Error.Details!["denied_reason"]);
    }

    [Fact]
    public async Task GetCapabilities_WithToolchain_ReportsContractFields()
    {
        if (Toolchain.Value is null)
        {
            return; // 环境无 g++（CI）
        }

        var host = CreateHost(CreateExecutor());

        var response = await host.DispatchAsync(
            Request("runner.get_capabilities"), CreateSession(capabilities: "runner.read"), CancellationToken.None);

        Assert.True(response.Ok);
        var result = response.Result!.Value;
        Assert.Equal("code_runner", result.GetProperty("component").GetString());
        Assert.True(result.GetProperty("available").GetBoolean());
        Assert.Equal(Toolchain.Value.CompilerPath, result.GetProperty("compiler_path").GetString());
        var languages = result.GetProperty("languages").EnumerateArray()
            .Select(l => l.GetString()).ToArray();
        Assert.Contains("cpp14", languages);
    }

    [Fact]
    public async Task Execute_HelloWorld_ReturnsRunnerResult()
    {
        if (Toolchain.Value is null)
        {
            return; // 环境无 g++（CI）
        }

        var host = CreateHost(CreateExecutor());

        var response = await host.DispatchAsync(
            Request("runner.execute", HelloWorldRequest(), traceId: "trace-ipc-1"),
            CreateSession(capabilities: "runner.execute"), CancellationToken.None);

        Assert.True(response.Ok);
        var result = response.Result!.Value;
        Assert.Equal("ipc-hello", result.GetProperty("request_id").GetString());
        Assert.Equal("RUN_OK", result.GetProperty("status").GetString());
        Assert.Contains("hello ipc", result.GetProperty("stdout").GetString(), StringComparison.Ordinal);
        Assert.True(result.GetProperty("artifacts_cleaned").GetBoolean());
        Assert.Equal("trace-ipc-1", result.GetProperty("trace_id").GetString());
    }

    [Fact]
    public async Task Execute_CompileError_ReturnsCompileFailedResult()
    {
        if (Toolchain.Value is null)
        {
            return; // 环境无 g++（CI）
        }

        var host = CreateHost(CreateExecutor());

        var response = await host.DispatchAsync(
            Request("runner.execute", new
            {
                request_id = "ipc-compile-error",
                language = "cpp14",
                source = "int main() { this is not c++ }",
                limits = new
                {
                    wall_clock_ms = 10_000,
                    cpu_ms = 8_000,
                    memory_mb = 128,
                    process_count = 1,
                    output_bytes = 65_536,
                    file_bytes = 1_024,
                },
            }),
            CreateSession(capabilities: "runner.execute"), CancellationToken.None);

        Assert.True(response.Ok);
        var result = response.Result!.Value;
        Assert.Equal("COMPILE_FAILED", result.GetProperty("status").GetString());
        Assert.NotEqual(0, result.GetProperty("compile_exit_code").GetInt32());
        Assert.False(string.IsNullOrEmpty(result.GetProperty("compile_diagnostics").GetString()));
    }
}
