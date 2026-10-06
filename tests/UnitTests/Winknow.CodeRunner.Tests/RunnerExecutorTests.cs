using System.Text.Json;
using Winknow.CodeRunner;
using Winknow.CodeRunner.Compilation;

namespace Winknow.CodeRunner.Tests;

/// <summary>
/// M3-5 RunnerExecutor 门面测试：能力快照（无工具链/有工具链）、
/// 串行执行、工具链缺失降级 INTERNAL_ERROR、契约序列化（snake_case）。
/// 本机无 g++ 时真实执行用例静默通过（环境自适应）。
/// 与其它启动 program.exe 的测试类同 Collection 串行（残留进程断言防误报）。
/// </summary>
[Collection("code-runner-pipeline")]
public sealed class RunnerExecutorTests
{
    private static readonly Lazy<GppToolchain?> Toolchain = new(GppToolchain.Discover);

    private static RunnerExecutor CreateExecutor() =>
        new(Toolchain.Value, Path.Combine(Path.GetTempPath(), "wk-executor-tests"));

    private static RunnerExecutor CreateUnavailableExecutor() =>
        new(toolchain: null, Path.Combine(Path.GetTempPath(), "wk-executor-tests"));

    private static ResourceLimits DefaultLimits() => new()
    {
        WallClockMs = 10_000,
        CpuMs = 8_000,
        MemoryMb = 128,
        ProcessCount = 1,
        OutputBytes = 65_536,
        FileBytes = 1_024,
    };

    [Fact]
    public void Capabilities_NoToolchain_ReportsUnavailable()
    {
        var executor = CreateUnavailableExecutor();

        Assert.False(executor.IsAvailable);
        var capabilities = executor.GetCapabilities();
        Assert.False(capabilities.Available);
        Assert.Null(capabilities.CompilerPath);
        Assert.Null(capabilities.CompilerVersion);
        Assert.Empty(capabilities.Languages);
    }

    [Fact]
    public void Capabilities_NoToolchain_SerializesContractFields()
    {
        var executor = CreateUnavailableExecutor();

        var json = JsonSerializer.Serialize(executor.GetCapabilities(), RunnerJson.Options);

        Assert.Contains("\"component\":\"code_runner\"", json, StringComparison.Ordinal);
        Assert.Contains("\"available\":false", json, StringComparison.Ordinal);
        Assert.Contains("\"languages\":[]", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Execute_NoToolchain_ReturnsInternalError()
    {
        var executor = CreateUnavailableExecutor();

        var result = await executor.ExecuteAsync(new RunnerRequest
        {
            RequestId = "no-tc",
            Language = RunnerLanguage.Cpp14,
            Source = "int main() { return 0; }",
            Limits = DefaultLimits(),
        }, CancellationToken.None);

        Assert.Equal(RunnerStatus.InternalError, result.Status);
        Assert.Equal("no-tc", result.RequestId);
        Assert.True(result.ArtifactsCleaned);
    }

    [Fact]
    public async Task Execute_InvalidRequest_ReturnsRejected()
    {
        // null 请求 → 管线校验器 REJECTED（与直连管线语义一致）
        var executor = CreateExecutor();
        if (!executor.IsAvailable)
        {
            return; // 环境无 g++（CI）
        }

        var result = await executor.ExecuteAsync(null, CancellationToken.None);

        Assert.Equal(RunnerStatus.Rejected, result.Status);
    }

    [Fact]
    public void Capabilities_WithToolchain_ReportsLanguages()
    {
        if (Toolchain.Value is null)
        {
            return; // 环境无 g++（CI）
        }

        var executor = CreateExecutor();
        var capabilities = executor.GetCapabilities();

        Assert.True(capabilities.Available);
        Assert.Equal(Toolchain.Value.CompilerPath, capabilities.CompilerPath);
        Assert.Equal(Toolchain.Value.Version, capabilities.CompilerVersion);
        Assert.Contains(RunnerLanguage.Cpp14, capabilities.Languages);
        // cpp17 仅在工具链支持时报（官方 Dev-Cpp 4.9.2 不支持）
        Assert.Equal(Toolchain.Value.Supports(RunnerLanguage.Cpp17),
            capabilities.Languages.Contains(RunnerLanguage.Cpp17));
    }

    [Fact]
    public async Task Execute_HelloWorld_ReturnsRunOk()
    {
        var executor = CreateExecutor();
        if (!executor.IsAvailable)
        {
            return; // 环境无 g++（CI）
        }

        var result = await executor.ExecuteAsync(new RunnerRequest
        {
            RequestId = "exec-hello",
            Language = RunnerLanguage.Cpp14,
            Source = """
                #include <iostream>
                int main() { std::cout << "via executor" << std::endl; return 0; }
                """,
            Limits = DefaultLimits(),
        }, CancellationToken.None);

        Assert.Equal(RunnerStatus.RunOk, result.Status);
        Assert.Contains("via executor", result.Stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Execute_ConcurrentRequests_AreSerialized()
    {
        var executor = CreateExecutor();
        if (!executor.IsAvailable)
        {
            return; // 环境无 g++（CI）
        }

        // 两个并发请求都要完整跑完（串行执行无交错半成品结果）
        var tasks = Enumerable.Range(0, 2).Select(i => executor.ExecuteAsync(new RunnerRequest
        {
            RequestId = $"serial-{i}",
            Language = RunnerLanguage.Cpp14,
            Source = "#include <iostream>\nint main() { std::cout << \"ok\"; return 0; }",
            Limits = DefaultLimits(),
        }, CancellationToken.None)).ToArray();

        var results = await Task.WhenAll(tasks);

        foreach (var result in results)
        {
            Assert.Equal(RunnerStatus.RunOk, result.Status);
            Assert.Equal("ok", result.Stdout);
        }
    }
}
