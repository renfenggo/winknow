using Winknow.CodeRunner;
using Winknow.CodeRunner.Compilation;

namespace Winknow.CodeRunner.Tests;

/// <summary>
/// 编译链管线集成测试（真实 g++ 编译运行；本机未装 g++ 时用例静默通过）。
/// 覆盖指导书 05 编译链：hello world、stdin、编译诊断、墙钟超时、输出截断、
/// 内存炸弹、工作区清理、校验拒绝。
/// </summary>
public sealed class RunnerPipelineTests
{
    private static readonly Lazy<GppToolchain?> Toolchain = new(GppToolchain.Discover);

    private static RunnerPipeline? TryCreatePipeline()
    {
        var toolchain = Toolchain.Value;
        return toolchain is null ? null
            : new RunnerPipeline(toolchain, Path.Combine(Path.GetTempPath(), "wk-runner-tests"));
    }

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
    public void Toolchain_Discover_FindsGpp()
    {
        var toolchain = Toolchain.Value;
        if (toolchain is null)
        {
            return; // 环境无 g++（CI）；本机开发环境必须安装
        }

        Assert.True(File.Exists(toolchain.CompilerPath), toolchain.CompilerPath);
        Assert.Contains("g++", toolchain.Version, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Pipeline_HelloWorld_Cpp14_RunsOk()
    {
        var pipeline = TryCreatePipeline();
        if (pipeline is null)
        {
            return;
        }

        var result = pipeline.Execute(new RunnerRequest
        {
            RequestId = "t-hello-14",
            Language = RunnerLanguage.Cpp14,
            Source = """
                #include <iostream>
                int main() { std::cout << "hello c++14" << std::endl; return 0; }
                """,
            Limits = DefaultLimits(),
        });

        Assert.Equal(RunnerStatus.RunOk, result.Status);
        Assert.Equal(0, result.CompileExitCode);
        Assert.Equal(0, result.RunExitCode);
        Assert.Contains("hello c++14", result.Stdout, StringComparison.Ordinal);
        Assert.False(result.TimedOut);
        Assert.True(result.ArtifactsCleaned);
    }

    [Fact]
    public void Pipeline_Cpp17_SupportOrReject()
    {
        var pipeline = TryCreatePipeline();
        if (pipeline is null)
        {
            return;
        }

        // 结构化绑定是 C++17 特性：工具链支持（GCC≥5）则编译运行成功；
        // 官方 Dev-Cpp 4.9.2 不支持 -std=c++17，应诚实 REJECTED（含工具链版本说明）
        var result = pipeline.Execute(new RunnerRequest
        {
            RequestId = "t-cpp17",
            Language = RunnerLanguage.Cpp17,
            Source = """
                #include <iostream>
                #include <utility>
                int main() { auto [a, b] = std::make_pair(3, 4); std::cout << a + b; return 0; }
                """,
            Limits = DefaultLimits(),
        });

        if (Toolchain.Value!.Supports(RunnerLanguage.Cpp17))
        {
            Assert.Equal(RunnerStatus.RunOk, result.Status);
            Assert.Equal("7", result.Stdout);
        }
        else
        {
            Assert.Equal(RunnerStatus.Rejected, result.Status);
            Assert.Contains("does not support", result.Stderr, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Pipeline_Stdin_IsDelivered()
    {
        var pipeline = TryCreatePipeline();
        if (pipeline is null)
        {
            return;
        }

        var result = pipeline.Execute(new RunnerRequest
        {
            RequestId = "t-stdin",
            Language = RunnerLanguage.Cpp14,
            Source = """
                #include <iostream>
                int main() { int a, b; std::cin >> a >> b; std::cout << a + b; return 0; }
                """,
            Stdin = "11 22\n",
            Limits = DefaultLimits(),
        });

        Assert.Equal(RunnerStatus.RunOk, result.Status);
        Assert.Equal("33", result.Stdout);
    }

    [Fact]
    public void Pipeline_CompileError_ReturnsDiagnostics()
    {
        var pipeline = TryCreatePipeline();
        if (pipeline is null)
        {
            return;
        }

        var result = pipeline.Execute(new RunnerRequest
        {
            RequestId = "t-cerr",
            Language = RunnerLanguage.Cpp14,
            Source = "int main() { this is not c++ }",
            Limits = DefaultLimits(),
        });

        Assert.Equal(RunnerStatus.CompileFailed, result.Status);
        Assert.NotEqual(0, result.CompileExitCode);
        Assert.NotNull(result.CompileDiagnostics);
        Assert.Contains("error", result.CompileDiagnostics, StringComparison.OrdinalIgnoreCase);
        Assert.True(result.ArtifactsCleaned);
    }

    [Fact]
    public void Pipeline_WallClockTimeout_KillsInfiniteLoop()
    {
        var pipeline = TryCreatePipeline();
        if (pipeline is null)
        {
            return;
        }

        var result = pipeline.Execute(new RunnerRequest
        {
            RequestId = "t-timeout",
            Language = RunnerLanguage.Cpp14,
            Source = "int main() { while (true) {} }",
            Limits = DefaultLimits() with { WallClockMs = 1_000, CpuMs = 60_000 },
        });

        Assert.Equal(RunnerStatus.RunTimeout, result.Status);
        Assert.True(result.TimedOut);
        Assert.Null(result.RunExitCode);
        Assert.True(result.ArtifactsCleaned);
    }

    [Fact]
    public void Pipeline_OutputFlood_IsTruncated()
    {
        var pipeline = TryCreatePipeline();
        if (pipeline is null)
        {
            return;
        }

        var result = pipeline.Execute(new RunnerRequest
        {
            RequestId = "t-flood",
            Language = RunnerLanguage.Cpp14,
            Source = """
                #include <cstdio>
                int main() { for (;;) { std::printf("0123456789"); } }
                """,
            Limits = DefaultLimits() with { WallClockMs = 2_000, OutputBytes = 4_096 },
        });

        // 洪泛输出塞满限额后：读端停止读取 → 管道写阻塞 → 墙钟超时终止
        Assert.True(result.TimedOut, $"flood should hit wall clock, status={result.Status}, err={pipeline.LastInternalError}");
        Assert.True(result.OutputTruncated);
        Assert.True(result.Stdout!.Length <= 4_096, $"stdout {result.Stdout.Length} must stay within limit");
    }

    [Fact]
    public void Pipeline_MemoryBomb_KilledByJobLimit()
    {
        var pipeline = TryCreatePipeline();
        if (pipeline is null)
        {
            return;
        }

        var result = pipeline.Execute(new RunnerRequest
        {
            RequestId = "t-membomb",
            Language = RunnerLanguage.Cpp14,
            Source = """
                #include <cstring>
                int main() {
                    for (;;) {
                        auto p = new char[64 * 1024 * 1024];
                        std::memset(p, 1, 64 * 1024 * 1024);
                    }
                }
                """,
            Limits = DefaultLimits() with { WallClockMs = 10_000, MemoryMb = 32 },
        });

        // Job 内存限额杀进程：不得 RUN_OK；程序不可能自然退出（无限分配）
        Assert.NotEqual(RunnerStatus.RunOk, result.Status);
        Assert.True(result.PeakMemoryKb > 0, "job memory accounting should report usage");
        Assert.True(result.ElapsedMs < 10_000, "memory limit should kill before wall clock");
    }

    [Fact]
    public void Pipeline_Workspace_CleanedAfterRun()
    {
        var pipeline = TryCreatePipeline();
        if (pipeline is null)
        {
            return;
        }

        var result = pipeline.Execute(new RunnerRequest
        {
            RequestId = "t-clean",
            Language = RunnerLanguage.Cpp14,
            Source = "int main() { return 0; }",
            Limits = DefaultLimits(),
        });

        Assert.Equal(RunnerStatus.RunOk, result.Status);
        // artifacts_cleaned 来自 TryCleanup 的真实返回值（目录确实消失才为 true）
        Assert.True(result.ArtifactsCleaned);
    }

    [Fact]
    public void Pipeline_Rejected_InvalidRequest()
    {
        var pipeline = TryCreatePipeline();
        if (pipeline is null)
        {
            return;
        }

        var result = pipeline.Execute(new RunnerRequest
        {
            RequestId = "t-reject",
            Language = RunnerLanguage.Cpp14,
            Source = "int main() { return 0; }",
            Limits = DefaultLimits() with { WallClockMs = 5 }, // 越界：[100, 60000]
        });

        Assert.Equal(RunnerStatus.Rejected, result.Status);
        Assert.NotNull(result.Stderr);
        Assert.True(result.ArtifactsCleaned);
    }

    [Fact]
    public void Pipeline_RunFailure_NonZeroExit()
    {
        var pipeline = TryCreatePipeline();
        if (pipeline is null)
        {
            return;
        }

        var result = pipeline.Execute(new RunnerRequest
        {
            RequestId = "t-runfail",
            Language = RunnerLanguage.Cpp14,
            Source = """
                #include <cstdio>
                int main() { std::fprintf(stderr, "boom"); return 3; }
                """,
            Limits = DefaultLimits(),
        });

        Assert.Equal(RunnerStatus.RunFailed, result.Status);
        Assert.Equal(3, result.RunExitCode);
        Assert.Contains("boom", result.Stderr, StringComparison.Ordinal);
    }
}
