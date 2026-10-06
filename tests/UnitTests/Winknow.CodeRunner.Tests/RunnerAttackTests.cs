using System.Diagnostics;
using Winknow.CodeRunner;
using Winknow.CodeRunner.Compilation;

namespace Winknow.CodeRunner.Tests;

/// <summary>
/// 攻击测试全集（指导书 05）：子进程风暴、写工作区外、访问用户文件、
/// 访问网络、崩溃、非法 exe 执行、超时残留子进程。
/// while(true)/大内存/stdout 洪泛已在 <see cref="RunnerPipelineTests"/> 覆盖。
/// 与所有会启动 program.exe 的测试类同 Collection 串行执行，
/// 避免残留进程断言被并发用例误报。
/// </summary>
[Collection("code-runner-pipeline")]
public sealed class RunnerAttackTests
{
    private static readonly Lazy<GppToolchain?> Toolchain = new(GppToolchain.Discover);

    private static RunnerPipeline? TryCreatePipeline()
    {
        var toolchain = Toolchain.Value;
        return toolchain is null ? null
            : new RunnerPipeline(toolchain, Path.Combine(Path.GetTempPath(), "wk-runner-tests"));
    }

    private static ResourceLimits AttackLimits() => new()
    {
        WallClockMs = 5_000,
        CpuMs = 4_000,
        MemoryMb = 128,
        ProcessCount = 8,
        OutputBytes = 65_536,
        FileBytes = 1_024,
    };

    [Fact]
    public void Attack_ProcessStorm_CappedByJobLimitAndKilled()
    {
        var pipeline = TryCreatePipeline();
        if (pipeline is null)
        {
            return;
        }

        // 自复制风暴（fork bomb 的 Windows 等价）：每个副本再尝试孵化 30 个副本，
        // Job ActiveProcessLimit=4 封顶进程数；墙钟超时杀全树
        var result = pipeline.Execute(new RunnerRequest
        {
            RequestId = "atk-storm",
            Language = RunnerLanguage.Cpp14,
            Source = """
                #include <windows.h>
                int main() {
                    char self[MAX_PATH];
                    GetModuleFileNameA(nullptr, self, MAX_PATH);
                    for (int i = 0; i < 30; ++i) {
                        STARTUPINFOA si = {}; si.cb = sizeof(si);
                        PROCESS_INFORMATION pi = {};
                        if (!CreateProcessA(self, nullptr, nullptr, nullptr, FALSE, 0,
                                            nullptr, nullptr, &si, &pi)) continue;
                        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                    }
                    for (;;) {}
                }
                """,
            Limits = AttackLimits() with { WallClockMs = 3_000, ProcessCount = 4 },
        });

        Assert.True(result.TimedOut, $"storm should hit wall clock, status={result.Status}");
        Assert.True(result.ArtifactsCleaned);
        AssertNoResidualProgramProcesses();
    }

    [Fact]
    public void Attack_WriteOutsideWorkspace_DeniedByLowIntegrity()
    {
        var pipeline = TryCreatePipeline();
        if (pipeline is null)
        {
            return;
        }

        // 低完整性（No-Write-Up）：写 C:\Windows 需管理员本就拒绝；
        // 写 C:\Users\Public 对普通中等完整性用户进程是允许的——被拒即证明
        // 令牌已降为低完整性（豁免仅覆盖工作区）
        var result = pipeline.Execute(new RunnerRequest
        {
            RequestId = "atk-writeout",
            Language = RunnerLanguage.Cpp14,
            Source = """
                #include <cstdio>
                int main() {
                    FILE* a = std::fopen("C:\\Windows\\wk-attack-marker.txt", "w");
                    int wa = 0; if (a) { std::fputs("x", a); std::fclose(a); wa = 1; }
                    FILE* b = std::fopen("C:\\Users\\Public\\wk-attack-marker.txt", "w");
                    int wb = 0; if (b) { std::fputs("x", b); std::fclose(b); wb = 1; }
                    std::printf("win=%d pub=%d", wa, wb);
                    return 0;
                }
                """,
            Limits = AttackLimits(),
        });

        Assert.Equal(RunnerStatus.RunOk, result.Status);
        Assert.Equal("win=0 pub=0", result.Stdout);
        Assert.False(File.Exists(@"C:\Windows\wk-attack-marker.txt"));
        Assert.False(File.Exists(@"C:\Users\Public\wk-attack-marker.txt"));
    }

    [Fact]
    public void Attack_UserFile_WriteDenied_ReadAllowedByDefaultAcl()
    {
        var pipeline = TryCreatePipeline();
        if (pipeline is null)
        {
            return;
        }

        // 诱饵文件（工作区外，中等完整性）：V1 语义实证——Windows 默认强制标签
        // 策略只挡写（No Write Up），低完整性进程读用户文件仍被允许；
        // 写必须拒绝。防读需后续里程碑收紧（AppContainer/ACL），此处固化现状。
        var baitPath = Path.Combine(Path.GetTempPath(), $"wk-attack-bait-{Guid.NewGuid():N}.txt");
        File.WriteAllText(baitPath, "SECRET");
        try
        {
            var baitLiteral = baitPath.Replace(@"\", @"\\");
            var result = pipeline.Execute(new RunnerRequest
            {
                RequestId = "atk-userfile",
                Language = RunnerLanguage.Cpp14,
                Source = $$"""
                    #include <cstdio>
                    int main() {
                        const char* bait = "{{baitLiteral}}";
                        FILE* f = std::fopen(bait, "rb");
                        int rd = 0, wr = 0;
                        char buf[8] = {};
                        if (f) { rd = (std::fread(buf, 1, 6, f) == 6) ? 1 : 0; std::fclose(f); }
                        FILE* g = std::fopen(bait, "ab");
                        if (g) { wr = 1; std::fclose(g); }
                        std::printf("rd=%d wr=%d", rd, wr);
                        return 0;
                    }
                    """,
                Limits = AttackLimits(),
            });

            Assert.Equal(RunnerStatus.RunOk, result.Status);
            Assert.Equal("rd=1 wr=0", result.Stdout);
            Assert.Equal("SECRET", File.ReadAllText(baitPath)); // 诱饵未被篡改
        }
        finally
        {
            File.Delete(baitPath);
        }
    }

    [Fact]
    public void Attack_NetworkAccess_BoundedRunDocumentsV1Posture()
    {
        var pipeline = TryCreatePipeline();
        if (pipeline is null)
        {
            return;
        }

        // V1 沙箱（受限令牌+Job+低完整性）不做网络隔离：回环 ping 应可达——
        // 学生程序网络暴露面的防线在 Winknow 网络管控层（代理/DNS/白名单），
        // 此用例固化该现状：程序安全完成、不失控、如实报告可达性
        var result = pipeline.Execute(new RunnerRequest
        {
            RequestId = "atk-net",
            Language = RunnerLanguage.Cpp14,
            Source = """
                #include <cstdio>
                #include <cstdlib>
                int main() {
                    int rc = std::system("ping -n 1 -w 1000 127.0.0.1 > nul");
                    std::printf("net=%d", rc);
                    return 0;
                }
                """,
            Limits = AttackLimits(),
        });

        Assert.Equal(RunnerStatus.RunOk, result.Status);
        Assert.StartsWith("net=", result.Stdout, StringComparison.Ordinal);
        Assert.False(result.TimedOut);
    }

    [Fact]
    public void Attack_Crash_NullDeref_ReportedAsRunFailed()
    {
        var pipeline = TryCreatePipeline();
        if (pipeline is null)
        {
            return;
        }

        var result = pipeline.Execute(new RunnerRequest
        {
            RequestId = "atk-crash",
            Language = RunnerLanguage.Cpp14,
            Source = """
                int main() { volatile int* p = nullptr; *p = 1; return 0; }
                """,
            Limits = AttackLimits(),
        });

        // 访问冲突：Windows 异常退出码 0xC0000005（非挂起、非墙钟）
        Assert.Equal(RunnerStatus.RunFailed, result.Status);
        Assert.False(result.TimedOut);
        Assert.Equal(unchecked((int)0xC0000005), result.RunExitCode);
        Assert.True(result.ArtifactsCleaned);
    }

    [Fact]
    public void Attack_IllegalExec_ChildConfinedInJob()
    {
        var pipeline = TryCreatePipeline();
        if (pipeline is null)
        {
            return;
        }

        // 学生代码尝试执行系统解释器（cmd.exe）：子进程随父进程进入同一 Job
        // （无 BREAKAWAY），受同一限额与杀树约束；运行结束即随树清理
        var result = pipeline.Execute(new RunnerRequest
        {
            RequestId = "atk-ilexe",
            Language = RunnerLanguage.Cpp14,
            Source = """
                #include <cstdio>
                #include <cstdlib>
                int main() {
                    int rc = std::system("cmd.exe /c echo child-ok");
                    std::printf("rc=%d", rc);
                    return 0;
                }
                """,
            Limits = AttackLimits(),
        });

        Assert.Equal(RunnerStatus.RunOk, result.Status);
        // 子进程输出先于父进程 printf 到达管道（"child-ok\r\nrc=0"），只断言存在性
        Assert.Contains("child-ok", result.Stdout, StringComparison.Ordinal);
        Assert.Contains("rc=0", result.Stdout, StringComparison.Ordinal);
        Assert.True(result.ArtifactsCleaned);
    }

    [Fact]
    public void Attack_Timeout_ChildResidualsKilledAndWorkspaceCleaned()
    {
        var pipeline = TryCreatePipeline();
        if (pipeline is null)
        {
            return;
        }

        // 父进程孵化一个同样死循环的子副本后挂死：墙钟超时必须杀掉全树
        // （TerminateJobObject），不得残留沙箱进程或工作区文件
        var result = pipeline.Execute(new RunnerRequest
        {
            RequestId = "atk-residual",
            Language = RunnerLanguage.Cpp14,
            Source = """
                #include <windows.h>
                int main() {
                    char self[MAX_PATH];
                    GetModuleFileNameA(nullptr, self, MAX_PATH);
                    STARTUPINFOA si = {}; si.cb = sizeof(si);
                    PROCESS_INFORMATION pi = {};
                    CreateProcessA(self, nullptr, nullptr, nullptr, FALSE, 0,
                                   nullptr, nullptr, &si, &pi);
                    for (;;) {}
                }
                """,
            Limits = AttackLimits() with { WallClockMs = 2_500 },
        });

        Assert.True(result.TimedOut, $"residual scenario should hit wall clock, status={result.Status}");
        Assert.True(result.ArtifactsCleaned);
        AssertNoResidualProgramProcesses();
    }

    /// <summary>断言沙箱产物进程（program.exe）无残留（留短暂句柄释放窗口）。</summary>
    private static void AssertNoResidualProgramProcesses()
    {
        Thread.Sleep(300);
        var residual = Process.GetProcessesByName("program");
        try
        {
            Assert.Empty(residual);
        }
        finally
        {
            foreach (var process in residual)
            {
                process.Dispose();
            }
        }
    }
}
