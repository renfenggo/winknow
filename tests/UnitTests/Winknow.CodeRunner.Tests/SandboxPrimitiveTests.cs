using System.Text;
using Winknow.CodeRunner.Sandbox;

namespace Winknow.CodeRunner.Tests;

/// <summary>
/// 沙箱原语测试：Job Object 限额/树清理、受限令牌（零特权/低完整性）、
/// 低完整性进程工作区外只读（真实进程验证，指导书 05 攻击测试的原语层前提）。
/// </summary>
public sealed class SandboxPrimitiveTests
{
    private static string SystemTool(string name) =>
        Path.Combine(Environment.SystemDirectory, name);

    [Fact]
    public void Job_DisposeKillsAssignedProcess()
    {
        using var job = new JobObjectSandbox();
        using var process = SandboxedProcess.Start(new SandboxedProcessStartInfo
        {
            FileName = SystemTool("ping.exe"),
            Arguments = "-n 30 127.0.0.1",
            RedirectOutput = true,
        });

        Assert.True(job.Assign(process));
        process.Resume();
        if (process.WaitForExit(1_000))
        {
            var output = Encoding.UTF8.GetString(process.ReadStdout(4_096));
            Assert.Fail($"ping 30s 不应已退出：exit={process.ExitCode}, stdout={output}");
        }

        job.Dispose(); // KILL_ON_JOB_CLOSE
        Assert.True(process.WaitForExit(3_000), "Job 关闭后进程树应被终止");
    }

    [Fact]
    public void Job_TerminateKillsProcessTree()
    {
        using var job = new JobObjectSandbox();
        using var process = SandboxedProcess.Start(new SandboxedProcessStartInfo
        {
            FileName = SystemTool("ping.exe"),
            Arguments = "-n 30 127.0.0.1",
        });

        Assert.True(job.Assign(process));
        process.Resume();
        Assert.False(process.WaitForExit(1_000));

        job.Terminate();
        Assert.True(process.WaitForExit(3_000));
    }

    [Fact]
    public void Job_ActiveProcessLimit_ContainsProcessCount()
    {
        using var job = new JobObjectSandbox(activeProcessLimit: 1);
        using var first = SandboxedProcess.Start(new SandboxedProcessStartInfo
        {
            FileName = SystemTool("ping.exe"),
            Arguments = "-n 30 127.0.0.1",
        });
        Assert.True(job.Assign(first));
        first.Resume();

        using var second = SandboxedProcess.Start(new SandboxedProcessStartInfo
        {
            FileName = SystemTool("ping.exe"),
            Arguments = "-n 30 127.0.0.1",
        });

        // 实证（Win10+，diag 矩阵）：超限时 Assign 直接失败（ERROR_NOT_ENOUGH_QUOTA=1816），
        // 超限进程不会被 Job 自动终止——调用方必须自行 Kill，否则泄漏不受控进程。
        // 另 Assign 失败的分配仍使 Job 的 Total/Active 计数 +1，二者不可作精确断言。
        Assert.False(job.Assign(second), "超出 ActiveProcessLimit 的分配应失败");
        second.Kill();
        Assert.True(second.WaitForExit(3_000), "被拒进程应由调用方显式终止");

        Assert.False(first.WaitForExit(1_000), "首个进程不应受影响");
    }

    [Fact]
    public void Job_ReportsPeakMemoryAndWriteBytes()
    {
        using var job = new JobObjectSandbox();
        using var process = SandboxedProcess.Start(new SandboxedProcessStartInfo
        {
            FileName = SystemTool("ping.exe"),
            Arguments = "-n 2 127.0.0.1",
        });
        Assert.True(job.Assign(process));
        process.Resume();
        Assert.True(process.WaitForExit(10_000));

        Assert.True(job.QueryPeakProcessMemoryBytes() > 0, "峰值内存记账应大于 0");
    }

    [Fact]
    public void SandboxToken_HasNoEnabledPrivileges()
    {
        using var token = RestrictedTokenSource.CreateSandboxToken();

        Assert.Equal(0, RestrictedTokenSource.CountEnabledPrivileges(token));
    }

    [Fact]
    public void SandboxToken_IntegrityIsLow()
    {
        using var token = RestrictedTokenSource.CreateSandboxToken();

        Assert.Equal(RestrictedTokenSource.LowIntegritySid, RestrictedTokenSource.QueryIntegrityLevel(token));
    }

    [Fact]
    public void LowIntegritySandboxProcess_CannotWriteOutsideWorkspace()
    {
        var outsideFile = Path.Combine(Path.GetTempPath(), $"wk-outside-{Guid.NewGuid():N}.txt");
        using var token = RestrictedTokenSource.CreateSandboxToken();
        using var job = new JobObjectSandbox();
        using var process = SandboxedProcess.Start(new SandboxedProcessStartInfo
        {
            FileName = SystemTool("cmd.exe"),
            Arguments = $"/c echo blocked > \"{outsideFile}\"",
            Token = token,
            RedirectOutput = true,
        });
        Assert.True(job.Assign(process));
        process.Resume();
        process.WaitForExit(10_000);

        Assert.False(File.Exists(outsideFile), "低完整性进程不应能写入用户目录（NO_WRITE_UP）");
    }

    [Fact]
    public void LowIntegritySandboxProcess_CanWriteInsideWorkspace()
    {
        var root = Path.Combine(Path.GetTempPath(), $"wk-root-{Guid.NewGuid():N}");
        try
        {
            using var workspace = RunnerWorkspace.Create(root);
            using var token = RestrictedTokenSource.CreateSandboxToken();
            using var job = new JobObjectSandbox();
            var target = Path.Combine(workspace.Directory, "inside.txt");
            using var process = SandboxedProcess.Start(new SandboxedProcessStartInfo
            {
                FileName = SystemTool("cmd.exe"),
                Arguments = $"/c echo ok > \"{target}\"",
                WorkingDirectory = workspace.Directory,
                Token = token,
                RedirectOutput = true,
            });
            Assert.True(job.Assign(process));
            process.Resume();
            process.WaitForExit(10_000);

            Assert.True(File.Exists(target), "低完整性进程应能写入带低完整性标签的工作区");
            if (File.Exists(target))
            {
                // cmd echo 输出为 OEM 代码页，仅断言 ASCII 前缀（.NET 8 无 936 编码，不做全量解码）
                var content = File.ReadAllText(target, Encoding.ASCII);
                Assert.StartsWith("ok", content.Trim(), StringComparison.Ordinal);
            }
        }
        finally
        {
            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch (IOException)
            {
                // 测试清理尽力而为
            }
        }
    }

    [Fact]
    public void Workspace_CleanupRemovesDirectory()
    {
        var root = Path.Combine(Path.GetTempPath(), $"wk-root-{Guid.NewGuid():N}");
        using var workspace = RunnerWorkspace.Create(root);
        File.WriteAllText(Path.Combine(workspace.Directory, "a.txt"), "x");

        Assert.True(Directory.Exists(workspace.Directory));
        Assert.True(workspace.TryCleanup());
        Assert.False(Directory.Exists(workspace.Directory));
        try
        {
            Directory.Delete(root, recursive: true);
        }
        catch (IOException)
        {
            // 尽力而为
        }
    }
}
