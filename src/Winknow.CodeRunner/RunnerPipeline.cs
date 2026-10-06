using System.Diagnostics;
using System.Text;
using Winknow.CodeRunner.Compilation;
using Winknow.CodeRunner.Sandbox;
using Winknow.Core.Results;

namespace Winknow.CodeRunner;

/// <summary>
/// 编译执行管线（指导书 05 编译链）：
/// source → validate → temp workdir → compile（g++ 亦受 Job 管控）→ capture diagnostics →
/// run（受限令牌 + Job 限额 + 墙钟超时杀树）→ capture stdout/stderr（限额截断）→ cleanup。
/// </summary>
public sealed class RunnerPipeline
{
    /// <summary>编译诊断上限（字节，契约 compile_diagnostics ≤ 64KB）。</summary>
    public const int MaxCompileDiagnosticsBytes = 65_536;

    private const int CompileTimeoutMs = 30_000;
    private const int CompileProcessLimit = 8; // g++ driver + cc1plus + as + collect2 + ld
    private const int CompileMemoryMb = 1_024;
    private static readonly TimeSpan CompileCpuLimit = TimeSpan.FromSeconds(20);

    private readonly GppToolchain _toolchain;
    private readonly string _runnerRoot;

    /// <summary>最近一次 INTERNAL_ERROR 的异常（诊断用；不进契约字段）。</summary>
    public Exception? LastInternalError { get; private set; }

    /// <summary>创建管线。</summary>
    /// <param name="toolchain">已探测的 g++ 编译链。</param>
    /// <param name="runnerRoot">每请求工作区根目录（ProductPaths.RunnerWork）。</param>
    public RunnerPipeline(GppToolchain toolchain, string runnerRoot)
    {
        ArgumentNullException.ThrowIfNull(toolchain);
        ArgumentException.ThrowIfNullOrWhiteSpace(runnerRoot);
        _toolchain = toolchain;
        _runnerRoot = runnerRoot;
    }

    /// <summary>执行一次编译运行请求（全流程；任何阶段失败都会清理工作区）。</summary>
    /// <param name="request">请求（含源码与限额）。</param>
    /// <returns>统一 RunnerResult（契约必填字段始终输出）。</returns>
    public RunnerResult Execute(RunnerRequest? request)
    {
        var stopwatch = Stopwatch.StartNew();
        var requestId = request?.RequestId ?? string.Empty;
        var traceId = request?.TraceId;

        var validation = RunnerRequestValidator.Validate(request);
        if (!validation.IsSuccess)
        {
            return new RunnerResult
            {
                RequestId = requestId,
                Status = RunnerStatus.Rejected,
                ElapsedMs = stopwatch.ElapsedMilliseconds,
                ArtifactsCleaned = true,
                Stderr = validation.ErrorMessage,
                TraceId = traceId,
            };
        }

        var validated = validation.Data!;
        if (!_toolchain.Supports(validated.Language))
        {
            // 工具链能力预检（官方 Dev-Cpp 4.9.2 无 -std=c++17）：诚实拒绝而非让 g++ 报 unrecognized
            return new RunnerResult
            {
                RequestId = requestId,
                Status = RunnerStatus.Rejected,
                ElapsedMs = stopwatch.ElapsedMilliseconds,
                ArtifactsCleaned = true,
                Stderr = $"toolchain does not support {validated.Language}: g++ {_toolchain.Version}.",
                TraceId = traceId,
            };
        }

        try
        {
            using var workspace = RunnerWorkspace.Create(_runnerRoot);
            var sourcePath = Path.Combine(workspace.Directory, "main.cpp");
            var outputPath = Path.Combine(workspace.Directory, "program.exe");
            File.WriteAllText(sourcePath, validated.Source, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

            var compile = Compile(validated.Language, sourcePath, outputPath, workspace.Directory);
            if (compile.ExitCode != 0)
            {
                return new RunnerResult
                {
                    RequestId = requestId,
                    Status = RunnerStatus.CompileFailed,
                    CompileExitCode = compile.ExitCode,
                    CompileDiagnostics = TruncateToUtf8(compile.Output, MaxCompileDiagnosticsBytes, out _),
                    ElapsedMs = stopwatch.ElapsedMilliseconds,
                    ArtifactsCleaned = workspace.TryCleanup(),
                    TraceId = traceId,
                };
            }

            return Run(validated, outputPath, workspace, stopwatch);
        }
        catch (Exception ex)
        {
            // 内部异常细节不进契约字段（不外泄）；记录供宿主日志与测试诊断
            LastInternalError = ex;
            System.Diagnostics.Debug.WriteLine($"[RunnerPipeline] internal error: {ex}");
            return new RunnerResult
            {
                RequestId = requestId,
                Status = RunnerStatus.InternalError,
                CompileExitCode = null,
                ElapsedMs = stopwatch.ElapsedMilliseconds,
                // 内部错误细节不外泄（审计走日志），契约层只报状态
                Stderr = "runner internal error.",
                TraceId = traceId,
            };
        }
    }

    private (int ExitCode, byte[] Output) Compile(
        RunnerLanguage language, string sourcePath, string outputPath, string workingDirectory)
    {
        // 编译器是可信工具链（非受限令牌），但仍入 Job：防失控 + 进程树清理
        using var job = new JobObjectSandbox(
            activeProcessLimit: CompileProcessLimit,
            processMemoryLimitBytes: (long)CompileMemoryMb * 1024 * 1024,
            perProcessCpuTime: CompileCpuLimit);
        using var process = SandboxedProcess.Start(new SandboxedProcessStartInfo
        {
            FileName = _toolchain.CompilerPath,
            Arguments = _toolchain.BuildArguments(language, sourcePath, outputPath),
            WorkingDirectory = workingDirectory,
            RedirectOutput = true,
        });

        if (!job.Assign(process))
        {
            process.Kill();
            return (-1, Encoding.UTF8.GetBytes("compilation rejected: job process limit exceeded."));
        }

        process.Resume();
        if (!process.WaitForExit(CompileTimeoutMs))
        {
            job.Terminate();
            process.WaitForExit(3_000);
            return (-1, Encoding.UTF8.GetBytes("compilation timed out."));
        }

        // 诊断 = stdout+stderr 合并（g++ 诊断主要走 stderr）
        var stdout = process.ReadStdout(MaxCompileDiagnosticsBytes);
        var stderr = process.ReadStderr(Math.Max(0, MaxCompileDiagnosticsBytes - stdout.Length));
        var output = new byte[stdout.Length + stderr.Length];
        Buffer.BlockCopy(stderr, 0, output, 0, stderr.Length);
        Buffer.BlockCopy(stdout, 0, output, stderr.Length, stdout.Length);
        return (process.ExitCode, output);
    }

    private RunnerResult Run(
        RunnerRequest request, string programPath, RunnerWorkspace workspace, Stopwatch stopwatch)
    {
        using var token = RestrictedTokenSource.CreateSandboxToken();
        using var job = new JobObjectSandbox(
            activeProcessLimit: request.Limits.ProcessCount,
            processMemoryLimitBytes: (long)request.Limits.MemoryMb * 1024 * 1024,
            perProcessCpuTime: TimeSpan.FromMilliseconds(request.Limits.CpuMs));
        using var process = SandboxedProcess.Start(new SandboxedProcessStartInfo
        {
            FileName = programPath,
            Arguments = string.Empty,
            WorkingDirectory = workspace.Directory,
            Token = token,
            RedirectOutput = true,
            ProvideStdin = request.Stdin is not null,
        });

        if (!job.Assign(process))
        {
            // 超限分配：进程不受 Job 管控，必须显式终止（M3-3 实证）
            process.Kill();
            return new RunnerResult
            {
                RequestId = request.RequestId,
                Status = RunnerStatus.ResourceLimit,
                CompileExitCode = 0,
                ElapsedMs = stopwatch.ElapsedMilliseconds,
                Stderr = "process count limit rejected the run.",
                ArtifactsCleaned = workspace.TryCleanup(),
                TraceId = request.TraceId,
            };
        }

        process.Resume();
        if (request.Stdin is not null)
        {
            process.WriteStdinAndClose(Encoding.UTF8.GetBytes(request.Stdin));
        }

        // 边跑边读：洪泛输出不得靠塞满管道把学生程序卡到墙钟超时；
        // ReadFile 阻塞至 EOF（进程树退出后写端关闭）或读满上限
        var stdoutTask = Task.Run(() => process.ReadStdout(request.Limits.OutputBytes));
        var stderrTask = Task.Run(() => process.ReadStderr(request.Limits.OutputBytes));

        var timedOut = !process.WaitForExit(request.Limits.WallClockMs);
        if (timedOut)
        {
            job.Terminate(); // 进程树清理（含残留子进程）
            process.WaitForExit(3_000);
        }

        var stdoutBytes = stdoutTask.Result;
        var stderrBytes = stderrTask.Result;

        // stdout+stderr 合计不超 OutputBytes（契约语义）：读满上限即视为截断（>=：
        // 恰好压线读满是"还有未读数据"的证据，宁可保守标记；OutputBytes 下限 1024，
        // 空输出不会误报）
        var truncated = stdoutBytes.Length + stderrBytes.Length >= request.Limits.OutputBytes;
        if (stdoutBytes.Length + stderrBytes.Length > request.Limits.OutputBytes)
        {
            var stderrBudget = Math.Max(0, request.Limits.OutputBytes - stdoutBytes.Length);
            if (stderrBytes.Length > stderrBudget)
            {
                Array.Resize(ref stderrBytes, stderrBudget);
            }
        }

        var status = timedOut ? RunnerStatus.RunTimeout
            : process.ExitCode == 0 ? RunnerStatus.RunOk
            : RunnerStatus.RunFailed;

        // 文件写入事后审计（Job 无 file-bytes 限额，超限标记 RESOURCE_LIMIT）
        if (!timedOut && status == RunnerStatus.RunOk &&
            job.QueryWriteTransferBytes() > (ulong)request.Limits.FileBytes)
        {
            status = RunnerStatus.ResourceLimit;
        }

        return new RunnerResult
        {
            RequestId = request.RequestId,
            Status = status,
            CompileExitCode = 0,
            RunExitCode = timedOut ? null : process.ExitCode,
            Stdout = TruncateToUtf8(stdoutBytes, request.Limits.OutputBytes, out _),
            Stderr = TruncateToUtf8(stderrBytes, request.Limits.OutputBytes, out _),
            ElapsedMs = stopwatch.ElapsedMilliseconds,
            PeakMemoryKb = job.QueryPeakProcessMemoryBytes() / 1024,
            TimedOut = timedOut,
            OutputTruncated = truncated,
            ArtifactsCleaned = workspace.TryCleanup(),
            TraceId = request.TraceId,
        };
    }

    private static string TruncateToUtf8(byte[] bytes, int maxBytes, out bool truncated)
    {
        truncated = bytes.Length > maxBytes;
        return Encoding.UTF8.GetString(bytes, 0, Math.Min(bytes.Length, maxBytes));
    }
}
