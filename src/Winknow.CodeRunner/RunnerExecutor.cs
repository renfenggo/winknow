using Winknow.CodeRunner.Compilation;

namespace Winknow.CodeRunner;

/// <summary>
/// CodeRunner 门面（M3-5，Worker 注入给 IPC runner.* handler）：
/// 持有启动期一次探测的工具链与共享执行管线。执行请求串行化——
/// 单管线诊断状态（LastInternalError）非线程安全，且 V1 教学场景
/// 一次只需服务一名学生的执行请求。
/// </summary>
public sealed class RunnerExecutor
{
    private readonly GppToolchain? _toolchain;
    private readonly RunnerPipeline? _pipeline;
    private readonly SemaphoreSlim _executeLock = new(1, 1);

    /// <summary>创建执行器。</summary>
    /// <param name="toolchain">已探测的 g++ 工具链（null 表示环境无编译器）。</param>
    /// <param name="runnerRoot">每请求工作区根目录（ProductPaths.RunnerWork）。</param>
    public RunnerExecutor(GppToolchain? toolchain, string runnerRoot)
    {
        _toolchain = toolchain;
        _pipeline = toolchain is null ? null : new RunnerPipeline(toolchain, runnerRoot);
    }

    /// <summary>工具链是否可用（不可用时 execute 返回 INTERNAL_ERROR 结果）。</summary>
    public bool IsAvailable => _pipeline is not null;

    /// <summary>最近一次内部异常（诊断用；不进契约字段）。</summary>
    public Exception? LastInternalError => _pipeline?.LastInternalError;

    /// <summary>
    /// 能力快照（runner.get_capabilities 后端）：
    /// 工具链版本与 -std= 能力过滤后的语言列表。
    /// </summary>
    public RunnerCapabilities GetCapabilities() => new()
    {
        Available = IsAvailable,
        CompilerPath = _toolchain?.CompilerPath,
        CompilerVersion = _toolchain?.Version,
        Languages = _toolchain is null
            ? Array.Empty<RunnerLanguage>()
            : new[] { RunnerLanguage.Cpp14, RunnerLanguage.Cpp17 }
                .Where(_toolchain.Supports)
                .ToArray(),
    };

    /// <summary>
    /// 执行一次编译运行请求（串行）。取消令牌只影响等待与响应——
    /// 已进入沙箱的执行由 RunnerPipeline 墙钟超时自杀进程树，无泄漏。
    /// </summary>
    /// <param name="request">请求（null/非法也会得到契约 REJECTED 结果）。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    /// <returns>统一 RunnerResult。</returns>
    public async Task<RunnerResult> ExecuteAsync(RunnerRequest? request, CancellationToken cancellationToken)
    {
        if (_pipeline is null)
        {
            return new RunnerResult
            {
                RequestId = request?.RequestId ?? string.Empty,
                Status = RunnerStatus.InternalError,
                ElapsedMs = 0,
                ArtifactsCleaned = true,
                Stderr = "code runner toolchain is not available.",
                TraceId = request?.TraceId,
            };
        }

        await _executeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // 同步管线放到线程池：不阻塞 IPC 分发线程；沙箱内自有墙钟超时兜底
            return await Task.Run(() => _pipeline.Execute(request), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _executeLock.Release();
        }
    }
}
