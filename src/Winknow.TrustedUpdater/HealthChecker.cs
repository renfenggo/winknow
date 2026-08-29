using Winknow.Core.Results;

namespace Winknow.TrustedUpdater;

/// <summary>
/// 更新后健康检查（Service / Agent / 策略）。
///
/// 用途：V7.0 第 7 周"健康检查：更新后确认 Service、Agent、策略"。
/// 满足验收"更新中断后自动回滚"：健康检查失败触发 UpdateOrchestrator 自动回滚。
///
/// 设计：三项检查通过回调注入（依赖反转），Orchestrator 注入实际检查逻辑。
/// 任一失败立即返回失败，Orchestrator 据此回滚。
/// </summary>
public sealed class HealthChecker
{
    /// <summary>检查主服务是否正常运行（由调用方注入）。</summary>
    public Func<Result>? CheckService { get; init; }

    /// <summary>检查 SessionAgent 是否连通（由调用方注入）。</summary>
    public Func<Result>? CheckAgent { get; init; }

    /// <summary>检查策略是否可加载且有效（由调用方注入）。</summary>
    public Func<Result>? CheckPolicy { get; init; }

    /// <summary>
    /// 执行全部健康检查，任一失败立即返回。
    /// </summary>
    /// <returns>全部通过返回成功，否则返回首个失败。</returns>
    public Result Check()
    {
        if (CheckService is not null)
        {
            var r = CheckService();
            if (!r.IsSuccess)
            {
                return Result.Failure(r.ErrorCode, $"Service 健康检查失败: {r.ErrorMessage}");
            }
        }

        if (CheckAgent is not null)
        {
            var r = CheckAgent();
            if (!r.IsSuccess)
            {
                return Result.Failure(r.ErrorCode, $"Agent 健康检查失败: {r.ErrorMessage}");
            }
        }

        if (CheckPolicy is not null)
        {
            var r = CheckPolicy();
            if (!r.IsSuccess)
            {
                return Result.Failure(r.ErrorCode, $"策略健康检查失败: {r.ErrorMessage}");
            }
        }

        return Result.Success();
    }
}
