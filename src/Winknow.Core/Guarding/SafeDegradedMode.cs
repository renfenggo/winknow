namespace Winknow.Core.Guarding;

/// <summary>
/// 安全降级模式状态机。
///
/// 用途：V7.0 第 10 周"Safe Degraded Mode——超阈值后保持最低管控"。
/// 满足验收"恢复失败时不自动全部放行"：降级模式的唯一语义是
/// **Fail-Closed**——管控不解除、策略不放宽，仅停止反复拉起崩溃的组件，
/// 由守护进程自身维持最低限度管控并持续告警。
///
/// 状态转移：
/// Normal --(超重启阈值/修复失败)--> Degraded
/// Degraded --(修复成功且窗口冷却)--> Normal
/// </summary>
public sealed class SafeDegradedMode
{
    /// <summary>降级原因。</summary>
    public record DegradedReason(string Component, string Detail, DateTimeOffset At);

    private readonly Func<DateTimeOffset> _clock;
    private readonly TimeSpan _recoveryCooldown;

    /// <summary>是否处于降级模式。</summary>
    public bool IsDegraded { get; private set; }

    /// <summary>进入降级模式的时间。</summary>
    public DateTimeOffset? DegradedSince { get; private set; }

    /// <summary>最近一次降级原因。</summary>
    public DegradedReason? Reason { get; private set; }

    /// <summary>进入降级模式的累计次数（跨恢复周期）。</summary>
    public int TotalDegradedCount { get; private set; }

    /// <summary>
    /// 构造安全降级状态机。
    /// </summary>
    /// <param name="recoveryCooldown">从降级恢复到 Normal 前的最短等待（默认 2 分钟）。</param>
    /// <param name="clock">时间源（测试注入）。</param>
    public SafeDegradedMode(TimeSpan? recoveryCooldown = null, Func<DateTimeOffset>? clock = null)
    {
        _recoveryCooldown = recoveryCooldown ?? TimeSpan.FromMinutes(2);
        _clock = clock ?? (static () => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// 进入降级模式（幂等：重复调用不覆盖首次原因与时间）。
    /// </summary>
    /// <param name="component">崩溃组件名（如 ControlService）。</param>
    /// <param name="detail">降级原因描述。</param>
    public void EnterDegraded(string component, string detail)
    {
        if (IsDegraded) return;
        IsDegraded = true;
        DegradedSince = _clock();
        Reason = new DegradedReason(component, detail, DegradedSince.Value);
        TotalDegradedCount++;
    }

    /// <summary>
    /// 尝试恢复正常模式：冷却期未满返回 false（防止修复后立即又崩溃的抖动循环）。
    /// </summary>
    public bool TryExitDegraded()
    {
        if (!IsDegraded) return true;
        if (_clock() - DegradedSince < _recoveryCooldown) return false;
        IsDegraded = false;
        DegradedSince = null;
        return true;
    }

    /// <summary>
    /// 降级模式下的最低管控策略断言——恒为 true。
    /// 存在的意义是让"恢复失败不自动放行"成为代码里的显式不变量，
    /// 调用方以此决定是否维持进程拦截等最低管控。
    /// </summary>
    public bool ShouldKeepMinimumControl => IsDegraded;
}
