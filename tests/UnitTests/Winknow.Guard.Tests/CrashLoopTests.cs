using Winknow.Core;
using Winknow.Core.Guarding;

namespace Winknow.Guard.Tests;

/// <summary>
/// 第 10 周崩溃循环测试：模拟 ControlService 连续 20 次异常退出，
/// 按计划书验收"不出现重启风暴 / 恢复失败不自动放行"驱动守护决策模型。
///
/// 模型与 GuardService.Worker.MonitorOnceAsync 的决策链一致：
/// 租约死亡 → 限流检查 → 退避到点 → （生产此处还有对端验证）→ 拉起 → 计入窗口。
/// 崩溃语义：每次拉起成功后服务立即死亡（租约永不过期假活），
/// 即 restartAttempts 全部计入限流窗口。
/// </summary>
public sealed class CrashLoopTests
{
    /// <summary>单次崩溃循环的守护决策模拟。</summary>
    private sealed class GuardModel
    {
        private DateTimeOffset _now;
        public RestartThrottle Throttle { get; }
        public ExponentialBackoff Backoff { get; }
        public SafeDegradedMode Degraded { get; }
        public int ActualRestarts { get; private set; }
        public DateTimeOffset NextAttemptAt { get; private set; } = DateTimeOffset.MinValue;

        public GuardModel(DateTimeOffset start)
        {
            _now = start;
            Throttle = new RestartThrottle(
                window: TimeSpan.FromMinutes(Constants.Guard.ThrottleWindowMinutes),
                maxRestarts: Constants.Guard.MaxRestartsPerWindow,
                clock: () => _now);
            Backoff = new ExponentialBackoff();
            Degraded = new SafeDegradedMode(clock: () => _now);
        }

        /// <summary>推进守护内部时钟（限流窗口/冷却期判定使用）。</summary>
        public void Advance(DateTimeOffset now) => _now = now;

        /// <summary>一轮决策：返回是否执行了拉起。</summary>
        public bool Decide(DateTimeOffset now)
        {
            _now = now;
            if (Degraded.IsDegraded) return false;          // 降级：不再拉起（保持最低管控）
            if (!Throttle.CanRestart())
            {
                Degraded.EnterDegraded("ControlService", "重启超阈值");
                return false;
            }
            if (now < NextAttemptAt) return false;          // 退避未到点

            NextAttemptAt = now + Backoff.NextDelay();
            Backoff.OnFailure();
            ActualRestarts++;                               // 拉起（随即又崩溃）
            Throttle.RecordRestart();
            return true;
        }
    }

    [Fact]
    public void CrashLoop_20ConsecutiveExits_NoRestartStorm()
    {
        var now = DateTimeOffset.Parse("2026-01-01T10:00:00Z");
        var model = new GuardModel(now);

        var restartExecuted = 0;
        for (var i = 0; i < Constants.Guard.CrashLoopTestIterations; i++)
        {
            // 每轮循环 5 秒（守护检查周期），立即崩溃的服务下一轮即再次决策
            now = now.AddSeconds(Constants.Guard.HeartbeatIntervalSeconds);
            if (model.Decide(now)) restartExecuted++;
        }

        // 验收①：不出现重启风暴——20 次异常退出只允许 5 次真实拉起（窗口阈值）
        Assert.Equal(Constants.Guard.MaxRestartsPerWindow, restartExecuted);
        Assert.Equal(5, model.ActualRestarts);

        // 20 次循环后必然进入降级
        Assert.True(model.Degraded.IsDegraded);
    }

    [Fact]
    public void CrashLoop_BackoffSpacing_IncreasesExponentially()
    {
        var now = DateTimeOffset.Parse("2026-01-01T10:00:00Z");
        var model = new GuardModel(now);

        // 每轮前进 100s（远超任何退避间隔），连续 4 次拉起；
        // NextAttemptAt - now 即本轮退避设置的下次最早尝试间隔
        var gaps = new List<int>();
        for (var i = 0; i < 4; i++)
        {
            now = now.AddSeconds(100);
            Assert.True(model.Decide(now));
            gaps.Add((int)(model.NextAttemptAt - now).TotalSeconds);
        }

        // 间隔序列 1→2→4→8：崩溃越频繁，拉起越克制
        Assert.Equal(new[] { 1, 2, 4, 8 }, gaps);
    }

    [Fact]
    public void CrashLoop_Degraded_RepairFailureKeepsMinimumControl()
    {
        // 验收②"恢复失败时不自动全部放行"：
        // 降级 + 修复失败 ⇒ ShouldKeepMinimumControl 持续为 true（Fail-Closed）
        var now = DateTimeOffset.Parse("2026-01-01T10:00:00Z");
        var model = new GuardModel(now);

        for (var i = 0; i < 12; i++)
        {
            now = now.AddSeconds(5);
            model.Decide(now);
        }

        Assert.True(model.Degraded.IsDegraded);

        // AutoRepairService.CheckAndRepair 返回 Failed 时不退出降级：
        // ShouldKeepMinimumControl 恒为 true（Fail-Closed，绝不放行）
        Assert.True(model.Degraded.ShouldKeepMinimumControl);

        // 后续 20 轮决策不再产生任何拉起（风暴终止）
        var restartsBefore = model.ActualRestarts;
        for (var i = 0; i < 20; i++)
        {
            now = now.AddSeconds(5);
            model.Decide(now);
        }
        Assert.Equal(restartsBefore, model.ActualRestarts);
    }

    [Fact]
    public void CrashLoop_RecoveryAfterCooldown_AllowsSupervisedRestart()
    {
        // 完整生命周期：崩溃 → 降级 → 修复成功 → 窗口冷却 → 退出降级 → 恢复拉起
        var now = DateTimeOffset.Parse("2026-01-01T10:00:00Z");
        var model = new GuardModel(now);

        for (var i = 0; i < 12; i++)
        {
            now = now.AddSeconds(5);
            model.Decide(now);
        }
        Assert.True(model.Degraded.IsDegraded);

        // 时间前进 11 分钟：限流窗口滑出 + 降级冷却期满（2 分钟）
        now = now.AddMinutes(11);
        model.Advance(now);
        Assert.True(model.Throttle.WindowElapsed());
        Assert.True(model.Degraded.TryExitDegraded());
        model.Throttle.Clear();

        // 修复成功后服务拉起并保持存活：允许再次重启
        Assert.True(model.Decide(now));
        Assert.Equal(6, model.ActualRestarts); // 恢复监督能力，但计数从零开始的新窗口
    }
}
