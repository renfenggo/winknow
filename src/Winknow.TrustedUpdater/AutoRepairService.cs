using Microsoft.Extensions.Logging;
using Winknow.Core.Results;

namespace Winknow.TrustedUpdater;

/// <summary>
/// 自动修复服务（Current 损坏检测与恢复）。
///
/// 用途：V7.0 第 10 周"自动修复——Current 损坏后恢复"。
/// 满足验收"核心文件损坏后自动恢复"与"恢复失败时不自动全部放行"：
///
/// 修复优先级：
/// 1. Recovery Vault 逐文件恢复（保留当前版本，最小改动）；
/// 2. Recovery 不可用/不全 → Previous 槽整目录回滚（DeploymentSlots.Rollback）；
/// 3. 两者都失败 → 返回失败（调用方 GuardService 必须转入 Safe Degraded，
///    保持最低管控，绝不因修复失败而放行）。
///
/// 修复后再校验：恢复动作完成后对 Current 重新 VerifyAgainstManifest，
/// 仍然不健康则按失败处理（防止恢复源本身已损坏）。
/// </summary>
public sealed class AutoRepairService
{
    /// <summary>修复结果。</summary>
    public sealed record RepairResult(
        bool Success,
        RepairStrategy Strategy,
        int RepairedFiles,
        string? Detail = null)
    {
        /// <summary>未做修复（本来就健康）。</summary>
        public static RepairResult AlreadyHealthy() => new(true, RepairStrategy.None, 0, "Current 健康，无需修复");

        /// <summary>修复成功。</summary>
        public static RepairResult Repaired(RepairStrategy s, int n) => new(true, s, n, $"已通过 {s} 恢复 {n} 个文件");

        /// <summary>修复失败——调用方必须进入 Safe Degraded。</summary>
        public static RepairResult Failed(string detail, RepairStrategy attempted) => new(false, attempted, 0, detail);
    }

    /// <summary>修复策略。</summary>
    public enum RepairStrategy
    {
        /// <summary>未修复。</summary>
        None = 0,
        /// <summary>Recovery Vault 逐文件恢复。</summary>
        VaultFileRestore = 1,
        /// <summary>Previous 槽整目录回滚。</summary>
        PreviousRollback = 2
    }

    private readonly DeploymentSlots _slots;
    private readonly RecoveryVault _vault;
    private readonly ILogger? _logger;

    /// <summary>
    /// 构造自动修复服务。
    /// </summary>
    /// <param name="slots">部署槽位（Current/Previous/Staging）。</param>
    /// <param name="vault">可信恢复库。</param>
    /// <param name="logger">可选日志。</param>
    public AutoRepairService(DeploymentSlots slots, RecoveryVault vault, ILogger? logger = null)
    {
        _slots = slots ?? throw new ArgumentNullException(nameof(slots));
        _vault = vault ?? throw new ArgumentNullException(nameof(vault));
        _logger = logger;
    }

    /// <summary>
    /// 检测 Current 健康状况；损坏时按优先级自动修复。
    /// </summary>
    /// <param name="version">用于修复后重建快照的版本号（null 则沿用清单版本）。</param>
    public RepairResult CheckAndRepair(string? version = null)
    {
        var manifest = _vault.GetManifest();

        // 无清单：Recovery 未建立。Current 存在则先建快照（首次部署路径），否则尝试 Previous 回滚
        if (manifest is null || manifest.Files.Count == 0)
        {
            _logger?.LogWarning("Recovery 清单缺失，尝试从 Current 建立首次快照");
            if (Directory.Exists(_slots.CurrentDir) && Directory.EnumerateFiles(_slots.CurrentDir).Any())
            {
                var snapVersion = version ?? _slots.GetCurrentVersion() ?? "unknown";
                var snap = _vault.SnapshotFrom(_slots.CurrentDir, snapVersion);
                return snap.IsSuccess
                    ? RepairResult.AlreadyHealthy()
                    : RepairResult.Failed($"建立首次快照失败: {snap.ErrorMessage}", RepairStrategy.VaultFileRestore);
            }
            return TryRollbackPrevious("Current 为空且无 Recovery 清单");
        }

        var report = _vault.VerifyAgainstManifest(_slots.CurrentDir, manifest);
        if (report.IsHealthy)
        {
            return RepairResult.AlreadyHealthy();
        }

        _logger?.LogWarning(
            "检测到 Current 损坏：{Corrupted} 个篡改，{Missing} 个缺失",
            report.Corrupted.Count, report.Missing.Count);

        // 策略 1：Recovery Vault 逐文件恢复
        if (_vault.IsReady())
        {
            var targets = report.Corrupted.Select(c => c.Path)
                .Concat(report.Missing)
                .ToList();

            var repaired = 0;
            foreach (var rel in targets)
            {
                var r = _vault.RestoreFile(rel, _slots.CurrentDir);
                if (r.IsSuccess) repaired++;
                else _logger?.LogError("Vault 恢复失败 {Path}: {Error}", rel, r.ErrorMessage);
            }

            if (repaired == targets.Count)
            {
                // 修复后复验：确认恢复源本身未被污染
                var reverify = _vault.VerifyAgainstManifest(_slots.CurrentDir);
                if (reverify.IsHealthy)
                {
                    return RepairResult.Repaired(RepairStrategy.VaultFileRestore, repaired);
                }
                _logger?.LogError("Vault 恢复后复验仍不健康，转入 Previous 回滚");
            }
        }
        else
        {
            _logger?.LogWarning("Recovery 库未就绪，转入 Previous 回滚");
        }

        // 策略 2：Previous 槽整目录回滚
        return TryRollbackPrevious("Vault 恢复不完整或未就绪");
    }

    /// <summary>
    /// 建立新快照（部署成功后或首次安装时调用）。
    /// </summary>
    public Result RefreshSnapshot(string? version = null)
    {
        var v = version ?? _slots.GetCurrentVersion() ?? "unknown";
        var r = _vault.SnapshotFrom(_slots.CurrentDir, v);
        if (r.IsSuccess) _logger?.LogInformation("Recovery 快照已刷新：版本 {Version}", v);
        return r;
    }

    private RepairResult TryRollbackPrevious(string reason)
    {
        var rollback = _slots.Rollback();
        if (rollback.IsSuccess)
        {
            // 回滚成功后刷新快照，让 Recovery 与新 Current 对齐
            var v = _slots.GetCurrentVersion() ?? "unknown";
            _ = _vault.SnapshotFrom(_slots.CurrentDir, v);
            return RepairResult.Repaired(RepairStrategy.PreviousRollback, 1);
        }

        // 全部手段失败：返回失败，调用方必须保持降级（不自动放行）
        var detail = $"修复全部失败（{reason}；Previous 回滚失败: {rollback.ErrorMessage}）——保持降级，不放行";
        _logger?.LogCritical("{Detail}", detail);
        return RepairResult.Failed(detail, RepairStrategy.PreviousRollback);
    }
}
