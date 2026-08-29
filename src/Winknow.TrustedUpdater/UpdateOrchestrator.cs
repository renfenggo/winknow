using System.IO;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Winknow.Core.Results;

namespace Winknow.TrustedUpdater;

/// <summary>
/// 更新编排配置（依赖反转：服务停启、迁移、健康检查通过回调注入）。
/// </summary>
public sealed class UpdateOptions
{
    /// <summary>部署根目录（含 Current/Previous/Staging）。</summary>
    public required string DeployRoot { get; init; }

    /// <summary>期望产品标识（防跨产品安装）。</summary>
    public required string ExpectedProductId { get; init; }

    /// <summary>更新包签名公钥（生产应来自 HSM/Token）。</summary>
    public required RSA PublicKey { get; init; }

    /// <summary>审计数据库路径（可选，启用迁移回滚）。</summary>
    public string? AuditDbPath { get; init; }

    /// <summary>数据库快照目录（可选）。</summary>
    public string? SnapshotDir { get; init; }

    /// <summary>停止服务回调（防双进程：旧版本必须先停，避免与新版本同时运行）。</summary>
    public Action? StopServices { get; init; }

    /// <summary>启动服务回调。</summary>
    public Action? StartServices { get; init; }

    /// <summary>数据库迁移逻辑（注入到 DatabaseMigrator.ApplyMigrations）。</summary>
    public Func<Result>? MigrateDatabase { get; init; }

    /// <summary>健康检查：主服务。</summary>
    public Func<Result>? CheckServiceHealth { get; init; }

    /// <summary>健康检查：SessionAgent。</summary>
    public Func<Result>? CheckAgentHealth { get; init; }

    /// <summary>健康检查：策略。</summary>
    public Func<Result>? CheckPolicyHealth { get; init; }

    /// <summary>可选日志记录器。</summary>
    public ILogger? Logger { get; init; }
}

/// <summary>
/// 更新编排器：签名验证 → 版本守卫 → 数据库迁移 → A/B 切换 → 健康检查 → 自动回滚。
///
/// 用途：V7.0 第 7 周"TrustedUpdater"+"自动回滚（更新失败恢复 Previous）"。
///
/// 防双进程：Stop → 切换 → Start，新旧版本不共存（满足验收"更新过程不会触发双进程互相拉起"）。
/// 自动回滚：健康检查失败 → Previous→Current + 数据库回滚 + 重启旧服务
///           （满足验收"更新中断后自动回滚"）。
/// </summary>
public sealed class UpdateOrchestrator
{
    private readonly UpdateOptions _options;

    /// <summary>构造更新编排器。</summary>
    /// <param name="options">编排配置。</param>
    public UpdateOrchestrator(UpdateOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
    }

    /// <summary>
    /// 应用更新包：完整流程，失败时尽量恢复到可用状态。
    /// </summary>
    /// <param name="packagePath">.wku 更新包路径。</param>
    /// <returns>成功或失败结果（失败含回滚说明）。</returns>
    public Result Apply(string packagePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(packagePath);
        var logger = _options.Logger;

        // 1. 停止服务（防双进程：旧版本必须先停，避免与新版本同时运行）
        logger?.LogInformation("Stopping services before update");
        _options.StopServices?.Invoke();

        var slots = new DeploymentSlots(_options.DeployRoot);

        // 2. 解包到 Staging
        var extract = UpdatePackage.Extract(packagePath, slots.StagingDir);
        if (!extract.IsSuccess)
        {
            logger?.LogError("Extract failed: {Error}", extract.ErrorMessage);
            slots.ClearStaging();
            _options.StartServices?.Invoke();
            return extract;
        }

        // 3. 加载清单 + 综合验证（签名+产品+Hash）
        UpdateManifest manifest;
        try
        {
            manifest = UpdatePackage.LoadManifest(slots.StagingDir);
        }
        catch (Exception ex)
        {
            logger?.LogError("Load manifest failed: {Error}", ex.Message);
            slots.ClearStaging();
            _options.StartServices?.Invoke();
            return Result.Failure(ErrorCode.PathNotFound, $"清单加载失败: {ex.Message}");
        }

        var verify = PackageVerifier.VerifyAll(manifest, slots.StagingDir, _options.ExpectedProductId, _options.PublicKey);
        if (!verify.IsSuccess)
        {
            logger?.LogError("Verify failed: {Error}", verify.ErrorMessage);
            slots.ClearStaging();
            _options.StartServices?.Invoke();
            return verify;
        }

        // 4. 版本守卫（防降级 + 兼容性 + 组件一致性）
        var currentVersion = slots.GetCurrentVersion() ?? "0.0.0";
        var upgrade = VersionGuard.CheckUpgrade(currentVersion, manifest);
        if (!upgrade.IsSuccess)
        {
            slots.ClearStaging();
            _options.StartServices?.Invoke();
            return upgrade;
        }

        var compat = VersionGuard.CheckCompatibility(currentVersion, manifest);
        if (!compat.IsSuccess)
        {
            slots.ClearStaging();
            _options.StartServices?.Invoke();
            return compat;
        }

        // 5. 数据库迁移（备份+迁移+失败回滚，由 DatabaseMigrator 保证）
        DatabaseMigrator? migrator = null;
        if (_options.AuditDbPath is not null && _options.SnapshotDir is not null && _options.MigrateDatabase is not null)
        {
            migrator = new DatabaseMigrator(_options.AuditDbPath, _options.SnapshotDir)
            {
                ApplyMigrations = _options.MigrateDatabase
            };
            var migrate = migrator.Migrate();
            if (!migrate.IsSuccess)
            {
                slots.ClearStaging();
                _options.StartServices?.Invoke();
                return migrate;
            }
        }

        // 6. Promote（Staging→Current, 原 Current→Previous）
        var promote = slots.Promote(manifest.Version, manifest.BuildTime);
        if (!promote.IsSuccess)
        {
            logger?.LogError("Promote failed: {Error}", promote.ErrorMessage);
            migrator?.Rollback();
            _options.StartServices?.Invoke();
            return promote;
        }

        // 7. 启动新版本服务（此时旧版本已在 Previous，不存在双进程）
        logger?.LogInformation("Starting updated services (v{Version})", manifest.Version);
        _options.StartServices?.Invoke();

        // 8. 健康检查
        var health = new HealthChecker
        {
            CheckService = _options.CheckServiceHealth,
            CheckAgent = _options.CheckAgentHealth,
            CheckPolicy = _options.CheckPolicyHealth
        }.Check();
        if (!health.IsSuccess)
        {
            // 9. 自动回滚：停新版本 → Previous→Current → 数据库回滚 → 启旧版本
            logger?.LogError("Health check failed, auto-rollback: {Error}", health.ErrorMessage);
            _options.StopServices?.Invoke();
            var rollback = slots.Rollback();
            migrator?.Rollback();
            _options.StartServices?.Invoke();
            return Result.Failure(health.ErrorCode,
                $"健康检查失败已自动回滚: {health.ErrorMessage}" +
                (rollback.IsSuccess ? "" : $"（槽位回滚失败: {rollback.ErrorMessage}）"));
        }

        logger?.LogInformation("Update applied to v{Version}", manifest.Version);
        slots.ClearStaging();
        return Result.Success();
    }

    /// <summary>
    /// 手动回滚到 Previous。
    /// </summary>
    /// <returns>回滚成功或失败结果。</returns>
    public Result Rollback()
    {
        var logger = _options.Logger;
        logger?.LogInformation("Manual rollback initiated");

        _options.StopServices?.Invoke();
        var slots = new DeploymentSlots(_options.DeployRoot);
        var r = slots.Rollback();
        _options.StartServices?.Invoke();

        if (r.IsSuccess)
        {
            logger?.LogInformation("Rollback completed");
        }
        else
        {
            logger?.LogError("Rollback failed: {Error}", r.ErrorMessage);
        }
        return r;
    }

    /// <summary>
    /// 查询当前部署状态（当前版本 + Previous 是否可回滚）。
    /// </summary>
    /// <returns>状态信息。</returns>
    public DeploymentStatus GetStatus()
    {
        var slots = new DeploymentSlots(_options.DeployRoot);
        return new DeploymentStatus(
            slots.GetCurrentVersion(),
            CanRollback: Directory.Exists(slots.PreviousDir)
                && Directory.EnumerateFileSystemEntries(slots.PreviousDir).Any());
    }
}

/// <summary>
/// 部署状态。
/// </summary>
public sealed record DeploymentStatus(string? CurrentVersion, bool CanRollback);
