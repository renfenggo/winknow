using System.IO;
using Winknow.Core.Results;
using Winknow.TrustedUpdater;

namespace Winknow.TrustedUpdater.Tests;

/// <summary>
/// 第 7 周"健康检查 + 数据库迁移"测试。
/// 覆盖验收项：
/// - "健康检查：更新后确认 Service、Agent、策略"
/// - "数据库迁移失败可回滚"（Migrate 失败自动 Restore）
/// </summary>
public class HealthAndMigratorTests : IDisposable
{
    private readonly string _workDir = Path.Combine(Path.GetTempPath(), $"wk7_hm_{Guid.NewGuid():N}");

    public HealthAndMigratorTests() => Directory.CreateDirectory(_workDir);
    public void Dispose() => Directory.Delete(_workDir, true);

    [Fact]
    public void HealthChecker_NoCallbacks_Succeeds()
    {
        var r = new HealthChecker().Check();
        Assert.True(r.IsSuccess);
    }

    [Fact]
    public void HealthChecker_AllPass_Succeeds()
    {
        var r = new HealthChecker
        {
            CheckService = () => Result.Success(),
            CheckAgent = () => Result.Success(),
            CheckPolicy = () => Result.Success()
        }.Check();
        Assert.True(r.IsSuccess);
    }

    [Fact]
    public void HealthChecker_ServiceFails_StopsAndReturns()
    {
        var r = new HealthChecker
        {
            CheckService = () => Result.Failure(ErrorCode.ExternalError, "down"),
            CheckAgent = () => Result.Success(),
            CheckPolicy = () => Result.Success()
        }.Check();
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.ExternalError, r.ErrorCode);
        Assert.Contains("Service", r.ErrorMessage ?? string.Empty);
    }

    [Fact]
    public void HealthChecker_AgentFails_StopsAndReturns()
    {
        var r = new HealthChecker
        {
            CheckService = () => Result.Success(),
            CheckAgent = () => Result.Failure(ErrorCode.Unknown, "agent down"),
            CheckPolicy = () => Result.Success()
        }.Check();
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.Unknown, r.ErrorCode);
        Assert.Contains("Agent", r.ErrorMessage ?? string.Empty);
    }

    [Fact]
    public void DatabaseMigrator_NoDatabase_MigrateWithoutBackup_Succeeds()
    {
        var dbPath = Path.Combine(_workDir, "absent.db");
        var snapDir = Path.Combine(_workDir, "snap");
        var migrator = new DatabaseMigrator(dbPath, snapDir)
        {
            ApplyMigrations = () => Result.Success()
        };
        var r = migrator.Migrate();
        Assert.True(r.IsSuccess);
    }

    [Fact]
    public void DatabaseMigrator_ExistingDatabase_BackupsThenMigrates()
    {
        var dbPath = Path.Combine(_workDir, "audit.db");
        var snapDir = Path.Combine(_workDir, "snap");
        File.WriteAllText(dbPath, "v1-data");

        var migrator = new DatabaseMigrator(dbPath, snapDir)
        {
            ApplyMigrations = () =>
            {
                File.WriteAllText(dbPath, "v2-data");
                return Result.Success();
            }
        };
        var r = migrator.Migrate();
        Assert.True(r.IsSuccess);
        Assert.Equal("v2-data", File.ReadAllText(dbPath));
        Assert.Equal("v1-data", File.ReadAllText(Path.Combine(snapDir, "pre_migration.db")));
    }

    [Fact]
    public void DatabaseMigrator_MigrationFails_AutoRestoresFromSnapshot()
    {
        var dbPath = Path.Combine(_workDir, "audit.db");
        var snapDir = Path.Combine(_workDir, "snap");
        File.WriteAllText(dbPath, "original");

        var migrator = new DatabaseMigrator(dbPath, snapDir)
        {
            ApplyMigrations = () =>
            {
                File.WriteAllText(dbPath, "corrupted-by-migration");
                return Result.Failure(ErrorCode.DatabaseWriteFailed, "schema 冲突");
            }
        };

        var r = migrator.Migrate();
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.DatabaseWriteFailed, r.ErrorCode);
        // 自动回滚：数据库恢复为 original
        Assert.Equal("original", File.ReadAllText(dbPath));
    }

    [Fact]
    public void DatabaseMigrator_ManualRollback_RestoresSnapshot()
    {
        var dbPath = Path.Combine(_workDir, "audit.db");
        var snapDir = Path.Combine(_workDir, "snap");
        File.WriteAllText(dbPath, "v1");

        var migrator = new DatabaseMigrator(dbPath, snapDir);
        var migrate = migrator.Migrate();
        Assert.True(migrate.IsSuccess);

        File.WriteAllText(dbPath, "dirty");
        var rollback = migrator.Rollback();
        Assert.True(rollback.IsSuccess);
        Assert.Equal("v1", File.ReadAllText(dbPath));
    }

    [Fact]
    public void DatabaseMigrator_Rollback_NoSnapshot_ReturnsPathNotFound()
    {
        var dbPath = Path.Combine(_workDir, "audit.db");
        var snapDir = Path.Combine(_workDir, "snap");
        var migrator = new DatabaseMigrator(dbPath, snapDir);
        var r = migrator.Rollback();
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.PathNotFound, r.ErrorCode);
    }
}
