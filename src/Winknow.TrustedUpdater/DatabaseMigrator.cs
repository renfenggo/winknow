using System.IO;
using Winknow.Core.Results;

namespace Winknow.TrustedUpdater;

/// <summary>
/// 数据库迁移骨架（备份 + 迁移回调 + 失败自动回滚）。
///
/// 用途：V7.0 第 7 周"数据库迁移：迁移与回滚"。
/// 满足验收"数据库迁移失败可回滚"：Migrate 内部先备份，迁移回调失败自动 Restore。
///
/// 设计：实际迁移逻辑通过 ApplyMigrations 回调注入（依赖反转），
/// 本类负责备份/回滚框架；具体 schema 变更脚本由第 9 周密钥与日志完整性补全。
/// </summary>
public sealed class DatabaseMigrator
{
    private readonly string _dbPath;
    private readonly string _snapshotDir;
    private readonly string _snapshotPath;

    /// <summary>
    /// 构造数据库迁移器。
    /// </summary>
    /// <param name="dbPath">数据库文件路径（如 audit.db）。</param>
    /// <param name="snapshotDir">快照备份目录。</param>
    public DatabaseMigrator(string dbPath, string snapshotDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dbPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(snapshotDir);
        _dbPath = dbPath;
        _snapshotDir = snapshotDir;
        _snapshotPath = Path.Combine(snapshotDir, "pre_migration.db");
        Directory.CreateDirectory(snapshotDir);
    }

    /// <summary>实际迁移逻辑（由调用方注入）。返回失败则自动回滚。</summary>
    public Func<Result>? ApplyMigrations { get; init; }

    /// <summary>
    /// 执行迁移：先备份当前数据库，再执行 ApplyMigrations，失败自动回滚。
    /// </summary>
    /// <returns>迁移成功返回成功，失败返回失败且数据库已回滚。</returns>
    public Result Migrate()
    {
        // 1. 备份当前 db
        try
        {
            if (File.Exists(_dbPath))
            {
                File.Copy(_dbPath, _snapshotPath, overwrite: true);
            }
        }
        catch (Exception ex)
        {
            return Result.Failure(ErrorCode.ExternalError, $"数据库备份失败: {ex.Message}");
        }

        // 2. 执行迁移回调
        var r = ApplyMigrations?.Invoke() ?? Result.Success();
        if (!r.IsSuccess)
        {
            var restore = RestoreInternal();
            return Result.Failure(r.ErrorCode,
                $"数据库迁移失败已回滚: {r.ErrorMessage}" +
                (restore.IsSuccess ? "" : $"（回滚也失败: {restore.ErrorMessage}）"));
        }

        return Result.Success();
    }

    /// <summary>
    /// 手动回滚到迁移前快照。
    /// </summary>
    public Result Rollback() => RestoreInternal();

    private Result RestoreInternal()
    {
        try
        {
            if (!File.Exists(_snapshotPath))
            {
                return Result.Failure(ErrorCode.PathNotFound, "无数据库快照可回滚");
            }
            File.Copy(_snapshotPath, _dbPath, overwrite: true);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ErrorCode.ExternalError, $"数据库回滚失败: {ex.Message}");
        }
    }
}
