using System.Diagnostics;
using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Winknow.Core;
using Winknow.Core.Results;

namespace Winknow.Logging;

/// <summary>
/// 数据保留管理器：默认 30 天保留期 + 安全删除（覆盖后删除）。
/// 验收项：日志数据到期后安全删除，防止残留恢复。
/// </summary>
public sealed class DataRetentionManager
{
    private readonly ILogger<DataRetentionManager>? _logger;
    private readonly string _dbPath;
    private readonly int _retentionDays;

    /// <summary>
    /// 创建数据保留管理器。
    /// </summary>
    /// <param name="dbPath">审计数据库路径。</param>
    /// <param name="retentionDays">保留天数（默认 30 天）。</param>
    /// <param name="logger">可选日志。</param>
    public DataRetentionManager(string dbPath, int? retentionDays = null, ILogger<DataRetentionManager>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dbPath);
        _dbPath = dbPath;
        _retentionDays = retentionDays ?? Constants.Logging.DefaultRetentionDays;
        _logger = logger;
    }

    /// <summary>
    /// 清理过期审计记录（超过保留期的记录删除）。
    /// </summary>
    /// <returns>删除的记录数。</returns>
    public Result<int> PurgeExpired()
    {
        try
        {
            if (!File.Exists(_dbPath))
            {
                return Result<int>.Success(0);  // 数据库不存在，无需清理
            }

            var cutoff = DateTimeOffset.UtcNow.AddDays(-_retentionDays).ToString("O");
            using var conn = new SqliteConnection($"Data Source={_dbPath}");
            conn.Open();

            // 统计待删除记录数
            var count = conn.ExecuteScalar<int>(
                "SELECT COUNT(*) FROM maintenance_audit WHERE timestamp < @Cutoff",
                new { Cutoff = cutoff });

            if (count == 0)
            {
                _logger?.LogDebug("No expired records to purge (retention: {Days} days)", _retentionDays);
                return Result<int>.Success(0);
            }

            // 删除过期记录
            conn.Execute(
                "DELETE FROM maintenance_audit WHERE timestamp < @Cutoff",
                new { Cutoff = cutoff });

            // 执行 VACUUM 回收空间（安全删除：SQLite VACUUM 覆盖已删除页）
            conn.Execute("VACUUM");

            _logger?.LogInformation("Purged {Count} expired audit records (retention: {Days} days)", count, _retentionDays);
            return Result<int>.Success(count);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to purge expired records");
            return Result<int>.Failure(ErrorCode.DatabaseWriteFailed, ex.Message);
        }
    }

    /// <summary>
    /// 安全删除文件：覆盖后删除（防残留恢复）。
    /// </summary>
    public Result SecureDeleteFile(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        try
        {
            if (!File.Exists(filePath))
            {
                return Result.Success();
            }

            // 用随机数据覆盖文件内容（单次覆盖，教学环境足够）
            var length = new FileInfo(filePath).Length;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None))
            {
                var buffer = new byte[Math.Min(length, 4096)];
                var rng = Random.Shared;
                while (fs.Position < length)
                {
                    rng.NextBytes(buffer);
                    var toWrite = (int)Math.Min(buffer.Length, length - fs.Position);
                    fs.Write(buffer, 0, toWrite);
                }
                fs.Flush(true);  // 强制写入磁盘
            }

            File.Delete(filePath);
            _logger?.LogInformation("Securely deleted file: {Path}", filePath);
            return Result.Success();
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to securely delete file: {Path}", filePath);
            return Result.Failure(ErrorCode.Unknown, ex.Message);
        }
    }

    /// <summary>
    /// 获取当前数据库大小（字节）。
    /// </summary>
    public long GetDatabaseSize()
    {
        return File.Exists(_dbPath) ? new FileInfo(_dbPath).Length : 0;
    }

    /// <summary>
    /// 检查数据库是否超过最大容量。
    /// </summary>
    public bool IsOverSizeLimit()
    {
        return GetDatabaseSize() > Constants.Logging.MaxDatabaseSizeBytes;
    }

    /// <summary>
    /// 获取保留天数。
    /// </summary>
    public int RetentionDays => _retentionDays;
}
