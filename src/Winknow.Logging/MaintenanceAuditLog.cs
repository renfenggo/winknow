using Dapper;
using Microsoft.Data.Sqlite;

namespace Winknow.Logging;

/// <summary>
/// 维护模式审计日志（SQLite 持久化）。
///
/// 用途：记录维护会话的启动人、时间、原因、操作、结束时间（V7.0 第 6 周"维护审计"）。
/// 采用事件流模型：进入/操作/退出/超时各记一条，便于追溯完整维护轨迹。
/// 满足验收"维护超时后自动恢复保护"：超时退出也产生审计记录。
///
/// 表结构：maintenance_audit(id, actor, operation, reason, detail, timestamp)
/// operation 取值：enter / exit / timeout / extend / uninstall
/// </summary>
public sealed class MaintenanceAuditLog
{
    private readonly string _connectionString;

    /// <summary>
    /// 构造审计日志，自动建表（幂等）。
    /// </summary>
    /// <param name="dbPath">SQLite 数据库文件路径。</param>
    public MaintenanceAuditLog(string dbPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dbPath);
        var dir = Path.GetDirectoryName(dbPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }
        _connectionString = $"Data Source={dbPath}";
        EnsureSchema();
    }

    /// <summary>
    /// 记录一条维护审计事件。
    /// </summary>
    /// <param name="actor">启动人/操作者（管理员名或"recovery-code"）。</param>
    /// <param name="operation">操作类型：enter/exit/timeout/extend/uninstall。</param>
    /// <param name="reason">维护原因（enter 时填写）。</param>
    /// <param name="detail">附加详情。</param>
    public void RecordEntry(string actor, string operation, string? reason = null, string? detail = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);
        ArgumentException.ThrowIfNullOrWhiteSpace(operation);

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        conn.Execute(
            """
            INSERT INTO maintenance_audit (actor, operation, reason, detail, timestamp)
            VALUES (@Actor, @Operation, @Reason, @Detail, @Ts)
            """,
            new
            {
                Actor = actor,
                Operation = operation,
                Reason = reason,
                Detail = detail,
                Ts = DateTimeOffset.UtcNow.ToString("O")
            });
    }

    /// <summary>
    /// 查询最近的审计记录（按时间倒序）。
    /// </summary>
    /// <param name="limit">返回条数，默认 50。</param>
    /// <returns>审计记录列表。</returns>
    public IReadOnlyList<MaintenanceAuditEntry> QueryRecent(int limit = 50)
    {
        if (limit <= 0) limit = 50;
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn.Query<MaintenanceAuditEntry>(
            """
            SELECT id AS Id, actor AS Actor, operation AS Operation,
                   reason AS Reason, detail AS Detail, timestamp AS Timestamp
            FROM maintenance_audit
            ORDER BY id DESC
            LIMIT @Limit
            """,
            new { Limit = limit }).ToList();
    }

    private void EnsureSchema()
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        conn.Execute(
            """
            CREATE TABLE IF NOT EXISTS maintenance_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                operation TEXT NOT NULL,
                reason TEXT,
                detail TEXT,
                timestamp TEXT NOT NULL
            )
            """);
    }
}

/// <summary>
/// 维护审计记录条目。
/// </summary>
public sealed class MaintenanceAuditEntry
{
    /// <summary>记录自增 ID。</summary>
    public long Id { get; set; }
    /// <summary>操作者。</summary>
    public string Actor { get; set; } = string.Empty;
    /// <summary>操作类型。</summary>
    public string Operation { get; set; } = string.Empty;
    /// <summary>维护原因。</summary>
    public string? Reason { get; set; }
    /// <summary>附加详情。</summary>
    public string? Detail { get; set; }
    /// <summary>时间戳（ISO 8601）。</summary>
    public string Timestamp { get; set; } = string.Empty;
}
