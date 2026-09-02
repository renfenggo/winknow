using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Winknow.Core;
using Winknow.Core.Results;

namespace Winknow.Ipc;

/// <summary>
/// 心跳租约（文件级活性协商，替代纯进程名/服务状态检测）。
///
/// 用途：V7.0 第 10 周"心跳租约——替代纯进程名检测"。
/// 纯服务状态检测的盲区：服务显示 Running 但主循环死锁/挂起。
/// 本组件让 ControlService 周期写租约（PID+时间戳+版本），
/// GuardService 以"租约是否在超时内续签"判定真实活性——
/// 挂起、死锁、进程存在但不工作的情形都能被识别。
///
/// 设计：
/// - 写侧（ControlService）：每 <see cref="Constants.Guard.HeartbeatIntervalSeconds"/> 秒 Write 一次。
/// - 读侧（GuardService）：ReadLease + IsExpired 判定，超时阈值默认 3 个心跳周期。
/// - JSON 序列化（原子写：临时文件 + File.Move）防读侧读到半截文件。
/// </summary>
public sealed class HeartbeatLease
{
    /// <summary>租约记录（heartbeat.json 内容）。</summary>
    public sealed record LeaseData
    {
        /// <summary>持有租约的进程 ID。</summary>
        [JsonPropertyName("pid")] public int Pid { get; init; }

        /// <summary>心跳时间戳（ISO 8601 UTC）。</summary>
        [JsonPropertyName("timestamp")] public string Timestamp { get; init; } = string.Empty;

        /// <summary>服务版本。</summary>
        [JsonPropertyName("version")] public string Version { get; init; } = string.Empty;

        /// <summary>服务名（SCM 内部名，如 WinknowControl）。</summary>
        [JsonPropertyName("serviceName")] public string ServiceName { get; init; } = string.Empty;

        /// <summary>进程启动时间（ISO 8601 UTC），用于识别"重启后又活过来"的新实例。</summary>
        [JsonPropertyName("startedAt")] public string StartedAt { get; init; } = string.Empty;
    }

    /// <summary>读侧判定结果。</summary>
    public sealed record LeaseStatus(bool HasLease, bool IsExpired, LeaseData? Lease, double AgeSeconds)
    {
        /// <summary>租约持有者存活的判定（有租约且未过期）。</summary>
        public bool IsAlive => HasLease && !IsExpired;
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly string _leaseFilePath;
    private readonly TimeSpan _leaseTimeout;
    private readonly Func<DateTimeOffset> _clock;

    /// <summary>
    /// 构造心跳租约。
    /// </summary>
    /// <param name="dataDir">数据目录（如 ProgramData\Winknow），租约文件写入其下。</param>
    /// <param name="leaseTimeout">租约超时（默认 <see cref="Constants.Guard.LeaseTimeoutSeconds"/>）。</param>
    /// <param name="clock">时间源（测试注入）。</param>
    public HeartbeatLease(string dataDir, TimeSpan? leaseTimeout = null, Func<DateTimeOffset>? clock = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDir);
        _leaseFilePath = Path.Combine(dataDir, Constants.Guard.HeartbeatFileName);
        _leaseTimeout = leaseTimeout ?? TimeSpan.FromSeconds(Constants.Guard.LeaseTimeoutSeconds);
        _clock = clock ?? (static () => DateTimeOffset.UtcNow);
    }

    /// <summary>租约文件完整路径。</summary>
    public string LeaseFilePath => _leaseFilePath;

    /// <summary>
    /// 写侧：续签租约（原子写，写失败返回失败结果不抛异常）。
    /// </summary>
    /// <param name="pid">进程 ID。</param>
    /// <param name="serviceName">服务名。</param>
    /// <param name="version">版本。</param>
    /// <param name="startedAt">进程启动时间。</param>
    public Result Write(int pid, string serviceName, string version, DateTimeOffset? startedAt = null)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_leaseFilePath)!);
            var lease = new LeaseData
            {
                Pid = pid,
                Timestamp = _clock().ToString("O"),
                Version = version,
                ServiceName = serviceName,
                StartedAt = (startedAt ?? _clock()).ToString("O")
            };
            var json = JsonSerializer.Serialize(lease, JsonOptions);

            // 原子写：先写临时文件再替换，读侧不会读到半截 JSON
            var tmp = _leaseFilePath + ".tmp";
            File.WriteAllText(tmp, json);
            if (File.Exists(_leaseFilePath))
            {
                File.Replace(tmp, _leaseFilePath, null);
            }
            else
            {
                File.Move(tmp, _leaseFilePath);
            }
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ErrorCode.ExternalError, $"写入心跳租约失败: {ex.Message}");
        }
    }

    /// <summary>
    /// 读侧：读取租约并判定活性。文件不存在/损坏视为无租约（即不活跃）。
    /// </summary>
    public LeaseStatus Check()
    {
        if (!File.Exists(_leaseFilePath))
        {
            return new LeaseStatus(HasLease: false, IsExpired: true, Lease: null, AgeSeconds: -1);
        }

        try
        {
            var lease = JsonSerializer.Deserialize<LeaseData>(File.ReadAllText(_leaseFilePath));
            if (lease is null || !DateTimeOffset.TryParse(lease.Timestamp, out var ts))
            {
                return new LeaseStatus(HasLease: false, IsExpired: true, Lease: null, AgeSeconds: -1);
            }

            var age = _clock() - ts;
            return new LeaseStatus(
                HasLease: true,
                IsExpired: age >= _leaseTimeout,
                Lease: lease,
                AgeSeconds: age.TotalSeconds);
        }
        catch (Exception)
        {
            // JSON 损坏等：按无租约处理（fail-safe：宁可误判死亡触发守护，不可误判存活）
            return new LeaseStatus(HasLease: false, IsExpired: true, Lease: null, AgeSeconds: -1);
        }
    }

    /// <summary>
    /// 写侧退出时清除租约文件（服务正常停止时调用，避免守护侧等待超时）。
    /// </summary>
    public void Clear()
    {
        try
        {
            if (File.Exists(_leaseFilePath)) File.Delete(_leaseFilePath);
        }
        catch (IOException)
        {
            // 清理失败无害：租约会自然过期
        }
    }
}
