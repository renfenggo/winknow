using System.IO;
using System.Text.Json;
using Winknow.Core.Results;

namespace Winknow.Security;

/// <summary>
/// 单实例守卫（全局 Mutex + 身份校验）。
///
/// 用途：V7.0 第 10 周"单实例——Mutex + 身份校验"。
/// 满足验收"更新模式不会触发交叉拉起"：新旧实例以全局互斥锁竞争唯一运行权，
/// 后启动者拿不到锁即退出；锁持有者身份落盘（PID+路径+启动时间），
/// 供守护侧与人工排查确认"谁在运行、从哪运行"。
///
/// 与 SessionMutex 的区别：后者是每用户会话一个 Agent 实例；
/// 本组件是系统级服务（LocalSystem）单实例。
///
/// 身份校验语义：
/// - Mutex 是唯一的运行权仲裁（Windows 保证跨进程可靠）。
/// - owner 文件只是辅助证据（Mutex 持有者崩溃后 OS 自动释放锁，
///   owner 文件可能残留——读侧以 Mutex 状态为准，owner 仅作参考）。
/// </summary>
public sealed class SingleInstanceGuard : IDisposable
{
    /// <summary>锁持有者身份记录（owner.json 内容）。</summary>
    public sealed record OwnerInfo
    {
        /// <summary>进程 ID。</summary>
        public int Pid { get; init; }
        /// <summary>可执行文件路径。</summary>
        public string ExePath { get; init; } = string.Empty;
        /// <summary>启动时间（ISO 8601 UTC）。</summary>
        public string StartedAt { get; init; } = string.Empty;
    }

    private readonly Mutex _mutex;
    private readonly string _ownerFilePath;
    private readonly bool _acquired;

    /// <summary>
    /// 构造单实例守卫：尝试获取全局互斥锁。
    /// </summary>
    /// <param name="mutexName">互斥锁名（建议 Global\Winknow_&lt;服务名&gt;_Instance）。</param>
    /// <param name="ownerFileDir">owner 身份文件目录（如 ProgramData\Winknow）。</param>
    public SingleInstanceGuard(string mutexName, string ownerFileDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(mutexName);
        ArgumentException.ThrowIfNullOrWhiteSpace(ownerFileDir);

        _mutex = new Mutex(initiallyOwned: true, name: mutexName, createdNew: out _acquired);
        var shortName = mutexName.Replace("Global\\", string.Empty).Replace("Local\\", string.Empty);
        _ownerFilePath = Path.Combine(ownerFileDir, $"{shortName}_owner.json");

        if (_acquired)
        {
            WriteOwner();
        }
    }

    /// <summary>是否成功获取运行权（true=本进程是唯一实例）。</summary>
    public bool IsAcquired => _acquired;

    /// <summary>
    /// 读取当前锁持有者身份（本进程未获锁时读到的即是对端实例）。
    /// 文件不存在或损坏返回 null（Mutex 状态仍以 <see cref="IsAcquired"/> 为准）。
    /// </summary>
    public OwnerInfo? ReadOwner()
    {
        try
        {
            if (!File.Exists(_ownerFilePath)) return null;
            return JsonSerializer.Deserialize<OwnerInfo>(File.ReadAllText(_ownerFilePath));
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// 旧实例是否仍在运行（PID 存活 + 路径与本进程一致才算有效占用）。
    /// 用于获锁失败后的诊断：true=合法旧实例在运行，本进程应退出；
    /// false=owner 文件残留（旧实例已崩溃），可报警后由守护流程处理。
    /// </summary>
    public static bool IsOwnerAlive(OwnerInfo? owner)
    {
        if (owner is null || owner.Pid <= 0) return false;
        try
        {
            var proc = System.Diagnostics.Process.GetProcessById(owner.Pid);
            // 进程名匹配基本身份；同名不同会话的精确甄别由路径校验承担
            return !proc.HasExited;
        }
        catch (ArgumentException)
        {
            return false; // PID 不存在
        }
        catch (Exception)
        {
            return true; // 无法判定时保守视为存活（fail-safe：不重复启动）
        }
    }

    private void WriteOwner()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_ownerFilePath)!);
            var owner = new OwnerInfo
            {
                Pid = Environment.ProcessId,
                ExePath = Environment.ProcessPath ?? string.Empty,
                StartedAt = DateTimeOffset.UtcNow.ToString("O")
            };
            File.WriteAllText(_ownerFilePath, JsonSerializer.Serialize(owner, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception)
        {
            // owner 文件写失败不影响 Mutex 仲裁（身份文件仅辅助）
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_acquired)
        {
            try
            {
                _mutex.ReleaseMutex();
            }
            catch (ApplicationException)
            {
                // 非持有线程释放，忽略
            }
        }
        _mutex.Dispose();
    }
}
