using System.IO;

namespace Winknow.TrustedUpdater;

/// <summary>
/// 更新模式标志（文件级互斥提示，防守护与更新交叉拉起）。
///
/// 用途：V7.0 第 10 周验收"更新模式不会触发交叉拉起"。
/// 更新流程会主动停止 ControlService（见 Program.StopManagedServices），
/// 若无协调机制，GuardService 会因心跳过期而"好心"把服务拉起来，
/// 与更新的 Stop→切换→Start 流程交叉，造成新旧版本同时运行。
///
/// 机制：
/// - TrustedUpdater 在 apply/rollback 前调用 <see cref="TryEnter"/>（写时间戳标志文件），
///   结束后 <see cref="Exit"/> 删除；
/// - GuardService 拉起前调用 <see cref="IsUpdateInProgress"/>，为 true 则暂停干预；
/// - 标志新鲜度上限 10 分钟：TrustedUpdater 中途崩溃遗留的陈旧标志自动失效，
///   守护恢复监控（防更新器一次崩溃永久禁用守护）。
///
/// 非强互斥（文件标志可被篡改删除），但配合 PeerVerifier 的 Hash/签名校验，
/// 攻击者删标志伪造更新窗口的收益仅是"暂缓拉起"，不产生放行。
/// </summary>
public static class UpdateModeFlag
{
    private const string FlagFileName = "update_mode.flag";

    /// <summary>标志文件最大新鲜期：超过即视为陈旧（更新器崩溃遗留）。</summary>
    public static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(10);

    /// <summary>
    /// 尝试进入更新模式：无有效标志时写入并返回 true；
    /// 已有新鲜标志（另一更新器在跑）返回 false。
    /// </summary>
    /// <param name="dataDir">数据目录（ProgramData\Winknow）。</param>
    public static bool TryEnter(string dataDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDir);
        try
        {
            Directory.CreateDirectory(dataDir);
            var path = Path.Combine(dataDir, FlagFileName);

            if (File.Exists(path) && IsFresh(path))
            {
                return false; // 已有更新在进行
            }

            File.WriteAllText(path, DateTimeOffset.UtcNow.ToString("O"));
            return true;
        }
        catch (IOException)
        {
            return false; // IO 失败按"无法进入"处理，宁可拒绝更新不可交叉拉起
        }
    }

    /// <summary>
    /// 退出更新模式（删除标志；幂等）。
    /// </summary>
    public static void Exit(string dataDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDir);
        try
        {
            var path = Path.Combine(dataDir, FlagFileName);
            if (File.Exists(path)) File.Delete(path);
        }
        catch (IOException)
        {
            // 删除失败：标志会因新鲜度超时自然失效
        }
    }

    /// <summary>
    /// 是否有新鲜的更新标志（守护侧调用：true 时暂停拉起干预）。
    /// </summary>
    public static bool IsUpdateInProgress(string dataDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDir);
        try
        {
            var path = Path.Combine(dataDir, FlagFileName);
            return File.Exists(path) && IsFresh(path);
        }
        catch (IOException)
        {
            return false;
        }
    }

    private static bool IsFresh(string path)
    {
        try
        {
            if (!DateTimeOffset.TryParse(File.ReadAllText(path), out var ts)) return false;
            return DateTimeOffset.UtcNow - ts < MaxAge;
        }
        catch (IOException)
        {
            return false;
        }
    }
}
