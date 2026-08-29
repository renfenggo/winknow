using System.IO;
using System.Text.Json;
using Winknow.Core.Results;

namespace Winknow.TrustedUpdater;

/// <summary>
/// A/B 部署槽位管理（Current / Previous / Staging）。
///
/// 用途：V7.0 第 7 周"A/B 目录 Current、Previous、Staging 切换"。
/// 切换用目录重命名（同卷原子），保证更新失败可回滚到 Previous。
/// 满足验收"更新中断后自动回滚"：Previous 始终保留上一可用版本。
///
/// 流程：
/// - Promote：Staging（新版本）→ Current，原 Current → Previous（备份）
/// - Rollback：Previous → Current（丢弃失败的新版本）
///
/// 防双进程：切换发生在服务停止后（由 UpdateOrchestrator 保证），不启动旧版本。
/// </summary>
public sealed class DeploymentSlots
{
    /// <summary>当前运行版本目录。</summary>
    public string CurrentDir { get; }
    /// <summary>上一可用版本目录（回滚源）。</summary>
    public string PreviousDir { get; }
    /// <summary>暂存目录（新版本解包验证目标）。</summary>
    public string StagingDir { get; }

    private readonly string _deployRoot;

    /// <summary>
    /// 构造部署槽位。
    /// </summary>
    /// <param name="deployRoot">部署根目录（如 ProgramData\Winknow\deploy）。</param>
    public DeploymentSlots(string deployRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deployRoot);
        _deployRoot = deployRoot;
        CurrentDir = Path.Combine(deployRoot, "Current");
        PreviousDir = Path.Combine(deployRoot, "Previous");
        StagingDir = Path.Combine(deployRoot, "Staging");
        Directory.CreateDirectory(deployRoot);
        Directory.CreateDirectory(CurrentDir);
        Directory.CreateDirectory(PreviousDir);
        Directory.CreateDirectory(StagingDir);
    }

    /// <summary>
    /// 读取当前版本号（Current/version.json），未安装返回 null。
    /// </summary>
    public string? GetCurrentVersion()
    {
        var v = ReadVersion(CurrentDir);
        return v?.Version;
    }

    /// <summary>
    /// 激活 Staging 为 Current，原 Current 降级为 Previous。
    /// </summary>
    /// <param name="version">新版本号。</param>
    /// <param name="buildTime">构建时间。</param>
    /// <returns>成功或失败结果。</returns>
    public Result Promote(string version, string buildTime)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(version);

        if (!Directory.Exists(StagingDir) || !Directory.EnumerateFileSystemEntries(StagingDir).Any())
        {
            return Result.Failure(ErrorCode.PathNotFound, "Staging 为空，无法激活");
        }

        try
        {
            // 1. 清空 Previous（旧备份）
            if (Directory.Exists(PreviousDir)) Directory.Delete(PreviousDir, true);

            // 2. Current → Previous（备份当前版本）
            if (Directory.Exists(CurrentDir))
            {
                Directory.Move(CurrentDir, PreviousDir);
            }

            // 3. Staging → Current（激活新版本）
            Directory.Move(StagingDir, CurrentDir);

            // 4. 写入 Current/version.json
            WriteVersion(CurrentDir, version, buildTime);
        }
        catch (Exception ex)
        {
            return Result.Failure(ErrorCode.ExternalError, $"Promote 失败: {ex.Message}");
        }

        return Result.Success();
    }

    /// <summary>
    /// 回滚：Previous → Current，丢弃失败的 Current。
    /// </summary>
    /// <returns>成功或失败结果。无 Previous 可回滚时返回失败。</returns>
    public Result Rollback()
    {
        if (!Directory.Exists(PreviousDir) || !Directory.EnumerateFileSystemEntries(PreviousDir).Any())
        {
            return Result.Failure(ErrorCode.PathNotFound, "Previous 为空，无法回滚");
        }

        try
        {
            // 1. 丢弃失败的 Current
            if (Directory.Exists(CurrentDir)) Directory.Delete(CurrentDir, true);

            // 2. Previous → Current
            Directory.Move(PreviousDir, CurrentDir);

            // 3. 清空 Previous（已用完）
            if (Directory.Exists(PreviousDir)) Directory.Delete(PreviousDir, true);
        }
        catch (Exception ex)
        {
            return Result.Failure(ErrorCode.ExternalError, $"Rollback 失败: {ex.Message}");
        }

        return Result.Success();
    }

    /// <summary>
    /// 清空 Staging（更新成功后或放弃时调用）。
    /// </summary>
    public void ClearStaging()
    {
        if (Directory.Exists(StagingDir)) Directory.Delete(StagingDir, true);
        Directory.CreateDirectory(StagingDir);
    }

    private static DeploymentVersion? ReadVersion(string dir)
    {
        var path = Path.Combine(dir, "version.json");
        if (!File.Exists(path)) return null;
        var json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<DeploymentVersion>(json);
    }

    private static void WriteVersion(string dir, string version, string buildTime)
    {
        var v = new DeploymentVersion { Version = version, BuildTime = buildTime };
        var json = JsonSerializer.Serialize(v, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(Path.Combine(dir, "version.json"), json);
    }
}

/// <summary>
/// 槽位版本标记。
/// </summary>
public sealed class DeploymentVersion
{
    /// <summary>版本号。</summary>
    public string Version { get; set; } = string.Empty;
    /// <summary>构建时间。</summary>
    public string BuildTime { get; set; } = string.Empty;
}
