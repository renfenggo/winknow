using Winknow.Core.Results;

namespace Winknow.TrustedUpdater;

/// <summary>
/// 版本守卫：防降级保护 + 版本兼容校验。
///
/// 用途：V7.0 第 7 周"版本兼容校验（主服务、守护服务、Agent 版本一致性）"+"防降级保护（拒绝降级到已知不安全版本）"。
///
/// 防降级：
/// - 目标版本低于当前版本 → 拒绝（VersionBlocked）
/// - 目标版本在 RollbackBlacklist → 拒绝（已知不安全版本）
/// - 允许重装同版本或升级
///
/// 版本一致性：
/// - manifest.Components 各组件版本必须彼此一致（防 ControlService=7.0.1 而 Agent=7.0.0）
/// - 当前版本必须 >= manifest.MinCompatibleVersion（太旧需先升级中间版本）
/// </summary>
public static class VersionGuard
{
    /// <summary>
    /// 比较两个版本号。支持 Major.Minor[.Build[.Revision]]。
    /// </summary>
    /// <returns>a 小于 b 返回 -1，相等 0，大于返回 1。</returns>
    public static int CompareVersions(string a, string b)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(a);
        ArgumentException.ThrowIfNullOrWhiteSpace(b);

        if (Version.TryParse(a, out var va) && Version.TryParse(b, out var vb))
        {
            return va.CompareTo(vb);
        }
        // 无法解析为 Version 时退回字符串序比较（确定性但语义弱）
        return string.Compare(a, b, StringComparison.Ordinal);
    }

    /// <summary>
    /// 防降级检查。
    /// </summary>
    /// <param name="currentVersion">当前已安装版本。</param>
    /// <param name="manifest">更新包清单。</param>
    /// <returns>允许升级/重装返回成功，降级或命中黑名单返回 VersionBlocked。</returns>
    public static Result CheckUpgrade(string currentVersion, UpdateManifest manifest)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(currentVersion);
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentException.ThrowIfNullOrWhiteSpace(manifest.Version);

        // 命中降级黑名单（已知不安全版本）
        if (manifest.RollbackBlacklist.Contains(manifest.Version, StringComparer.OrdinalIgnoreCase))
        {
            return Result.Failure(ErrorCode.VersionBlocked,
                $"目标版本 {manifest.Version} 在降级黑名单中");
        }

        // 禁止降级（允许重装同版本）
        if (CompareVersions(manifest.Version, currentVersion) < 0)
        {
            return Result.Failure(ErrorCode.VersionBlocked,
                $"不允许降级：当前 {currentVersion}，目标 {manifest.Version}");
        }

        return Result.Success();
    }

    /// <summary>
    /// 版本兼容校验：当前版本是否满足最低兼容要求 + 组件版本一致性。
    /// </summary>
    /// <param name="currentVersion">当前已安装版本。</param>
    /// <param name="manifest">更新包清单。</param>
    /// <returns>兼容返回成功。</returns>
    public static Result CheckCompatibility(string currentVersion, UpdateManifest manifest)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(currentVersion);
        ArgumentNullException.ThrowIfNull(manifest);

        // 当前版本必须 >= 最低兼容版本
        if (!string.IsNullOrWhiteSpace(manifest.MinCompatibleVersion)
            && CompareVersions(currentVersion, manifest.MinCompatibleVersion) < 0)
        {
            return Result.Failure(ErrorCode.InvalidArgument,
                $"当前版本 {currentVersion} 太旧，最低需 {manifest.MinCompatibleVersion}，请先升级中间版本");
        }

        // 组件版本一致性：manifest 内各组件版本必须彼此相同
        if (manifest.Components.Count > 0)
        {
            var distinct = manifest.Components.Values.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (distinct.Count > 1)
            {
                return Result.Failure(ErrorCode.InvalidArgument,
                    "组件版本不一致：" + string.Join(", ", manifest.Components.Select(kv => $"{kv.Key}={kv.Value}")));
            }
        }

        return Result.Success();
    }
}
