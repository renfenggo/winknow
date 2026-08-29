using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Winknow.Core.Results;

namespace Winknow.TrustedUpdater;

/// <summary>
/// 可信恢复库（Recovery 目录：核心文件的离线可信副本 + Hash 清单）。
///
/// 用途：V7.0 第 10 周"Recovery 目录——可信恢复副本"。
/// 在部署根之外维护一份只读副本（Recovery Vault）：
/// - SnapshotFrom：从 Current（或安装介质）建立副本并生成 manifest（文件名+SHA256+版本+时间）；
/// - VerifyAgainstManifest：对任意目录逐文件 Hash 校验，报告损坏清单；
/// - RestoreFile / RestoreAll：从副本恢复被损坏的文件。
///
/// 与 DeploymentSlots.Previous 的区别：Previous 是"上一版本"（更新回滚用），
/// Recovery 是"当前版本的已知良好副本"（损坏修复用）——两者来源与用途不同，
/// Previous 可能在一次成功更新后为空，Recovery 始终保有最近一次快照。
/// </summary>
public sealed class RecoveryVault
{
    /// <summary>清单条目。</summary>
    public sealed record ManifestEntry
    {
        /// <summary>相对路径（相对于 Current 根）。</summary>
        [JsonPropertyName("path")] public string Path { get; init; } = string.Empty;

        /// <summary>SHA256（小写 Hex）。</summary>
        [JsonPropertyName("sha256")] public string Sha256 { get; init; } = string.Empty;

        /// <summary>文件大小（字节）。</summary>
        [JsonPropertyName("size")] public long Size { get; init; }
    }

    /// <summary>恢复库清单（manifest.json）。</summary>
    public sealed class VaultManifest
    {
        /// <summary>快照来源版本号。</summary>
        [JsonPropertyName("version")] public string Version { get; set; } = string.Empty;

        /// <summary>快照时间（ISO 8601 UTC）。</summary>
        [JsonPropertyName("snapshotAt")] public string SnapshotAt { get; set; } = string.Empty;

        /// <summary>文件条目。</summary>
        [JsonPropertyName("files")] public List<ManifestEntry> Files { get; set; } = new();
    }

    /// <summary>校验结果。</summary>
    public sealed record VerifyReport(int Checked, List<ManifestEntry> Corrupted, List<string> Missing)
    {
        /// <summary>是否全部完好。</summary>
        public bool IsHealthy => Corrupted.Count == 0 && Missing.Count == 0;
    }

    /// <summary>Recovery 目录名。</summary>
    public const string VaultDirName = "Recovery";

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    /// <summary>Recovery 目录路径。</summary>
    public string VaultDir { get; }

    /// <summary>清单文件路径。</summary>
    public string ManifestPath { get; }

    /// <summary>
    /// 构造恢复库。
    /// </summary>
    /// <param name="deployRoot">部署根目录（Recovery 建在其下）。</param>
    public RecoveryVault(string deployRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deployRoot);
        VaultDir = Path.Combine(deployRoot, VaultDirName);
        ManifestPath = Path.Combine(VaultDir, "manifest.json");
    }

    /// <summary>
    /// 从源目录（通常 Current）建立可信快照：复制全部文件 + 生成 Hash 清单。
    /// 已有快照会被覆盖（以最近一次成功部署为准）。
    /// </summary>
    /// <param name="sourceDir">快照来源目录。</param>
    /// <param name="version">来源版本号。</param>
    public Result SnapshotFrom(string sourceDir, string version)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceDir);
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        if (!Directory.Exists(sourceDir))
        {
            return Result.Failure(ErrorCode.PathNotFound, $"快照来源不存在: {sourceDir}");
        }

        try
        {
            // 重建 Recovery 目录（清空旧快照）
            if (Directory.Exists(VaultDir)) Directory.Delete(VaultDir, true);
            Directory.CreateDirectory(VaultDir);

            var manifest = new VaultManifest
            {
                Version = version,
                SnapshotAt = DateTimeOffset.UtcNow.ToString("O")
            };

            foreach (var file in Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories))
            {
                var rel = Path.GetRelativePath(sourceDir, file);
                var bytes = File.ReadAllBytes(file);
                var dest = Path.Combine(VaultDir, rel);
                Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                File.WriteAllBytes(dest, bytes);

                manifest.Files.Add(new ManifestEntry
                {
                    Path = rel,
                    Sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
                    Size = bytes.Length
                });
            }

            File.WriteAllText(ManifestPath, JsonSerializer.Serialize(manifest, JsonOptions));
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ErrorCode.ExternalError, $"建立恢复快照失败: {ex.Message}");
        }
    }

    /// <summary>
    /// 读取清单；不存在返回 null。
    /// </summary>
    public VaultManifest? GetManifest()
    {
        try
        {
            if (!File.Exists(ManifestPath)) return null;
            return JsonSerializer.Deserialize<VaultManifest>(File.ReadAllText(ManifestPath));
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// 校验目标目录（通常 Current）与清单的一致性。
    /// Hash 不匹配 → Corrupted；文件缺失 → Missing。
    /// </summary>
    /// <param name="targetDir">被校验目录。</param>
    /// <param name="manifest">清单（null 时自动读取）。</param>
    public VerifyReport VerifyAgainstManifest(string targetDir, VaultManifest? manifest = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetDir);
        manifest ??= GetManifest() ?? new VaultManifest();

        var corrupted = new List<ManifestEntry>();
        var missing = new List<string>();
        var checked_ = 0;

        foreach (var entry in manifest.Files)
        {
            var path = Path.Combine(targetDir, entry.Path);
            checked_++;
            if (!File.Exists(path))
            {
                missing.Add(entry.Path);
                continue;
            }
            var actual = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
            if (!string.Equals(actual, entry.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                corrupted.Add(entry);
            }
        }

        return new VerifyReport(checked_, corrupted, missing);
    }

    /// <summary>
    /// 从恢复库恢复单个文件（覆盖目标）。
    /// </summary>
    /// <param name="relativePath">清单中的相对路径。</param>
    /// <param name="targetDir">恢复目标目录。</param>
    public Result RestoreFile(string relativePath, string targetDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetDir);

        var src = Path.Combine(VaultDir, relativePath);
        if (!File.Exists(src))
        {
            return Result.Failure(ErrorCode.PathNotFound, $"恢复库中无此文件: {relativePath}");
        }
        try
        {
            var dest = Path.Combine(targetDir, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            File.Copy(src, dest, overwrite: true);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ErrorCode.ExternalError, $"恢复文件失败 {relativePath}: {ex.Message}");
        }
    }

    /// <summary>
    /// 恢复库是否就绪（目录存在、清单有效、副本文件齐全）。
    /// </summary>
    public bool IsReady()
    {
        var m = GetManifest();
        if (m is null) return false;
        return m.Files.All(f => File.Exists(Path.Combine(VaultDir, f.Path)));
    }
}
