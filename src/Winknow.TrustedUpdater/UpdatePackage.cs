using System.IO.Compression;
using System.Security.Cryptography;
using Winknow.Core.Results;

namespace Winknow.TrustedUpdater;

/// <summary>
/// 更新包解包与文件 Hash 验证。
///
/// 用途：V7.0 第 7 周"文件 Hash 验证"。
/// 更新包格式：.wku（zip），内含 manifest.json + 各组件文件。
/// 验证：解包后逐文件 SHA256 校验，防篡改。
/// </summary>
public static class UpdatePackage
{
    /// <summary>清单文件名。</summary>
    public const string ManifestFileName = "manifest.json";

    /// <summary>
    /// 解包 .wku（zip）到目标目录（先清空目录）。
    /// </summary>
    /// <param name="packagePath">.wku 文件路径。</param>
    /// <param name="destDir">解包目标目录。</param>
    /// <returns>成功或失败结果。</returns>
    public static Result Extract(string packagePath, string destDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(packagePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(destDir);

        if (!File.Exists(packagePath))
        {
            return Result.Failure(ErrorCode.PathNotFound, $"更新包不存在: {packagePath}");
        }

        try
        {
            if (Directory.Exists(destDir)) Directory.Delete(destDir, true);
            Directory.CreateDirectory(destDir);
            using var zip = ZipFile.OpenRead(packagePath);
            zip.ExtractToDirectory(destDir, overwriteFiles: true);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ErrorCode.Unknown, $"解包失败: {ex.Message}");
        }
    }

    /// <summary>
    /// 从已解包目录加载清单。
    /// </summary>
    /// <param name="extractedDir">解包目录。</param>
    /// <returns>清单对象。</returns>
    public static UpdateManifest LoadManifest(string extractedDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(extractedDir);
        var path = Path.Combine(extractedDir, ManifestFileName);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("manifest.json 不存在", path);
        }
        return UpdateManifest.Parse(File.ReadAllText(path));
    }

    /// <summary>
    /// 逐文件校验 SHA256，防篡改。
    /// </summary>
    /// <param name="extractedDir">解包目录。</param>
    /// <param name="manifest">清单。</param>
    /// <returns>全部匹配返回成功。</returns>
    public static Result VerifyFileHashes(string extractedDir, UpdateManifest manifest)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(extractedDir);
        ArgumentNullException.ThrowIfNull(manifest);

        foreach (var entry in manifest.Files)
        {
            var relative = entry.RelativePath.Replace('/', Path.DirectorySeparatorChar);
            var full = Path.Combine(extractedDir, relative);
            if (!File.Exists(full))
            {
                return Result.Failure(ErrorCode.PathNotFound, $"文件缺失: {entry.RelativePath}");
            }

            var actual = ComputeSha256(full);
            if (!string.Equals(actual, entry.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                return Result.Failure(ErrorCode.HashMismatch, $"文件 Hash 不匹配: {entry.RelativePath}");
            }
        }

        return Result.Success();
    }

    /// <summary>
    /// 计算文件 SHA256（小写 hex）。
    /// </summary>
    public static string ComputeSha256(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
