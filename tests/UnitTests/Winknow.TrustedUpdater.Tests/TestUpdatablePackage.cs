using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Winknow.TrustedUpdater;

namespace Winknow.TrustedUpdater.Tests;

/// <summary>
/// 测试辅助：构建签名清单 + 生成 .wku 包 + 工具方法。
/// 复用率：多个测试文件共享同一签名/打包流程，避免重复实现。
/// </summary>
internal static class TestUpdatablePackage
{
    public const string ProductId = "Winknow.V7";

    /// <summary>
    /// 生成 RSA 密钥对（测试用，每次调用生成新对）。
    /// </summary>
    public static (RSA privateKey, RSA publicKey) NewRsaKeyPair(int size = 2048)
    {
        var priv = RSA.Create(size);
        var pub = RSA.Create();
        pub.ImportParameters(priv.ExportParameters(false));
        return (priv, pub);
    }

    /// <summary>
    /// 构造清单并用私钥签名。
    /// </summary>
    public static UpdateManifest BuildSignedManifest(
        RSA privateKey,
        string version = "7.0.1",
        string minCompatibleVersion = "7.0.0",
        string productId = ProductId,
        List<string>? rollbackBlacklist = null,
        Dictionary<string, string>? components = null,
        List<FileEntry>? files = null,
        string buildTime = "2026-08-29T00:00:00Z")
    {
        var m = new UpdateManifest
        {
            ProductId = productId,
            Version = version,
            MinCompatibleVersion = minCompatibleVersion,
            RollbackBlacklist = rollbackBlacklist ?? new List<string>(),
            Components = components ?? new Dictionary<string, string>
            {
                ["ControlService"] = version,
                ["GuardService"] = version,
                ["SessionAgent"] = version
            },
            Files = files ?? new List<FileEntry>(),
            BuildTime = buildTime
        };

        var data = Encoding.UTF8.GetBytes(m.ToSignableJson());
        var sig = privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        m.Signature = Convert.ToBase64String(sig);
        return m;
    }

    /// <summary>
    /// 将清单和文件打包成 .wku（zip）。
    /// </summary>
    public static string WritePackage(string packagePath, UpdateManifest manifest, IEnumerable<(string RelativePath, string Content)> files)
    {
        var dir = Path.GetDirectoryName(packagePath) ?? Path.GetTempPath();
        Directory.CreateDirectory(dir);
        if (File.Exists(packagePath)) File.Delete(packagePath);

        using var zip = ZipFile.Open(packagePath, ZipArchiveMode.Create);
        var manifestEntry = zip.CreateEntry("manifest.json");
        using (var s = manifestEntry.Open())
        {
            var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            });
            s.Write(Encoding.UTF8.GetBytes(json));
        }

        foreach (var (rel, content) in files)
        {
            var entry = zip.CreateEntry(rel);
            using var s = entry.Open();
            s.Write(Encoding.UTF8.GetBytes(content));
        }

        return packagePath;
    }

    /// <summary>
    /// 生成文件 + 计算 SHA256（小写 hex）。
    /// </summary>
    public static (string Content, string Sha256) NewFile(string content = "hello") =>
        (content, ComputeSha256(content));

    public static string ComputeSha256(string content)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(content));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// 新建临时部署根目录（唯一）。
    /// </summary>
    public static string NewDeployRoot() => Path.Combine(Path.GetTempPath(), $"wk7_deploy_{Guid.NewGuid():N}");
}
