using System.IO;
using System.IO.Compression;
using System.Text;
using Winknow.Core.Results;
using Winknow.TrustedUpdater;

namespace Winknow.TrustedUpdater.Tests;

/// <summary>
/// 第 7 周"更新包解包 + 文件 Hash 验证"测试。
/// 覆盖验收项：
/// - "文件 Hash 验证"（VerifyFileHashes 成功/Hash 不匹配/文件缺失）
/// - "更新包签名验证失败时拒绝安装"（Extract 失败链路）
/// </summary>
public class UpdatePackageTests : IDisposable
{
    private readonly string _workDir = Path.Combine(Path.GetTempPath(), $"wk7_pkg_{Guid.NewGuid():N}");

    public UpdatePackageTests()
    {
        Directory.CreateDirectory(_workDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_workDir)) Directory.Delete(_workDir, true);
    }

    [Fact]
    public void Extract_NonExistentPackage_ReturnsPathNotFound()
    {
        var path = Path.Combine(_workDir, "nope.wku");
        var r = UpdatePackage.Extract(path, Path.Combine(_workDir, "out"));
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.PathNotFound, r.ErrorCode);
    }

    [Fact]
    public void Extract_InvalidZip_ReturnsUnknown()
    {
        var path = Path.Combine(_workDir, "bad.wku");
        File.WriteAllBytes(path, [0x00, 0x01, 0x02]);   // 不是合法 zip
        var r = UpdatePackage.Extract(path, Path.Combine(_workDir, "out"));
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.Unknown, r.ErrorCode);
    }

    [Fact]
    public void Extract_ValidZip_ExtractsAllEntries()
    {
        var path = MakeZip("valid.wku", ("manifest.json", "{}"), ("a.txt", "hello"), ("b/c.txt", "world"));
        var outDir = Path.Combine(_workDir, "out");
        var r = UpdatePackage.Extract(path, outDir);
        Assert.True(r.IsSuccess);
        Assert.True(File.Exists(Path.Combine(outDir, "manifest.json")));
        Assert.True(File.Exists(Path.Combine(outDir, "a.txt")));
        Assert.True(File.Exists(Path.Combine(outDir, "b", "c.txt")));
    }

    [Fact]
    public void LoadManifest_MissingManifest_Throws()
    {
        var outDir = Path.Combine(_workDir, "no_manifest");
        Directory.CreateDirectory(outDir);
        File.WriteAllText(Path.Combine(outDir, "a.txt"), "x");
        Assert.Throws<FileNotFoundException>(() => UpdatePackage.LoadManifest(outDir));
    }

    [Fact]
    public void LoadManifest_ReadsManifest()
    {
        var outDir = Path.Combine(_workDir, "with_manifest");
        Directory.CreateDirectory(outDir);
        File.WriteAllText(Path.Combine(outDir, "manifest.json"),
            "{\"productId\":\"Winknow.V7\",\"version\":\"7.0.1\",\"files\":[]}");
        var m = UpdatePackage.LoadManifest(outDir);
        Assert.Equal("Winknow.V7", m.ProductId);
        Assert.Equal("7.0.1", m.Version);
    }

    [Fact]
    public void VerifyFileHashes_AllMatch_Succeeds()
    {
        var outDir = Path.Combine(_workDir, "hash_ok");
        Directory.CreateDirectory(outDir);
        var (c1, h1) = TestUpdatablePackage.NewFile("alpha");
        var (c2, h2) = TestUpdatablePackage.NewFile("beta");
        File.WriteAllText(Path.Combine(outDir, "a.txt"), c1);
        Directory.CreateDirectory(Path.Combine(outDir, "sub"));
        File.WriteAllText(Path.Combine(outDir, "sub", "b.txt"), c2);

        var m = new UpdateManifest
        {
            Files = new List<FileEntry>
            {
                new() { RelativePath = "a.txt", Sha256 = h1 },
                new() { RelativePath = "sub/b.txt", Sha256 = h2 }
            }
        };

        var r = UpdatePackage.VerifyFileHashes(outDir, m);
        Assert.True(r.IsSuccess);
    }

    [Fact]
    public void VerifyFileHashes_HashMismatch_ReturnsHashMismatch()
    {
        var outDir = Path.Combine(_workDir, "hash_bad");
        Directory.CreateDirectory(outDir);
        File.WriteAllText(Path.Combine(outDir, "a.txt"), "actual");
        var m = new UpdateManifest
        {
            Files = new List<FileEntry>
            {
                new() { RelativePath = "a.txt", Sha256 = "0000" }   // 故意错误
            }
        };
        var r = UpdatePackage.VerifyFileHashes(outDir, m);
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.HashMismatch, r.ErrorCode);
    }

    [Fact]
    public void VerifyFileHashes_FileMissing_ReturnsPathNotFound()
    {
        var outDir = Path.Combine(_workDir, "hash_missing");
        Directory.CreateDirectory(outDir);
        var m = new UpdateManifest
        {
            Files = new List<FileEntry>
            {
                new() { RelativePath = "ghost.txt", Sha256 = "00" }
            }
        };
        var r = UpdatePackage.VerifyFileHashes(outDir, m);
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.PathNotFound, r.ErrorCode);
    }

    private string MakeZip(string name, params (string Entry, string Content)[] entries)
    {
        var path = Path.Combine(_workDir, name);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var (entry, content) in entries)
        {
            var e = zip.CreateEntry(entry);
            using var s = e.Open();
            s.Write(Encoding.UTF8.GetBytes(content));
        }
        return path;
    }
}
