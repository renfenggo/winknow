using System.Security.Cryptography;
using Winknow.Security;

namespace Winknow.Guard.Tests;

/// <summary>
/// 第 10 周对端验证器测试。
/// 注：测试二进制无 Authenticode 签名，签名强校验场景断言其拒绝；
/// 其余场景跳过签名检查（RequireSignature=false）聚焦路径/版本/Hash 逻辑。
/// </summary>
public sealed class PeerVerifierTests : IDisposable
{
    private readonly string _tempDir =
        Path.Combine(Path.GetTempPath(), $"winknow_peer_{Guid.NewGuid():N}");

    public PeerVerifierTests()
    {
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch (IOException) { }
    }

    private string CreateExe(string name = "Winknow.ControlService.exe", string content = "PE payloads")
    {
        var path = Path.Combine(_tempDir, name);
        File.WriteAllText(path, content);
        return path;
    }

    private static string Sha256OfFile(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();

    [Fact]
    public void Verify_Trusted_WhenAllChecksPass()
    {
        var exe = CreateExe();
        var verifier = new PeerVerifier();

        var result = verifier.Verify(exe, new PeerVerifier.PeerExpectation
        {
            AllowedDir = _tempDir,
            RequireSignature = false,           // 测试二进制未签名
            ExpectedSha256 = Sha256OfFile(exe)  // Hash 一致
        });

        Assert.True(result.IsTrusted, result.FailureDetail);
        Assert.True(result.PathOk);
        Assert.True(result.HashOk);
    }

    [Fact]
    public void Verify_Rejects_WrongDirectory()
    {
        var exe = CreateExe();
        var otherDir = Path.Combine(_tempDir, "elsewhere");
        Directory.CreateDirectory(otherDir);

        var result = new PeerVerifier().Verify(exe, new PeerVerifier.PeerExpectation
        {
            AllowedDir = otherDir,
            RequireSignature = false
        });

        Assert.False(result.PathOk);
        Assert.False(result.IsTrusted);
        Assert.Contains("路径", result.FailureDetail);
    }

    [Fact]
    public void Verify_Rejects_NonexistentFile()
    {
        var result = new PeerVerifier().Verify(
            Path.Combine(_tempDir, "ghost.exe"),
            new PeerVerifier.PeerExpectation { AllowedDir = _tempDir, RequireSignature = false });

        Assert.False(result.IsTrusted);
        Assert.False(result.PathOk);
    }

    [Fact]
    public void Verify_Rejects_HashMismatch()
    {
        var exe = CreateExe();
        var result = new PeerVerifier().Verify(exe, new PeerVerifier.PeerExpectation
        {
            AllowedDir = _tempDir,
            RequireSignature = false,
            ExpectedSha256 = new string('a', 64) // 篡改后的 Hash
        });

        Assert.False(result.HashOk);
        Assert.False(result.IsTrusted);
        Assert.Contains("SHA256", result.FailureDetail);
    }

    [Fact]
    public void Verify_Rejects_LowVersion()
    {
        var exe = CreateExe(); // 无版本资源的文件 → 0.0.0
        var result = new PeerVerifier().Verify(exe, new PeerVerifier.PeerExpectation
        {
            AllowedDir = _tempDir,
            RequireSignature = false,
            MinimumVersion = "7.0.0"
        });

        Assert.False(result.VersionOk);
        Assert.False(result.IsTrusted);
    }

    [Fact]
    public void Verify_Rejects_UnsignedBinary_WhenSignatureRequired()
    {
        var exe = CreateExe(); // 测试二进制无 Authenticode 签名
        var result = new PeerVerifier().Verify(exe, new PeerVerifier.PeerExpectation
        {
            AllowedDir = _tempDir,
            RequireSignature = true
        });

        Assert.False(result.SignatureOk);
        Assert.False(result.IsTrusted);
    }

    [Fact]
    public void Verify_Skips_OptionalChecksWhenNotConfigured()
    {
        var exe = CreateExe();
        var result = new PeerVerifier().Verify(exe, new PeerVerifier.PeerExpectation
        {
            AllowedDir = _tempDir,
            RequireSignature = false,
            MinimumVersion = null,
            ExpectedSha256 = null
        });

        Assert.True(result.IsTrusted);
        Assert.Null(result.FailureDetail);
    }
}
