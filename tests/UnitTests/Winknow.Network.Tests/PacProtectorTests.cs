using System.IO;
using Winknow.Core.Results;
using Winknow.Network;
using Winknow.Policy;

namespace Winknow.Network.Tests;

/// <summary>
/// 第 8 周"PAC 保护器"测试。
/// 覆盖验收项："修改 PAC 后恢复"（Hash 校验 + Restore）
/// </summary>
public class PacProtectorTests : IDisposable
{
    private readonly string _workDir = Path.Combine(Path.GetTempPath(), $"wk8_pac_{Guid.NewGuid():N}");
    private readonly string _pacPath;

    public PacProtectorTests()
    {
        Directory.CreateDirectory(_workDir);
        _pacPath = Path.Combine(_workDir, "proxy.pac");
        File.WriteAllText(_pacPath, "// clean pac\nfunction FindProxyForURL(url, host){ return 'DIRECT'; }");
    }

    public void Dispose()
    {
        if (Directory.Exists(_workDir)) Directory.Delete(_workDir, true);
    }

    [Fact]
    public void Initialize_ValidLocalPath_ComputesBaselineHash()
    {
        var protector = new PacProtector(new PacSection { Allowed = true });
        var r = protector.Initialize(_pacPath);
        Assert.True(r.IsSuccess);
        Assert.False(string.IsNullOrEmpty(protector.BaselineHash));
    }

    [Fact]
    public void Initialize_EmptyUrl_ReturnsInvalidParameter()
    {
        var protector = new PacProtector(new PacSection { Allowed = true });
        var r = protector.Initialize("");
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.InvalidParameter, r.ErrorCode);
    }

    [Fact]
    public void Initialize_NonExistentFile_ReturnsPathNotFound()
    {
        var protector = new PacProtector(new PacSection { Allowed = true });
        var r = protector.Initialize(Path.Combine(_workDir, "nope.pac"));
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.PathNotFound, r.ErrorCode);
    }

    [Fact]
    public void Initialize_FileUrl_ResolvesToLocalPath()
    {
        var protector = new PacProtector(new PacSection { Allowed = true });
        var fileUrl = "file:///" + _pacPath.Replace(Path.DirectorySeparatorChar, '/');
        var r = protector.Initialize(fileUrl);
        Assert.True(r.IsSuccess);
    }

    [Fact]
    public void Initialize_HttpUrl_ReturnsPathNotFound()
    {
        var protector = new PacProtector(new PacSection { Allowed = true });
        var r = protector.Initialize("https://example.com/proxy.pac");
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.PathNotFound, r.ErrorCode);
    }

    [Fact]
    public void VerifyIntegrity_Unmodified_Succeeds()
    {
        var protector = new PacProtector(new PacSection { Allowed = true });
        protector.Initialize(_pacPath);
        var r = protector.VerifyIntegrity();
        Assert.True(r.IsSuccess);
    }

    [Fact]
    public void VerifyIntegrity_Modified_ReturnsHashMismatch()
    {
        var protector = new PacProtector(new PacSection { Allowed = true });
        protector.Initialize(_pacPath);
        // 篡改 PAC
        File.WriteAllText(_pacPath, "// tampered\nfunction FindProxyForURL(url, host){ return 'PROXY evil:8080'; }");
        var r = protector.VerifyIntegrity();
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.HashMismatch, r.ErrorCode);
    }

    [Fact]
    public void VerifyIntegrity_FileDeleted_ReturnsPathNotFound()
    {
        var protector = new PacProtector(new PacSection { Allowed = true });
        protector.Initialize(_pacPath);
        File.Delete(_pacPath);
        var r = protector.VerifyIntegrity();
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.PathNotFound, r.ErrorCode);
    }

    [Fact]
    public void Restore_CorrectContent_Succeeds()
    {
        var original = File.ReadAllText(_pacPath);
        var protector = new PacProtector(new PacSection { Allowed = true });
        protector.Initialize(_pacPath);
        // 篡改后恢复
        File.WriteAllText(_pacPath, "// tampered");
        Assert.False(protector.VerifyIntegrity().IsSuccess);
        var r = protector.Restore(original);
        Assert.True(r.IsSuccess);
        Assert.True(protector.VerifyIntegrity().IsSuccess);
    }

    [Fact]
    public void Restore_WrongContent_ReturnsHashMismatch()
    {
        var protector = new PacProtector(new PacSection { Allowed = true });
        protector.Initialize(_pacPath);
        var r = protector.Restore("// wrong content");
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.HashMismatch, r.ErrorCode);
    }

    [Fact]
    public void StartMonitoring_WithoutInitialize_ReturnsInvalidParameter()
    {
        var protector = new PacProtector(new PacSection { Allowed = true });
        var r = protector.StartMonitoring();
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.InvalidParameter, r.ErrorCode);
    }

    [Fact]
    public void StartMonitoring_AfterInitialize_Succeeds()
    {
        var protector = new PacProtector(new PacSection { Allowed = true });
        protector.Initialize(_pacPath);
        var r = protector.StartMonitoring();
        Assert.True(r.IsSuccess);
    }
}
