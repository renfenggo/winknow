using System.Security.Cryptography;
using System.Text.Json;
using Winknow.Core.Results;
using Winknow.TrustedUpdater;

namespace Winknow.TrustedUpdater.Tests;

/// <summary>
/// 第 7 周"清单 + 签名验证"测试。
/// 覆盖验收项：
/// - "TrustedUpdater 验证签名、产品标识、目标版本和文件 Hash"
/// - "更新包签名验证失败时拒绝安装"（VerifySignature 失败链路）
/// </summary>
public class ManifestAndVerifierTests
{
    [Fact]
    public void ToSignableJson_DoesNotContainSignatureField()
    {
        var (priv, _) = TestUpdatablePackage.NewRsaKeyPair();
        var m = TestUpdatablePackage.BuildSignedManifest(priv, files: new List<FileEntry>
        {
            new() { RelativePath = "a.txt", Sha256 = "deadbeef" }
        });

        var json = m.ToSignableJson();
        // 反序列化后 Signature 字段应为 null
        var parsed = JsonSerializer.Deserialize<UpdateManifest>(json, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
        Assert.NotNull(parsed);
        Assert.Null(parsed!.Signature);
        Assert.Equal("Winknow.V7", parsed.ProductId);
        Assert.Single(parsed.Files);
    }

    [Fact]
    public void Parse_Roundtrips_AllFields()
    {
        var (priv, _) = TestUpdatablePackage.NewRsaKeyPair();
        var m = TestUpdatablePackage.BuildSignedManifest(priv, version: "7.0.2",
            rollbackBlacklist: new List<string> { "7.0.0-broken" },
            components: new Dictionary<string, string> { ["ControlService"] = "7.0.2" },
            files: new List<FileEntry> { new() { RelativePath = "x.dll", Sha256 = "abc" } });

        var json = JsonSerializer.Serialize(m, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        });

        var parsed = UpdateManifest.Parse(json);
        Assert.Equal("7.0.2", parsed.Version);
        Assert.Equal("Winknow.V7", parsed.ProductId);
        Assert.Contains("7.0.0-broken", parsed.RollbackBlacklist);
        Assert.Equal("abc", parsed.Files[0].Sha256);
        Assert.False(string.IsNullOrWhiteSpace(parsed.Signature));
    }

    [Fact]
    public void VerifySignature_ValidSignature_Succeeds()
    {
        var (priv, pub) = TestUpdatablePackage.NewRsaKeyPair();
        var m = TestUpdatablePackage.BuildSignedManifest(priv);
        var r = PackageVerifier.VerifySignature(m, pub);
        Assert.True(r.IsSuccess);
    }

    [Fact]
    public void VerifySignature_UnsignedManifest_ReturnsSignatureInvalid()
    {
        var (_, pub) = TestUpdatablePackage.NewRsaKeyPair();
        var m = TestUpdatablePackage.BuildSignedManifest(RSA.Create(2048));
        m.Signature = null;
        var r = PackageVerifier.VerifySignature(m, pub);
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.SignatureInvalid, r.ErrorCode);
    }

    [Fact]
    public void VerifySignature_TamperedManifest_ReturnsSignatureInvalid()
    {
        var (priv, pub) = TestUpdatablePackage.NewRsaKeyPair();
        var m = TestUpdatablePackage.BuildSignedManifest(priv, version: "7.0.1");
        // 篡改：签名后再改版本号（与签名数据不匹配）
        m.Version = "7.0.99";
        var r = PackageVerifier.VerifySignature(m, pub);
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.SignatureInvalid, r.ErrorCode);
    }

    [Fact]
    public void VerifySignature_WrongPublicKey_ReturnsSignatureInvalid()
    {
        var (priv, _) = TestUpdatablePackage.NewRsaKeyPair();
        var (_, otherPub) = TestUpdatablePackage.NewRsaKeyPair();
        var m = TestUpdatablePackage.BuildSignedManifest(priv);
        var r = PackageVerifier.VerifySignature(m, otherPub);
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.SignatureInvalid, r.ErrorCode);
    }

    [Fact]
    public void VerifySignature_IllegalBase64_ReturnsSignatureInvalid()
    {
        var (priv, pub) = TestUpdatablePackage.NewRsaKeyPair();
        var m = TestUpdatablePackage.BuildSignedManifest(priv);
        m.Signature = "!!!not-base64!!!";
        var r = PackageVerifier.VerifySignature(m, pub);
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.SignatureInvalid, r.ErrorCode);
    }

    [Fact]
    public void VerifyProduct_MatchingId_Succeeds()
    {
        var (priv, _) = TestUpdatablePackage.NewRsaKeyPair();
        var m = TestUpdatablePackage.BuildSignedManifest(priv);
        var r = PackageVerifier.VerifyProduct(m, TestUpdatablePackage.ProductId);
        Assert.True(r.IsSuccess);
    }

    [Fact]
    public void VerifyProduct_MismatchedId_ReturnsInvalidArgument()
    {
        var (priv, _) = TestUpdatablePackage.NewRsaKeyPair();
        var m = TestUpdatablePackage.BuildSignedManifest(priv, productId: "Other.Product");
        var r = PackageVerifier.VerifyProduct(m, TestUpdatablePackage.ProductId);
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.InvalidArgument, r.ErrorCode);
    }

    [Fact]
    public void VerifyProduct_CaseInsensitive_Succeeds()
    {
        var (priv, _) = TestUpdatablePackage.NewRsaKeyPair();
        var m = TestUpdatablePackage.BuildSignedManifest(priv, productId: "winknow.v7");
        var r = PackageVerifier.VerifyProduct(m, TestUpdatablePackage.ProductId);
        Assert.True(r.IsSuccess);
    }
}
