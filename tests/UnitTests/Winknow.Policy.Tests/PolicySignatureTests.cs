using System.Security.Cryptography;
using System.Text.Json;
using Winknow.Core.Results;
using Winknow.Policy;

namespace Winknow.Policy.Tests;

/// <summary>
/// R04（审查 2026-10-07）策略签名/验签回归：
/// 未签名/伪签名/篡改/错误公钥/公钥缺失一律拒绝；合法签名通过；
/// 格式重排（字段大小写/空白变化）不影响验签（可恢复配置）。
/// </summary>
public class PolicySignatureTests : IDisposable
{
    private readonly RSA _signingKey = RSA.Create(2048);
    private readonly RSA _otherKey = RSA.Create(2048);
    private readonly string _tempDir;
    private readonly PolicyLoader _loader = new();

    public PolicySignatureTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "winknow-policy-sig-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        _signingKey.Dispose();
        _otherKey.Dispose();
    }

    private static PolicyFile SamplePolicy() => new()
    {
        Version = "7.0.0",
        PolicyId = "sig-test-policy",
        CreatedAt = new DateTime(2026, 10, 7, 0, 0, 0, DateTimeKind.Utc),
        Description = "签名测试策略",
        SoftwareControl = new SoftwareControlSection
        {
            HighRiskInterpreters = new HighRiskInterpretersSection
            {
                Blocked = ["powershell.exe", "wscript.exe"]
            }
        }
    };

    private string WritePolicy(PolicyFile policy, JsonSerializerOptions? options = null)
    {
        var path = Path.Combine(_tempDir, $"policy-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, JsonSerializer.Serialize(policy, options));
        return path;
    }

    private static readonly JsonSerializerOptions Camel = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    [Fact(DisplayName = "合法签名策略验签通过")]
    public void SignedPolicy_LoadsWithValidation()
    {
        var signed = new PolicyFile
        {
            Version = SamplePolicy().Version,
            PolicyId = SamplePolicy().PolicyId,
            CreatedAt = SamplePolicy().CreatedAt,
            Description = SamplePolicy().Description,
            SoftwareControl = SamplePolicy().SoftwareControl,
            Signature = PolicySigner.Sign(SamplePolicy(), _signingKey)
        };
        var path = WritePolicy(signed, Camel);

        var result = _loader.Load(path, validateSignature: true, publicKey: _signingKey);

        Assert.True(result.IsSuccess, result.ErrorMessage);
        Assert.Equal("sig-test-policy", result.Data!.PolicyId);
    }

    [Fact(DisplayName = "未签名策略在 validateSignature=true 时拒绝（旧缺陷：直接放行）")]
    public void UnsignedPolicy_RejectedWhenValidationRequested()
    {
        var path = WritePolicy(SamplePolicy(), Camel);

        var result = _loader.Load(path, validateSignature: true, publicKey: _signingKey);

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.PolicySignatureInvalid, result.ErrorCode);
    }

    [Fact(DisplayName = "内容篡改被拒绝（改 Description）")]
    public void TamperedPolicy_Rejected()
    {
        var policy = SamplePolicy();
        var signed = new PolicyFile
        {
            Version = policy.Version,
            PolicyId = policy.PolicyId,
            CreatedAt = policy.CreatedAt,
            Description = policy.Description,
            SoftwareControl = policy.SoftwareControl,
            Signature = PolicySigner.Sign(policy, _signingKey)
        };
        // 落盘后篡改描述字段（保持签名不变）
        var tampered = new PolicyFile
        {
            Version = signed.Version,
            PolicyId = signed.PolicyId,
            CreatedAt = signed.CreatedAt,
            Description = "被学生篡改的策略",
            SoftwareControl = signed.SoftwareControl,
            Signature = signed.Signature
        };
        var path = WritePolicy(tampered, Camel);

        var result = _loader.Load(path, validateSignature: true, publicKey: _signingKey);

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.PolicySignatureInvalid, result.ErrorCode);
    }

    [Fact(DisplayName = "篡改管控区块被拒绝（放开 USB 管控）")]
    public void TamperedControlSection_Rejected()
    {
        var policy = SamplePolicy();
        var signed = new PolicyFile
        {
            Version = policy.Version,
            PolicyId = policy.PolicyId,
            CreatedAt = policy.CreatedAt,
            Description = policy.Description,
            SoftwareControl = policy.SoftwareControl,
            Signature = PolicySigner.Sign(policy, _signingKey)
        };
        var tampered = new PolicyFile
        {
            Version = signed.Version,
            PolicyId = signed.PolicyId,
            CreatedAt = signed.CreatedAt,
            Description = signed.Description,
            SoftwareControl = new SoftwareControlSection
            {
                HighRiskInterpreters = new HighRiskInterpretersSection { Blocked = [] }
            },
            Signature = signed.Signature
        };
        var path = WritePolicy(tampered, Camel);

        var result = _loader.Load(path, validateSignature: true, publicKey: _signingKey);

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.PolicySignatureInvalid, result.ErrorCode);
    }

    [Fact(DisplayName = "错误公钥拒绝（旧缺陷：任意非空签名即通过）")]
    public void WrongPublicKey_Rejected()
    {
        var policy = SamplePolicy();
        var signed = new PolicyFile
        {
            Version = policy.Version,
            PolicyId = policy.PolicyId,
            CreatedAt = policy.CreatedAt,
            Description = policy.Description,
            SoftwareControl = policy.SoftwareControl,
            Signature = PolicySigner.Sign(policy, _signingKey)
        };
        var path = WritePolicy(signed, Camel);

        var result = _loader.Load(path, validateSignature: true, publicKey: _otherKey);

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.PolicySignatureInvalid, result.ErrorCode);
    }

    [Fact(DisplayName = "validateSignature=true 但未提供公钥：fail-closed 拒绝")]
    public void MissingPublicKey_FailClosed()
    {
        var policy = SamplePolicy();
        var signed = new PolicyFile
        {
            Version = policy.Version,
            PolicyId = policy.PolicyId,
            CreatedAt = policy.CreatedAt,
            Description = policy.Description,
            SoftwareControl = policy.SoftwareControl,
            Signature = PolicySigner.Sign(policy, _signingKey)
        };
        var path = WritePolicy(signed, Camel);

        var result = _loader.Load(path, validateSignature: true, publicKey: null);

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.PolicySignatureInvalid, result.ErrorCode);
    }

    [Fact(DisplayName = "伪签名（非 RSA 签名数据）拒绝")]
    public void ForgedSignature_Rejected()
    {
        var policy = SamplePolicy();
        // 用 SHA256 哈希冒充签名（对应 TeacherLicenseServer 旧 SignToken 桩）
        var forged = Convert.ToBase64String(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(policy.ToSignableJson())));
        var signed = new PolicyFile
        {
            Version = policy.Version,
            PolicyId = policy.PolicyId,
            CreatedAt = policy.CreatedAt,
            Description = policy.Description,
            SoftwareControl = policy.SoftwareControl,
            Signature = forged
        };
        var path = WritePolicy(signed, Camel);

        var result = _loader.Load(path, validateSignature: true, publicKey: _signingKey);

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.PolicySignatureInvalid, result.ErrorCode);
    }

    [Fact(DisplayName = "字段大小写与空白重排不影响验签（可恢复配置）")]
    public void ReformattedPolicy_StillVerifies()
    {
        var policy = SamplePolicy();
        var signed = new PolicyFile
        {
            Version = policy.Version,
            PolicyId = policy.PolicyId,
            CreatedAt = policy.CreatedAt,
            Description = policy.Description,
            SoftwareControl = policy.SoftwareControl,
            Signature = PolicySigner.Sign(policy, _signingKey)
        };
        // PascalCase + 无缩进重写（内容等价，格式不同）
        var path = WritePolicy(signed, new JsonSerializerOptions { WriteIndented = false });

        var result = _loader.Load(path, validateSignature: true, publicKey: _signingKey);

        Assert.True(result.IsSuccess, result.ErrorMessage);
    }

    [Fact(DisplayName = "仓库默认策略已签名且可通过信任锚公钥验签")]
    public void DefaultPolicy_SignedAndTrusted()
    {
        var policyPath = Path.Combine(
            AppContext.BaseDirectory, "policies", "default_policy_v7.0.json");
        if (!File.Exists(policyPath))
        {
            return; // 测试环境跳过
        }

        using var publicKey = PolicyTrustAnchor.CreatePublicKey();
        var result = _loader.Load(policyPath, validateSignature: true, publicKey);

        Assert.True(result.IsSuccess, result.ErrorMessage);
        Assert.Equal("default-classroom-v1", result.Data!.PolicyId);
    }

    // ------------------------------------------------------------------
    // P0 生产收紧（2026-10-07）：生产禁止回退 dev 公钥，缺正式公钥拒绝启用管控
    // ------------------------------------------------------------------

    [Fact(DisplayName = "生产模式缺正式公钥：信任锚直接拒绝（不回退 dev）")]
    public void Production_WithoutOfficialKey_Throws()
    {
        var original = Environment.GetEnvironmentVariable(PolicyTrustAnchor.PublicKeyXmlEnvVar);
        try
        {
            Environment.SetEnvironmentVariable(PolicyTrustAnchor.PublicKeyXmlEnvVar, null);

            Assert.Throws<InvalidOperationException>(() =>
                PolicyTrustAnchor.CreatePublicKey(null, allowDevKeyFallback: false));
        }
        finally
        {
            Environment.SetEnvironmentVariable(PolicyTrustAnchor.PublicKeyXmlEnvVar, original);
        }
    }

    [Fact(DisplayName = "生产配正式公钥后：开发钥签名的默认策略被拒绝")]
    public void DevSignedDefaultPolicy_RejectedUnderOfficialKey()
    {
        var policyPath = Path.Combine(
            AppContext.BaseDirectory, "policies", "default_policy_v7.0.json");
        if (!File.Exists(policyPath))
        {
            return; // 测试环境跳过
        }

        // _signingKey 充当正式公钥：仓库默认策略为 dev 钥签名 → 验签必败
        var result = _loader.Load(policyPath, validateSignature: true, publicKey: _signingKey);

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.PolicySignatureInvalid, result.ErrorCode);
    }

    [Fact(DisplayName = "生产模式经环境变量注入正式公钥：导入成功且正式签名策略通过")]
    public void Production_OfficialKeyFromEnvVar_Works()
    {
        var original = Environment.GetEnvironmentVariable(PolicyTrustAnchor.PublicKeyXmlEnvVar);
        try
        {
            Environment.SetEnvironmentVariable(
                PolicyTrustAnchor.PublicKeyXmlEnvVar, _signingKey.ToXmlString(false));

            using var publicKey = PolicyTrustAnchor.CreatePublicKey(null, allowDevKeyFallback: false);
            var policy = SamplePolicy();
            var signed = new PolicyFile
            {
                Version = policy.Version,
                PolicyId = policy.PolicyId,
                CreatedAt = policy.CreatedAt,
                Description = policy.Description,
                SoftwareControl = policy.SoftwareControl,
                Signature = PolicySigner.Sign(policy, _signingKey)
            };
            var path = WritePolicy(signed, Camel);

            var result = _loader.Load(path, validateSignature: true, publicKey);

            Assert.True(result.IsSuccess, result.ErrorMessage);
        }
        finally
        {
            Environment.SetEnvironmentVariable(PolicyTrustAnchor.PublicKeyXmlEnvVar, original);
        }
    }
}
