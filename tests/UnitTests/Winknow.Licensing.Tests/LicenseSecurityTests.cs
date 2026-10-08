using System.Security.Cryptography;
using Winknow.Core.Results;
using Winknow.Licensing;
using Winknow.Security;

namespace Winknow.Licensing.Tests;

/// <summary>
/// R04（审查 2026-10-07）授权安全回归：
/// 令牌真实 RSA 验签（伪签名/错误公钥/过期/设备不匹配/未签名拒绝）；
/// 教师端未配置签发密钥时 fail-closed；固定解锁码复用维护密码
/// Argon2id 校验（任意八位密码拒绝）。
/// </summary>
public sealed class LicenseTokenTests : IDisposable
{
    private readonly RSA _issuerKey = RSA.Create(2048);   // 教师端（签发方）
    private readonly RSA _otherKey = RSA.Create(2048);    // 攻击者/错误公钥

    public void Dispose()
    {
        _issuerKey.Dispose();
        _otherKey.Dispose();
    }

    [Fact(DisplayName = "教师端签名令牌可通过配对公钥验签")]
    public void SignedToken_VerifiesWithPairedKey()
    {
        var token = LicenseToken.Sign(
            LicenseToken.Create("device-001", validityMinutes: 30), _issuerKey);

        Assert.True(token.VerifySignature(_issuerKey));
    }

    [Fact(DisplayName = "未签名令牌拒绝（旧缺陷：任意非空签名即通过）")]
    public void UnsignedToken_Rejected()
    {
        var token = LicenseToken.Create("device-001", validityMinutes: 30);

        Assert.False(token.VerifySignature(_issuerKey));
        Assert.False(token.VerifySignature(string.Empty));
    }

    [Fact(DisplayName = "伪签名（SHA256 哈希冒充，旧 SignToken 桩产物）拒绝")]
    public void ForgedSignature_Rejected()
    {
        var unsigned = LicenseToken.Create("device-001", validityMinutes: 30);
        var forged = Convert.ToBase64String(
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(unsigned.ToSignableData())));
        var token = new LicenseToken
        {
            DeviceId = unsigned.DeviceId,
            IssuedAt = unsigned.IssuedAt,
            ValidityMinutes = unsigned.ValidityMinutes,
            Signature = forged
        };

        Assert.False(token.VerifySignature(_issuerKey));
    }

    [Fact(DisplayName = "错误公钥拒绝")]
    public void WrongKey_Rejected()
    {
        var token = LicenseToken.Sign(
            LicenseToken.Create("device-001", validityMinutes: 30), _issuerKey);

        Assert.False(token.VerifySignature(_otherKey));
    }

    [Fact(DisplayName = "过期令牌完整校验拒绝")]
    public void ExpiredToken_VerifyRejected()
    {
        var expired = new LicenseToken
        {
            DeviceId = "device-001",
            IssuedAt = DateTime.UtcNow.AddHours(-2),
            ValidityMinutes = 30
        };
        var token = LicenseToken.Sign(expired, _issuerKey);

        Assert.True(token.IsExpired);
        Assert.False(token.Verify(_issuerKey, "device-001"));
    }

    [Fact(DisplayName = "设备不匹配令牌完整校验拒绝（防跨设备重放）")]
    public void DeviceMismatch_VerifyRejected()
    {
        var token = LicenseToken.Sign(
            LicenseToken.Create("device-001", validityMinutes: 30), _issuerKey);

        Assert.False(token.Verify(_issuerKey, "device-002"));
        Assert.True(token.Verify(_issuerKey, "device-001"));
    }

    [Fact(DisplayName = "XML 公钥重载：合法通过，非法 XML/空串返回 false")]
    public void PublicKeyXmlOverload_Behaves()
    {
        var token = LicenseToken.Sign(
            LicenseToken.Create("device-001", validityMinutes: 30), _issuerKey);
        var publicXml = _issuerKey.ToXmlString(includePrivateParameters: false);

        Assert.True(token.VerifySignature(publicXml));
        Assert.False(token.VerifySignature("not-a-valid-xml-key"));
        Assert.False(token.VerifySignature(""));
        Assert.False(token.VerifySignature(_otherKey.ToXmlString(includePrivateParameters: false)));
    }
}

public sealed class TeacherLicenseServerTests : IDisposable
{
    private readonly RSA _signingKey = RSA.Create(2048);

    public void Dispose() => _signingKey.Dispose();

    [Fact(DisplayName = "未配置签发密钥：令牌签发 fail-closed（InvalidConfiguration）")]
    public void NoSigningKey_IssuanceDisabled()
    {
        var server = new TeacherLicenseServer();

        var result = server.VerifyAndIssueToken("test-device-001");

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.InvalidConfiguration, result.ErrorCode);
    }

    [Fact(DisplayName = "配置签发密钥：签发令牌可被配对公钥验签")]
    public void WithSigningKey_IssuesVerifiableToken()
    {
        var server = new TeacherLicenseServer(signingKey: _signingKey);

        var result = server.VerifyAndIssueToken("test-device-001");

        Assert.True(result.IsSuccess, result.ErrorMessage);
        using var publicKey = RSA.Create();
        publicKey.FromXmlString(_signingKey.ToXmlString(includePrivateParameters: false));
        Assert.True(result.Data!.Verify(publicKey, "test-device-001"));
    }

    [Fact(DisplayName = "未授权设备与锁定设备拒绝签发")]
    public async Task UnauthorizedDevice_Rejected()
    {
        await Task.CompletedTask;
        var server = new TeacherLicenseServer(signingKey: _signingKey);

        var unknown = server.VerifyAndIssueToken("unknown-device");
        Assert.False(unknown.IsSuccess);
        Assert.Equal(ErrorCode.Unauthorized, unknown.ErrorCode);

        server.LockDevice("test-device-001");
        var locked = server.VerifyAndIssueToken("test-device-001");
        Assert.False(locked.IsSuccess);
        Assert.Equal(ErrorCode.Unauthorized, locked.ErrorCode);
    }
}

public sealed class LicenseEnforcementTests : IDisposable
{
    private readonly RSA _issuerKey = RSA.Create(2048);
    private readonly string _gracePath;

    public LicenseEnforcementTests()
    {
        _gracePath = Path.Combine(Path.GetTempPath(),
            "winknow-grace-" + Guid.NewGuid().ToString("N") + ".dat");
    }

    public void Dispose()
    {
        _issuerKey.Dispose();
        if (File.Exists(_gracePath))
        {
            File.Delete(_gracePath);
        }
    }

    /// <summary>可控 ILicenseProvider 桩：返回预置令牌（模拟教师机响应被伪造或可信）。</summary>
    private sealed class StubProvider : ILicenseProvider
    {
        public LicenseToken? NextToken { get; set; }

        public Task<Result<LicenseToken>> VerifyLicenseAsync(
            string deviceId, CancellationToken cancellationToken = default)
            => Task.FromResult(Result<LicenseToken>.Success(NextToken!));

        public Task<bool> IsDeviceAuthorizedAsync(
            string deviceId, CancellationToken cancellationToken = default)
            => Task.FromResult(true);

        public Task<Result<string>> GenerateDynamicCodeAsync(
            string deviceId, CancellationToken cancellationToken = default)
            => Task.FromResult(Result<string>.Success("123456"));
    }

    private LicenseEnforcement Create(
        StubProvider provider,
        RSA? publicKey = null,
        string deviceId = "",
        string? maintenanceHash = null,
        bool isProduction = false)
        => new(
            new DeviceLicenseClient(provider, deviceId),
            new OfflineGraceStore(_gracePath),
            tokenPublicKey: publicKey,
            deviceId: deviceId,
            maintenancePasswordHash: maintenanceHash,
            isProduction: isProduction);

    [Fact(DisplayName = "任意八位密码不再放行（旧缺陷：长度>=8 即通过）")]
    public void FixedCode_ArbitraryLength8_Rejected()
    {
        var hash = MaintenancePassword.Hash("real-maintenance-password-2026");
        var enforcement = Create(
            new StubProvider(), maintenanceHash: hash);

        Assert.False(enforcement.VerifyFixedCode("abcdefgh"));
        Assert.False(enforcement.VerifyFixedCode("12345678"));
        Assert.False(enforcement.VerifyFixedCode(""));
        Assert.False(enforcement.VerifyFixedCode("real-maintenance-password-2026-wrong"));
    }

    [Fact(DisplayName = "正确维护密码通过")]
    public void FixedCode_CorrectPassword_Accepted()
    {
        var hash = MaintenancePassword.Hash("real-maintenance-password-2026");
        var enforcement = Create(
            new StubProvider(), maintenanceHash: hash);

        Assert.True(enforcement.VerifyFixedCode("real-maintenance-password-2026"));
    }

    [Fact(DisplayName = "未配置维护密码哈希：固定解锁恒拒绝（fail-closed）")]
    public void FixedCode_Unconfigured_AlwaysRejected()
    {
        var enforcement = Create(new StubProvider());

        Assert.False(enforcement.VerifyFixedCode("abcdefgh"));
        Assert.False(enforcement.VerifyFixedCode("any-password-at-all"));
    }

    [Fact(DisplayName = "在线刷新返回伪签名令牌：拒绝并锁定")]
    public async Task ForgedOnlineToken_LocksDown()
    {
        var unsigned = LicenseToken.Create("device-001", validityMinutes: 30);
        var forged = new LicenseToken
        {
            DeviceId = unsigned.DeviceId,
            IssuedAt = unsigned.IssuedAt,
            ValidityMinutes = unsigned.ValidityMinutes,
            Signature = Convert.ToBase64String(
                SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(unsigned.ToSignableData())))
        };
        var enforcement = Create(
            new StubProvider { NextToken = forged },
            publicKey: _issuerKey,
            deviceId: "device-001");

        var status = await enforcement.CheckStatusAsync();

        Assert.Equal(LicenseEnforcementStatus.Locked, status);
    }

    [Fact(DisplayName = "在线刷新返回设备不匹配令牌：拒绝并锁定")]
    public async Task DeviceMismatchToken_LocksDown()
    {
        var token = LicenseToken.Sign(
            LicenseToken.Create("device-other", validityMinutes: 30), _issuerKey);
        var enforcement = Create(
            new StubProvider { NextToken = token },
            publicKey: _issuerKey,
            deviceId: "device-001");

        var status = await enforcement.CheckStatusAsync();

        Assert.Equal(LicenseEnforcementStatus.Locked, status);
    }

    [Fact(DisplayName = "真实签名令牌：在线通过")]
    public async Task SignedOnlineToken_StaysOnline()
    {
        var token = LicenseToken.Sign(
            LicenseToken.Create("device-001", validityMinutes: 30), _issuerKey);
        var enforcement = Create(
            new StubProvider { NextToken = token },
            publicKey: _issuerKey,
            deviceId: "device-001");

        var status = await enforcement.CheckStatusAsync();

        Assert.Equal(LicenseEnforcementStatus.Online, status);
    }

    [Fact(DisplayName = "P0 生产缺正式公钥：合法签名令牌也拒绝（fail-closed 锁定）")]
    public async Task Production_WithoutPublicKey_LocksDown()
    {
        // 即使签发方密钥正确、令牌未过期且设备匹配：生产模式未注入验签公钥
        // 时一律拒绝（旧缺陷：退化为仅过期检查，伪签名令牌可上线）。
        var token = LicenseToken.Sign(
            LicenseToken.Create("device-001", validityMinutes: 30), _issuerKey);
        var enforcement = Create(
            new StubProvider { NextToken = token },
            publicKey: null,
            deviceId: "device-001",
            isProduction: true);

        var status = await enforcement.CheckStatusAsync();

        Assert.Equal(LicenseEnforcementStatus.Locked, status);
    }
}
