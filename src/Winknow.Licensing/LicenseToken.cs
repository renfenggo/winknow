using System.Security.Cryptography;
using System.Text;

namespace Winknow.Licensing;

/// <summary>
/// 授权令牌：DeviceId + 签发时间 + 有效期 + 签名（防伪造）。
///
/// R04（审查 2026-10-07）：签名方案落地为 RSA-SHA256 + PKCS#1 v1.5，
/// 对 ToSignableData()（DeviceId|IssuedAt("O")|ValidityMinutes）的
/// UTF-8 字节签名，base64 存储。仅有私钥的教师端/服务端可签发，
/// 学生机用公钥验签——本地自签或伪签名一律无效。
/// </summary>
public sealed class LicenseToken
{
    /// <summary>设备唯一标识符。</summary>
    public string DeviceId { get; init; } = string.Empty;

    /// <summary>令牌签发时间（UTC）。</summary>
    public DateTime IssuedAt { get; init; }

    /// <summary>令牌有效期（分钟）。</summary>
    public int ValidityMinutes { get; init; }

    /// <summary>令牌过期时间（UTC）。</summary>
    public DateTime ExpiresAt => IssuedAt.AddMinutes(ValidityMinutes);

    /// <summary>签名（防伪造）。</summary>
    public string? Signature { get; init; }

    /// <summary>检查令牌是否过期。</summary>
    public bool IsExpired => DateTime.UtcNow > ExpiresAt;

    /// <summary>创建新令牌（未签名；签名须由持私钥方调用 Sign）。</summary>
    public static LicenseToken Create(string deviceId, int validityMinutes)
    {
        return new LicenseToken
        {
            DeviceId = deviceId,
            IssuedAt = DateTime.UtcNow,
            ValidityMinutes = validityMinutes
        };
    }

    /// <summary>
    /// 用私钥对令牌签名，返回携带签名的新令牌（原令牌不可变）。
    /// </summary>
    public static LicenseToken Sign(LicenseToken token, RSA privateKey)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(privateKey);
        var data = Encoding.UTF8.GetBytes(token.ToSignableData());
        var signature = privateKey.SignData(
            data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return new LicenseToken
        {
            DeviceId = token.DeviceId,
            IssuedAt = token.IssuedAt,
            ValidityMinutes = token.ValidityMinutes,
            Signature = Convert.ToBase64String(signature)
        };
    }

    /// <summary>签名的规范化载荷（确定性：字段顺序与格式固定）。</summary>
    public string ToSignableData() => $"{DeviceId}|{IssuedAt:O}|{ValidityMinutes}";

    /// <summary>
    /// 验证签名是否有效（R04：真实 RSA 验签，错误公钥/伪签名/未签名返回 false）。
    /// </summary>
    /// <param name="publicKeyXml">公钥 XML（RSA.ToXmlString(false) 格式）。</param>
    /// <returns>签名是否有效。</returns>
    public bool VerifySignature(string publicKeyXml)
    {
        if (string.IsNullOrEmpty(publicKeyXml) || string.IsNullOrEmpty(Signature))
            return false;

        try
        {
            using var rsa = RSA.Create();
            rsa.FromXmlString(publicKeyXml);
            return VerifySignature(rsa);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// 验证签名是否有效（RSA 对象重载）。
    /// </summary>
    public bool VerifySignature(RSA publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        if (string.IsNullOrEmpty(Signature))
            return false;

        byte[] signatureBytes;
        try
        {
            signatureBytes = Convert.FromBase64String(Signature);
        }
        catch (FormatException)
        {
            return false;
        }

        var data = Encoding.UTF8.GetBytes(ToSignableData());
        return publicKey.VerifyData(
            data, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    /// <summary>
    /// 完整校验（R04 验收）：签名有效 + 未过期 + 设备匹配。
    /// 任一不满足返回 false。
    /// </summary>
    /// <param name="publicKey">可信公钥。</param>
    /// <param name="expectedDeviceId">本机设备标识（令牌不得跨设备重放）。</param>
    public bool Verify(RSA publicKey, string expectedDeviceId)
    {
        if (string.IsNullOrEmpty(expectedDeviceId))
            return false;
        return !IsExpired
            && string.Equals(DeviceId, expectedDeviceId, StringComparison.Ordinal)
            && VerifySignature(publicKey);
    }
}
