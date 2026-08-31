namespace Winknow.Licensing;

/// <summary>
/// 授权令牌：DeviceId + 签发时间 + 有效期 + 签名（防伪造）。
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

    /// <summary>创建新令牌。</summary>
    public static LicenseToken Create(string deviceId, int validityMinutes)
    {
        return new LicenseToken
        {
            DeviceId = deviceId,
            IssuedAt = DateTime.UtcNow,
            ValidityMinutes = validityMinutes
        };
    }

    /// <summary>验证签名是否有效。</summary>
    /// <param name="publicKey">公钥（简化版本）。</param>
    /// <returns>签名是否有效。</returns>
    public bool VerifySignature(string publicKey)
    {
        // TODO 第7周后实现真正的签名验证
        // 简化版本：检查签名字段是否存在
        return !string.IsNullOrEmpty(Signature);
    }
}