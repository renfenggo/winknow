using System.Text.Json.Serialization;

namespace Winknow.Security;

/// <summary>
/// 密钥清单：声明本设备所有密钥的用途、来源和存储位置。
/// 验收项：客户端不包含签名私钥（本清单仅声明公钥标识，私钥在 HSM/Token）。
/// </summary>
public sealed class KeyManifest
{
    /// <summary>设备唯一标识（由机器特征生成）。</summary>
    public string DeviceId { get; init; } = string.Empty;

    /// <summary>密钥条目列表。</summary>
    public List<KeyEntry> Keys { get; init; } = new();

    /// <summary>清单生成时间（ISO 8601）。</summary>
    public string CreatedAt { get; init; } = DateTimeOffset.UtcNow.ToString("O");

    /// <summary>
    /// 创建默认密钥清单（包含签名公钥标识、日志密钥、TOTP 密钥、恢复码哈希）。
    /// </summary>
    public static KeyManifest CreateDefault(string deviceId) => new()
    {
        DeviceId = deviceId,
        Keys = new List<KeyEntry>
        {
            new()
            {
                Name = "CodeSigning",
                Purpose = KeyPurpose.CodeSigning,
                Source = KeySource.ExternalHsm,
                StorageLocation = "HSM/Token（客户端仅持公钥验签）",
                ContainsPrivateKey = false
            },
            new()
            {
                Name = "LogEncryption",
                Purpose = KeyPurpose.LogEncryption,
                Source = KeySource.DeviceGenerated,
                StorageLocation = "DPAPI Machine Scope 保护",
                ContainsPrivateKey = true,
                Algorithm = "AES-256-GCM"
            },
            new()
            {
                Name = "LogCheckpoint",
                Purpose = KeyPurpose.LogCheckpoint,
                Source = KeySource.DeviceGenerated,
                StorageLocation = "DPAPI Machine Scope 保护",
                ContainsPrivateKey = true,
                Algorithm = "HMAC-SHA256"
            },
            new()
            {
                Name = "Totp",
                Purpose = KeyPurpose.Totp,
                Source = KeySource.AdminProvisioned,
                StorageLocation = "DPAPI Machine Scope 保护",
                ContainsPrivateKey = true,
                Algorithm = "HMAC-SHA1"
            },
            new()
            {
                Name = "RecoveryCodes",
                Purpose = KeyPurpose.RecoveryCodes,
                Source = KeySource.AdminProvisioned,
                StorageLocation = "SHA-256 哈希存储（明文不持久化）",
                ContainsPrivateKey = false,
                Algorithm = "SHA-256"
            }
        }
    };
}

/// <summary>
/// 密钥条目。
/// </summary>
public sealed class KeyEntry
{
    /// <summary>密钥名称。</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>密钥用途。</summary>
    public KeyPurpose Purpose { get; init; }

    /// <summary>密钥来源。</summary>
    public KeySource Source { get; init; }

    /// <summary>存储位置说明。</summary>
    public string StorageLocation { get; init; } = string.Empty;

    /// <summary>是否包含私钥（签名密钥在客户端仅持公钥）。</summary>
    public bool ContainsPrivateKey { get; init; }

    /// <summary>算法标识。</summary>
    public string? Algorithm { get; init; }
}

/// <summary>
/// 密钥用途分类。
/// </summary>
public enum KeyPurpose
{
    /// <summary>代码签名（更新包签名验证，客户端仅持公钥）。</summary>
    CodeSigning,
    /// <summary>日志加密（AES-GCM 敏感正文加密）。</summary>
    LogEncryption,
    /// <summary>日志检查点签名（HMAC-SHA256 防截断）。</summary>
    LogCheckpoint,
    /// <summary>TOTP 密钥（HMAC-SHA1）。</summary>
    Totp,
    /// <summary>恢复码哈希（SHA-256）。</summary>
    RecoveryCodes
}

/// <summary>
/// 密钥来源。
/// </summary>
public enum KeySource
{
    /// <summary>外部 HSM/Token（签名公钥来自受控构建环境）。</summary>
    ExternalHsm,
    /// <summary>设备本地生成（首次运行时生成，DPAPI 保护）。</summary>
    DeviceGenerated,
    /// <summary>管理员配置（通过安全通道下发）。</summary>
    AdminProvisioned
}
