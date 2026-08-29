using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Winknow.Core.Results;

namespace Winknow.Logging;

/// <summary>
/// 日志 AES-GCM 加密器：对敏感日志正文进行加密。
/// 验收项：密码、密钥、恢复码不进入普通日志（敏感字段加密后存储）。
/// 验收项：默认不记录网页正文和学生代码正文（调用方用 IsSensitive 判定后加密或拒绝）。
/// </summary>
public sealed class LogCipher : IDisposable
{
    private readonly byte[] _key;
    private readonly ILogger<LogCipher>? _logger;
    private bool _disposed;

    /// <summary>
    /// 创建日志加密器。
    /// </summary>
    /// <param name="key">AES-256 密钥（32 字节，由 DeviceLogKeyGenerator 生成）。</param>
    /// <param name="logger">可选日志。</param>
    public LogCipher(byte[] key, ILogger<LogCipher>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 32)
        {
            throw new ArgumentException("AES-256 密钥必须为 32 字节", nameof(key));
        }
        _key = key;
        _logger = logger;
    }

    /// <summary>
    /// 加密敏感日志正文，返回 Base64 编码的 nonce + ciphertext。
    /// </summary>
    /// <param name="plaintext">明文正文。</param>
    /// <returns>Base64(nonce || ciphertext || tag)。</returns>
    public string Encrypt(string plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(plaintext);

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(12);  // AES-GCM 推荐 12 字节
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[16];  // AES-GCM 标签

        try
        {
            var gcm = new AesGcm(_key, tagSizeInBytes: 16);
            // 参数顺序：nonce, plaintext, ciphertext, tag
            gcm.Encrypt(nonce, plaintextBytes, ciphertext, tag);

            // 合并 nonce + ciphertext + tag 便于存储
            var combined = new byte[nonce.Length + ciphertext.Length + tag.Length];
            Buffer.BlockCopy(nonce, 0, combined, 0, nonce.Length);
            Buffer.BlockCopy(ciphertext, 0, combined, nonce.Length, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, combined, nonce.Length + ciphertext.Length, tag.Length);

            return Convert.ToBase64String(combined);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "AES-GCM encryption failed");
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }
    }

    /// <summary>
    /// 解密日志正文。
    /// </summary>
    /// <param name="base64">Encrypt 返回的 Base64 字符串。</param>
    /// <returns>明文正文，失败返回 null。</returns>
    public Result<string> Decrypt(string base64)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(base64);

        try
        {
            var combined = Convert.FromBase64String(base64);
            if (combined.Length < 12 + 16)  // nonce + tag 最小长度
            {
                return Result<string>.Failure(ErrorCode.DecryptionFailed, "密文长度不足");
            }

            var nonce = new byte[12];
            var tag = new byte[16];
            var ciphertext = new byte[combined.Length - 12 - 16];

            Buffer.BlockCopy(combined, 0, nonce, 0, 12);
            Buffer.BlockCopy(combined, 12, ciphertext, 0, ciphertext.Length);
            Buffer.BlockCopy(combined, 12 + ciphertext.Length, tag, 0, 16);

            var plaintext = new byte[ciphertext.Length];
            var gcm = new AesGcm(_key, tagSizeInBytes: 16);
            gcm.Decrypt(nonce, ciphertext, tag, plaintext);

            return Result<string>.Success(Encoding.UTF8.GetString(plaintext));
        }
        catch (CryptographicException ex)
        {
            _logger?.LogError(ex, "AES-GCM decryption failed（密文被篡改或密钥不匹配）");
            return Result<string>.Failure(ErrorCode.DecryptionFailed, ex.Message);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Decryption error");
            return Result<string>.Failure(ErrorCode.Unknown, ex.Message);
        }
    }

    /// <summary>
    /// 判断日志字段是否为敏感数据（需加密或脱敏）。
    /// 验收项：密码、密钥、恢复码不进入普通日志。
    /// </summary>
    public static bool IsSensitive(string fieldName)
    {
        if (string.IsNullOrWhiteSpace(fieldName)) return false;
        var lower = fieldName.ToLowerInvariant();
        return lower.Contains("password")
            || lower.Contains("secret")
            || lower.Contains("privatekey")
            || lower.Contains("recoverycode")
            || lower.Contains("totpsecret")
            || lower.Contains("token");
    }

    /// <summary>
    /// 判断日志字段是否默认不记录（即使加密也不记录）。
    /// 验收项：默认不记录网页正文和学生代码正文。
    /// </summary>
    public static bool IsDefaultExcluded(string fieldName)
    {
        if (string.IsNullOrWhiteSpace(fieldName)) return false;
        var lower = fieldName.ToLowerInvariant();
        return lower.Contains("webpagecontent")
            || lower.Contains("sourcecode")
            || lower.Contains("studentcode")
            || lower.Contains("pagebody")
            || lower.Contains("htmlcontent");
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_key);
    }
}
