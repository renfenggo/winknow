using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Winknow.Core.Results;

namespace Winknow.Security;

/// <summary>
/// DPAPI Machine Scope 封装：用于保护设备本地密钥（日志加密密钥等）。
/// 安全约束：Machine Scope 允许同机任何进程解密，但跨设备/跨用户不可解密。
/// 不用于保护密码（密码用 Argon2id）或签名私钥（在 HSM）。
/// </summary>
public static class DpapiProtector
{
    /// <summary>
    /// 使用 DPAPI Machine Scope 加密数据。
    /// </summary>
    /// <param name="plaintext">明文字节。</param>
    /// <param name="optionalEntropy">可选熵值（额外密钥，增强保护）。</param>
    /// <returns>加密后的字节数组。</returns>
    public static byte[] Protect(byte[] plaintext, byte[]? optionalEntropy = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return ProtectedData.Protect(plaintext, optionalEntropy, DataProtectionScope.LocalMachine);
    }

    /// <summary>
    /// 使用 DPAPI Machine Scope 解密数据。
    /// </summary>
    /// <param name="ciphertext">密文字节。</param>
    /// <param name="optionalEntropy">可选熵值（必须与加密时一致）。</param>
    /// <returns>解密后的字节数组。</returns>
    public static byte[] Unprotect(byte[] ciphertext, byte[]? optionalEntropy = null)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        return ProtectedData.Unprotect(ciphertext, optionalEntropy, DataProtectionScope.LocalMachine);
    }

    /// <summary>
    /// 加密数据并持久化到文件（DPAPI Machine Scope）。
    /// </summary>
    /// <param name="filePath">目标文件路径。</param>
    /// <param name="plaintext">明文字节。</param>
    /// <param name="optionalEntropy">可选熵值。</param>
    /// <param name="logger">可选日志。</param>
    public static Result ProtectToFile(string filePath, byte[] plaintext, byte[]? optionalEntropy = null, ILogger? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        ArgumentNullException.ThrowIfNull(plaintext);

        try
        {
            var dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var ciphertext = Protect(plaintext, optionalEntropy);
            File.WriteAllBytes(filePath, ciphertext);
            logger?.LogInformation("Protected data written to {Path} ({Bytes} bytes ciphertext)", filePath, ciphertext.Length);
            return Result.Success();
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to protect data to file {Path}", filePath);
            return Result.Failure(ErrorCode.EncryptionFailed, ex.Message);
        }
    }

    /// <summary>
    /// 从文件读取并解密数据（DPAPI Machine Scope）。
    /// </summary>
    /// <param name="filePath">源文件路径。</param>
    /// <param name="optionalEntropy">可选熵值（必须与加密时一致）。</param>
    /// <param name="logger">可选日志。</param>
    /// <returns>解密后的明文字节，失败返回 null。</returns>
    public static Result<byte[]> UnprotectFromFile(string filePath, byte[]? optionalEntropy = null, ILogger? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        try
        {
            if (!File.Exists(filePath))
            {
                return Result<byte[]>.Failure(ErrorCode.PathNotFound, $"密钥文件不存在: {filePath}");
            }

            var ciphertext = File.ReadAllBytes(filePath);
            var plaintext = Unprotect(ciphertext, optionalEntropy);
            logger?.LogInformation("Protected data read from {Path} ({Bytes} bytes plaintext)", filePath, plaintext.Length);
            return Result<byte[]>.Success(plaintext);
        }
        catch (CryptographicException ex)
        {
            logger?.LogError(ex, "DPAPI unprotect failed for {Path}（可能跨设备迁移）", filePath);
            return Result<byte[]>.Failure(ErrorCode.EncryptionFailed, ex.Message);
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to read protected file {Path}", filePath);
            return Result<byte[]>.Failure(ErrorCode.Unknown, ex.Message);
        }
    }
}
