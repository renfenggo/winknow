using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Winknow.Core;
using Winknow.Core.Results;

namespace Winknow.Security;

/// <summary>
/// 设备日志密钥生成器：每台设备独立生成 AES-256 日志加密密钥和 HMAC-SHA256 检查点密钥。
/// 密钥由 DPAPI Machine Scope 保护后持久化，明文仅在内存中使用。
/// 验收项：客户端不包含签名私钥（日志密钥是设备独立的，非签名私钥）。
/// </summary>
public sealed class DeviceLogKeyGenerator
{
    private readonly ILogger<DeviceLogKeyGenerator>? _logger;
    private readonly string _keyDir;

    /// <summary>日志加密密钥文件名。</summary>
    public const string LogEncryptionKeyFile = "log_enc.key";

    /// <summary>日志检查点 HMAC 密钥文件名。</summary>
    public const string LogCheckpointKeyFile = "log_hmac.key";

    /// <summary>DPAPI 熵值（额外保护，基于设备 ID）。</summary>
    private readonly byte[] _entropy;

    /// <summary>
    /// 创建密钥生成器。
    /// </summary>
    /// <param name="keyDir">密钥存储目录（通常在 ProgramData\Winknow\keys）。</param>
    /// <param name="deviceId">设备标识（用于 DPAPI 熵值）。</param>
    /// <param name="logger">可选日志。</param>
    public DeviceLogKeyGenerator(string keyDir, string deviceId, ILogger<DeviceLogKeyGenerator>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyDir);
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);

        _keyDir = keyDir;
        _logger = logger;
        _entropy = System.Text.Encoding.UTF8.GetBytes(deviceId);
    }

    /// <summary>
    /// 获取或生成日志加密密钥（AES-256，32 字节）。
    /// 首次调用时生成新密钥并 DPAPI 保护后存储，后续调用从文件加载。
    /// </summary>
    public Result<byte[]> GetOrCreateLogEncryptionKey()
    {
        var path = Path.Combine(_keyDir, LogEncryptionKeyFile);
        return GetOrCreateKey(path, 32);  // AES-256
    }

    /// <summary>
    /// 获取或生成日志检查点 HMAC 密钥（HMAC-SHA256，32 字节）。
    /// </summary>
    public Result<byte[]> GetOrCreateLogCheckpointKey()
    {
        var path = Path.Combine(_keyDir, LogCheckpointKeyFile);
        return GetOrCreateKey(path, 32);  // HMAC-SHA256
    }

    /// <summary>
    /// 生成设备密钥清单（包含所有密钥的用途声明）。
    /// </summary>
    public KeyManifest GenerateManifest(string deviceId)
    {
        return KeyManifest.CreateDefault(deviceId);
    }

    /// <summary>
    /// 检查密钥文件是否已存在（不生成新密钥）。
    /// </summary>
    public bool KeysExist()
    {
        return File.Exists(Path.Combine(_keyDir, LogEncryptionKeyFile))
            && File.Exists(Path.Combine(_keyDir, LogCheckpointKeyFile));
    }

    private Result<byte[]> GetOrCreateKey(string path, int keySize)
    {
        try
        {
            // 尝试从现有文件加载
            if (File.Exists(path))
            {
                var loadResult = DpapiProtector.UnprotectFromFile(path, _entropy, _logger);
                if (loadResult.IsSuccess && loadResult.Data!.Length == keySize)
                {
                    return Result<byte[]>.Success(loadResult.Data);
                }
                _logger?.LogWarning("Existing key invalid, regenerating: {Path}", path);
            }

            // 生成新密钥
            var key = RandomNumberGenerator.GetBytes(keySize);
            try
            {
                var saveResult = DpapiProtector.ProtectToFile(path, key, _entropy, _logger);
                if (!saveResult.IsSuccess)
                {
                    CryptographicOperations.ZeroMemory(key);
                    return Result<byte[]>.Failure(saveResult.ErrorCode, saveResult.ErrorMessage);
                }
                _logger?.LogInformation("Generated new device key: {Path} ({Bits} bits)", path, keySize * 8);
                return Result<byte[]>.Success(key);
            }
            finally
            {
                // 返回的密钥副本由调用方管理生命周期
                // 此处不清零，因为 Result 持有引用
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to get or create key: {Path}", path);
            return Result<byte[]>.Failure(ErrorCode.EncryptionFailed, ex.Message);
        }
    }
}
