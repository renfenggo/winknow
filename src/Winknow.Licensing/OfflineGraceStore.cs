using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Winknow.Licensing;

/// <summary>
/// 离线宽限存储：DPAPI缓存最近令牌（分钟级宽限）。
/// 扛网络抖动和学生机重启，断网宽限5分钟（可配）。
/// </summary>
public sealed class OfflineGraceStore
{
    private readonly string _storagePath;
    private readonly ILogger<OfflineGraceStore>? _logger;
    private readonly TimeSpan _gracePeriod = TimeSpan.FromMinutes(5); // 断网宽限5分钟（可配）

    /// <summary>
    /// 创建离线宽限存储。
    /// </summary>
    /// <param name="storagePath">存储路径（默认：ProgramData）。</param>
    /// <param name="logger">可选的日志记录器。</param>
    public OfflineGraceStore(
        string? storagePath = null,
        ILogger<OfflineGraceStore>? logger = null)
    {
        _storagePath = storagePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Winknow", "Licensing", "offline_grace.dat");

        _logger = logger;

        // 确保目录存在
        var directory = Path.GetDirectoryName(_storagePath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }

    /// <summary>
    /// 保存授权令牌到存储。
    /// </summary>
    public bool SaveToken(LicenseToken token)
    {
        try
        {
            var json = JsonSerializer.Serialize(token, new JsonSerializerOptions { WriteIndented = false });
            var encrypted = ProtectData(json);
            File.WriteAllBytes(_storagePath, encrypted);

            _logger?.LogInformation("Offline grace token saved, expires at {ExpiresAt}", token.ExpiresAt);
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to save offline grace token");
            return false;
        }
    }

    /// <summary>
    /// 从存储加载授权令牌。
    /// </summary>
    public LicenseToken? LoadToken()
    {
        try
        {
            if (!File.Exists(_storagePath))
            {
                _logger?.LogDebug("Offline grace token file not found");
                return null;
            }

            var encrypted = File.ReadAllBytes(_storagePath);
            var json = UnprotectData(encrypted);
            var token = JsonSerializer.Deserialize<LicenseToken>(json);

            if (token == null)
            {
                _logger?.LogWarning("Failed to deserialize offline grace token");
                return null;
            }

            // 检查是否过期
            if (token.IsExpired)
            {
                _logger?.LogWarning("Offline grace token expired at {ExpiresAt}", token.ExpiresAt);
                DeleteToken();
                return null;
            }

            _logger?.LogInformation("Offline grace token loaded, expires at {ExpiresAt}", token.ExpiresAt);
            return token;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to load offline grace token");
            return null;
        }
    }

    /// <summary>
    /// 删除存储的令牌。
    /// </summary>
    public void DeleteToken()
    {
        try
        {
            if (File.Exists(_storagePath))
            {
                File.Delete(_storagePath);
                _logger?.LogInformation("Offline grace token deleted");
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to delete offline grace token");
        }
    }

    /// <summary>
    /// 检查存储的令牌是否在宽限期内。
    /// </summary>
    public bool IsTokenInGracePeriod()
    {
        var token = LoadToken();
        if (token == null)
            return false;

        var remainingTime = token.ExpiresAt - DateTime.UtcNow;
        return remainingTime > TimeSpan.Zero && remainingTime <= _gracePeriod;
    }

    /// <summary>
    /// 使用DPAPI保护数据。
    /// </summary>
    private byte[] ProtectData(string data)
    {
        var bytes = Encoding.UTF8.GetBytes(data);
        return ProtectedData.Protect(bytes, null, DataProtectionScope.LocalMachine);
    }

    /// <summary>
    /// 使用DPAPI解密数据。
    /// </summary>
    private string UnprotectData(byte[] encryptedData)
    {
        var bytes = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.LocalMachine);
        return Encoding.UTF8.GetString(bytes);
    }
}