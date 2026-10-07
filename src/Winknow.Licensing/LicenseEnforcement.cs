using System.Security.Cryptography;
using Winknow.Security;
using Winknow.Core;
using Winknow.Core.Results;
using Microsoft.Extensions.Logging;

namespace Winknow.Licensing;

/// <summary>
/// 授权执行组件：三态机（在线/宽限中/锁定）。
///
/// R04（审查 2026-10-07）：
/// - 令牌验签：注入可信公钥（tokenPublicKey）后，在线刷新令牌与离线宽限
///   缓存令牌均须通过 RSA 验签（可选绑定本机 deviceId），伪签名/错误公钥/
///   过期/设备不匹配一律拒绝；
/// - 固定解锁码：复用 MaintenancePassword（Argon2id）校验，未配置维护
///   密码哈希时恒拒绝（fail-closed），移除按长度放行。
/// </summary>
public sealed class LicenseEnforcement
{
    private readonly DeviceLicenseClient _client;
    private readonly OfflineGraceStore _offlineGraceStore;
    private readonly ILogger<LicenseEnforcement>? _logger;
    private readonly TimeSpan _gracePeriod = TimeSpan.FromMinutes(5); // 断网宽限5分钟
    private readonly RSA? _tokenPublicKey;
    private readonly string _deviceId;
    private readonly string? _maintenancePasswordHash;

    private LicenseEnforcementStatus _currentStatus = LicenseEnforcementStatus.Online;
    private DateTime _lastCheckTime = DateTime.MinValue;

    /// <summary>当前授权状态。</summary>
    public LicenseEnforcementStatus CurrentStatus => _currentStatus;

    /// <summary>最后检查时间。</summary>
    public DateTime LastCheckTime => _lastCheckTime;

    /// <summary>
    /// 创建授权执行组件。
    /// </summary>
    /// <param name="client">授权客户端。</param>
    /// <param name="offlineGraceStore">离线宽限存储。</param>
    /// <param name="logger">可选的日志记录器。</param>
    /// <param name="tokenPublicKey">令牌验签公钥（生产装配必须注入；未注入时仅退化为过期检查并告警）。</param>
    /// <param name="deviceId">本机设备标识（非空时令牌不得跨设备重放）。</param>
    /// <param name="maintenancePasswordHash">维护密码 Argon2id 哈希（MaintenancePassword.Hash 输出；未配置则固定解锁不可用）。</param>
    public LicenseEnforcement(
        DeviceLicenseClient client,
        OfflineGraceStore offlineGraceStore,
        ILogger<LicenseEnforcement>? logger = null,
        RSA? tokenPublicKey = null,
        string deviceId = "",
        string? maintenancePasswordHash = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _offlineGraceStore = offlineGraceStore ?? throw new ArgumentNullException(nameof(offlineGraceStore));
        _logger = logger;
        _tokenPublicKey = tokenPublicKey;
        _deviceId = deviceId ?? string.Empty;
        _maintenancePasswordHash = maintenancePasswordHash;

        if (_tokenPublicKey is null)
        {
            _logger?.LogWarning(
                "License token signature verification disabled (no public key configured)");
        }
    }

    /// <summary>
    /// 检查授权状态（每30秒调用）。
    /// </summary>
    public async Task<LicenseEnforcementStatus> CheckStatusAsync()
    {
        _lastCheckTime = DateTime.UtcNow;

        try
        {
            // 尝试刷新令牌
            var result = await _client.RefreshTokenAsync();

            if (result.IsSuccess && result.Data != null && TokenAcceptable(result.Data))
            {
                // 在线授权成功
                if (_currentStatus != LicenseEnforcementStatus.Online)
                {
                    _logger?.LogInformation("Device status changed to ONLINE");
                }

                _currentStatus = LicenseEnforcementStatus.Online;

                // 保存到离线宽限存储
                _offlineGraceStore.SaveToken(result.Data);

                return _currentStatus;
            }

            // 在线授权失败，检查离线宽限
            var cachedToken = _offlineGraceStore.LoadToken();
            if (cachedToken != null && TokenAcceptable(cachedToken))
            {
                // 在宽限期内
                if (_currentStatus != LicenseEnforcementStatus.GracePeriod)
                {
                    _logger?.LogWarning("Device status changed to GRACE_PERIOD (offline grace)");
                }

                _currentStatus = LicenseEnforcementStatus.GracePeriod;
                return _currentStatus;
            }

            // 宽限期已过，需要锁定
            if (_currentStatus != LicenseEnforcementStatus.Locked)
            {
                _logger?.LogError("Device status changed to LOCKED (authorization failed)");
            }

            _currentStatus = LicenseEnforcementStatus.Locked;
            return _currentStatus;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error checking license status");

            // 出错时检查是否有有效缓存令牌
            var cachedToken = _offlineGraceStore.LoadToken();
            if (cachedToken != null && TokenAcceptable(cachedToken))
            {
                _currentStatus = LicenseEnforcementStatus.GracePeriod;
                return _currentStatus;
            }

            _currentStatus = LicenseEnforcementStatus.Locked;
            return _currentStatus;
        }
    }

    /// <summary>
    /// 令牌可接受性判定（R04）：未过期 +（配置公钥时）验签通过 +
    /// （配置本机标识时）设备匹配。公钥未配置时退化为仅过期检查（装配告警）。
    /// </summary>
    private bool TokenAcceptable(LicenseToken token)
    {
        if (token.IsExpired)
            return false;

        if (_tokenPublicKey is not null)
        {
            if (!token.VerifySignature(_tokenPublicKey))
            {
                _logger?.LogError("License token signature verification failed");
                return false;
            }
            if (_deviceId.Length > 0 &&
                !string.Equals(token.DeviceId, _deviceId, StringComparison.Ordinal))
            {
                _logger?.LogError(
                    "License token device mismatch: token={TokenDevice} local={LocalDevice}",
                    token.DeviceId, _deviceId);
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// 验证动态解锁码（TOTP）。
    /// </summary>
    public bool VerifyDynamicCode(string code, string deviceId)
    {
        if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(deviceId))
            return false;

        try
        {
            // 从设备ID派生共享密钥（与服务端一致）
            var secret = DeriveDeviceSecret(deviceId);

            // 验证TOTP码（使用自定义窗口：前后各一个时间步）
            return Winknow.Security.TotpGenerator.Verify(secret, code, window: 1);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to verify dynamic code");
            return false;
        }
    }

    /// <summary>
    /// 验证固定解锁码（维护密码，R04）。
    /// 复用 MaintenancePassword（Argon2id 常量时间比较）；
    /// 未配置维护密码哈希时恒拒绝（fail-closed，移除按长度放行）。
    /// </summary>
    public bool VerifyFixedCode(string code)
    {
        if (string.IsNullOrWhiteSpace(code) || string.IsNullOrEmpty(_maintenancePasswordHash))
            return false;

        try
        {
            return Winknow.Security.MaintenancePassword.Verify(code, _maintenancePasswordHash);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to verify fixed unlock code");
            return false;
        }
    }

    /// <summary>
    /// 解锁设备。
    /// </summary>
    public Result Unlock(string deviceId, string code, bool isDynamicCode = false)
    {
        bool isValid;

        if (isDynamicCode)
        {
            isValid = VerifyDynamicCode(code, deviceId);
            _logger?.LogInformation("Dynamic code verification: {Result}", isValid ? "Success" : "Failed");
        }
        else
        {
            isValid = VerifyFixedCode(code);
            _logger?.LogInformation("Fixed code verification: {Result}", isValid ? "Success" : "Failed");
        }

        if (!isValid)
        {
            _logger?.LogWarning("Unlock attempt failed");
            return Result.Failure(ErrorCode.Unauthorized, "Invalid unlock code");
        }

        // 解锁后重置状态为在线（给一次宽限）
        if (_currentStatus == LicenseEnforcementStatus.Locked)
        {
            _logger?.LogInformation("Device unlocked successfully");
            _currentStatus = LicenseEnforcementStatus.Online;
        }

        // 生成新的临时令牌
        var tempToken = LicenseToken.Create(deviceId, validityMinutes: 2);
        _offlineGraceStore.SaveToken(tempToken);

        _logger?.LogInformation("Temporary grace token issued for 2 minutes");
        return Result.Success();
    }

    /// <summary>
    /// 从设备ID派生共享密钥（与LanProvider一致）。
    /// </summary>
    private byte[] DeriveDeviceSecret(string deviceId)
    {
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        return sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(deviceId));
    }
}