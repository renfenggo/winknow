using Winknow.Core.Results;
using Winknow.Security;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace Winknow.Licensing;

/// <summary>
/// 教师机侧轻量端点：名单查询+令牌签发+动态码生成。
/// </summary>
public sealed class TeacherLicenseServer
{
    private readonly ConcurrentDictionary<string, AuthorizedDevice> _authorizedDevices;
    private readonly ILogger<TeacherLicenseServer>? _logger;

    /// <summary>授权设备名单。</summary>
    public IReadOnlyDictionary<string, AuthorizedDevice> AuthorizedDevices => _authorizedDevices;

    /// <summary>
    /// 创建教师机授权服务器。
    /// </summary>
    /// <param name="logger">可选的日志记录器。</param>
    public TeacherLicenseServer(ILogger<TeacherLicenseServer>? logger = null)
    {
        _authorizedDevices = new ConcurrentDictionary<string, AuthorizedDevice>();
        _logger = logger;

        // 初始化测试设备名单
        InitializeTestDevices();
    }

    /// <summary>
    /// 验证设备授权状态并签发令牌。
    /// </summary>
    public Result<LicenseToken> VerifyAndIssueToken(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return Result<LicenseToken>.Failure(ErrorCode.InvalidParameter, "DeviceId is required");
        }

        // 检查设备是否在授权名单中
        if (!_authorizedDevices.TryGetValue(deviceId, out var deviceInfo))
        {
            _logger?.LogWarning("Device {DeviceId} not in authorization list", deviceId);
            return Result<LicenseToken>.Failure(ErrorCode.Unauthorized, "Device not authorized");
        }

        // 检查设备状态
        if (deviceInfo.Status == DeviceStatus.Locked)
        {
            _logger?.LogWarning("Device {DeviceId} is locked", deviceId);
            return Result<LicenseToken>.Failure(ErrorCode.Unauthorized, "Device is locked");
        }

        try
        {
            // 创建令牌
            var token = LicenseToken.Create(deviceId, validityMinutes: 30);

            // 签名（简化版本）
            var signature = SignToken(token);
            var signedToken = new LicenseToken
            {
                DeviceId = token.DeviceId,
                IssuedAt = token.IssuedAt,
                ValidityMinutes = token.ValidityMinutes,
                Signature = signature
            };

            // 更新设备状态
            deviceInfo.LastSeen = DateTime.UtcNow;
            deviceInfo.Status = DeviceStatus.Online;

            _logger?.LogInformation("Token issued for device {DeviceId}, expires at {ExpiresAt}",
                deviceId, signedToken.ExpiresAt);

            return Result<LicenseToken>.Success(signedToken);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to issue token for device {DeviceId}", deviceId);
            return Result<LicenseToken>.Failure(ErrorCode.Unknown, $"Token issuance error: {ex.Message}");
        }
    }

    /// <summary>
    /// 查询设备是否在授权名单中。
    /// </summary>
    public bool IsDeviceAuthorized(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            return false;

        return _authorizedDevices.ContainsKey(deviceId);
    }

    /// <summary>
    /// 生成动态解锁码（TOTP）。
    /// </summary>
    public Result<string> GenerateDynamicCode(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return Result<string>.Failure(ErrorCode.InvalidParameter, "DeviceId is required");
        }

        if (!_authorizedDevices.TryGetValue(deviceId, out var deviceInfo))
        {
            return Result<string>.Failure(ErrorCode.Unauthorized, "Device not authorized");
        }

        try
        {
            // 生成设备特定的共享密钥
            var secret = DeriveDeviceSecret(deviceId);

            // 生成TOTP码（5分钟步长）
            var code = GenerateTotpWithCustomStep(secret, stepSeconds: 300);

            _logger?.LogInformation("Dynamic code generated for device {DeviceId}: {Code}", deviceId, code);
            return Result<string>.Success(code);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to generate dynamic code for device {DeviceId}", deviceId);
            return Result<string>.Failure(ErrorCode.EncryptionFailed, $"Code generation error: {ex.Message}");
        }
    }

    /// <summary>
    /// 锁定设备。
    /// </summary>
    public Result LockDevice(string deviceId)
    {
        if (!_authorizedDevices.TryGetValue(deviceId, out var deviceInfo))
        {
            return Result.Failure(ErrorCode.InvalidParameter, "Device not found");
        }

        deviceInfo.Status = DeviceStatus.Locked;
        deviceInfo.LockedAt = DateTime.UtcNow;

        _logger?.LogWarning("Device {DeviceId} locked by admin", deviceId);
        return Result.Success();
    }

    /// <summary>
    /// 解锁设备。
    /// </summary>
    public Result UnlockDevice(string deviceId)
    {
        if (!_authorizedDevices.TryGetValue(deviceId, out var deviceInfo))
        {
            return Result.Failure(ErrorCode.InvalidParameter, "Device not found");
        }

        deviceInfo.Status = DeviceStatus.Online;
        deviceInfo.LockedAt = null;

        _logger?.LogInformation("Device {DeviceId} unlocked by admin", deviceId);
        return Result.Success();
    }

    /// <summary>
    /// 添加设备到授权名单。
    /// </summary>
    public Result AddAuthorizedDevice(string deviceId, string studentName)
    {
        if (string.IsNullOrWhiteSpace(deviceId) || string.IsNullOrWhiteSpace(studentName))
        {
            return Result.Failure(ErrorCode.InvalidParameter, "DeviceId and student name are required");
        }

        var device = new AuthorizedDevice
        {
            DeviceId = deviceId,
            StudentName = studentName,
            AddedAt = DateTime.UtcNow,
            Status = DeviceStatus.Online
        };

        if (!_authorizedDevices.TryAdd(deviceId, device))
        {
            return Result.Failure(ErrorCode.InvalidParameter, "Device already in authorization list");
        }

        _logger?.LogInformation("Device {DeviceId} ({StudentName}) added to authorization list", deviceId, studentName);
        return Result.Success();
    }

    /// <summary>
    /// 从授权名单移除设备。
    /// </summary>
    public Result RemoveAuthorizedDevice(string deviceId)
    {
        if (!_authorizedDevices.TryRemove(deviceId, out _))
        {
            return Result.Failure(ErrorCode.InvalidParameter, "Device not found in authorization list");
        }

        _logger?.LogInformation("Device {DeviceId} removed from authorization list", deviceId);
        return Result.Success();
    }

    /// <summary>
    /// 获取所有授权设备的状态。
    /// </summary>
    public List<DeviceStatusInfo> GetAllDeviceStatus()
    {
        return _authorizedDevices.Values
            .Select(d => new DeviceStatusInfo
            {
                DeviceId = d.DeviceId,
                StudentName = d.StudentName,
                Status = d.Status,
                LastSeen = d.LastSeen,
                LockedAt = d.LockedAt
            })
            .ToList();
    }

    /// <summary>
    /// 从设备ID派生共享密钥。
    /// </summary>
    private byte[] DeriveDeviceSecret(string deviceId)
    {
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        return sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(deviceId));
    }

    /// <summary>
    /// 生成自定义步长的TOTP码。
    /// </summary>
    private string GenerateTotpWithCustomStep(byte[] secret, int stepSeconds)
    {
        // 简化版本：使用标准TOTP但修改时间步长
        // TODO 实现完整的自定义步长TOTP
        var code = Winknow.Security.TotpGenerator.GenerateCode(secret);
        return code;
    }

    /// <summary>
    /// 签名令牌（简化版本）。
    /// </summary>
    private string SignToken(LicenseToken token)
    {
        var data = $"{token.DeviceId}|{token.IssuedAt:O}|{token.ValidityMinutes}";
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data));
        return Convert.ToBase64String(hash);
    }

    /// <summary>
    /// 初始化测试设备名单。
    /// </summary>
    private void InitializeTestDevices()
    {
        // 添加一些测试设备
        AddAuthorizedDevice("test-device-001", "张三");
        AddAuthorizedDevice("test-device-002", "李四");
        AddAuthorizedDevice("test-device-003", "王五");
    }
}

/// <summary>
/// 授权设备信息。
/// </summary>
public sealed class AuthorizedDevice
{
    /// <summary>设备唯一标识符。</summary>
    public string DeviceId { get; set; } = string.Empty;

    /// <summary>学生姓名。</summary>
    public string StudentName { get; set; } = string.Empty;

    /// <summary>添加到授权名单的时间。</summary>
    public DateTime AddedAt { get; set; }

    /// <summary>最后一次心跳时间。</summary>
    public DateTime LastSeen { get; set; }

    /// <summary>设备状态。</summary>
    public DeviceStatus Status { get; set; }

    /// <summary>锁定时间。</summary>
    public DateTime? LockedAt { get; set; }
}

/// <summary>
/// 设备状态。
/// </summary>
public enum DeviceStatus
{
    /// <summary>在线。</summary>
    Online,

    /// <summary>宽限中。</summary>
    GracePeriod,

    /// <summary>锁定。</summary>
    Locked
}

/// <summary>
/// 设备状态信息。
/// </summary>
public sealed class DeviceStatusInfo
{
    /// <summary>设备唯一标识符。</summary>
    public string DeviceId { get; set; } = string.Empty;

    /// <summary>学生姓名。</summary>
    public string StudentName { get; set; } = string.Empty;

    /// <summary>设备状态。</summary>
    public DeviceStatus Status { get; set; }

    /// <summary>最后一次心跳时间。</summary>
    public DateTime LastSeen { get; set; }

    /// <summary>锁定时间。</summary>
    public DateTime? LockedAt { get; set; }
}