using Winknow.Core.Results;
using Winknow.Core;
using Microsoft.Extensions.Logging;

namespace Winknow.Licensing;

/// <summary>
/// 教师机授权验证端点（局域网模式）。
/// 心跳锚点：教师机（局域网），只罚"学生拔自己网线"。
/// </summary>
public sealed class LanProvider : ILicenseProvider
{
    private readonly string _teacherMachineIp;
    private readonly int _heartbeatPort;
    private readonly ILogger<LanProvider>? _logger;

    /// <summary>
    /// 创建教师机授权提供者。
    /// </summary>
    /// <param name="teacherMachineIp">教师机IP地址。</param>
    /// <param name="heartbeatPort">心跳端口（默认54321）。</param>
    /// <param name="logger">可选的日志记录器。</param>
    public LanProvider(
        string teacherMachineIp = "192.168.1.100",
        int heartbeatPort = 54321,
        ILogger<LanProvider>? logger = null)
    {
        _teacherMachineIp = teacherMachineIp;
        _heartbeatPort = heartbeatPort;
        _logger = logger;
    }

    /// <summary>
    /// 验证设备授权状态。
    /// </summary>
    public async Task<Result<LicenseToken>> VerifyLicenseAsync(string deviceId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return Result<LicenseToken>.Failure(ErrorCode.InvalidParameter, "DeviceId is required");
        }

        try
        {
            // 模拟网络请求到教师机验证授权
            // TODO 实现真实的HTTP客户端调用教师机端点
            await Task.Delay(10, cancellationToken);

            // 简化版本：假设所有设备都在授权名单中
            var token = LicenseToken.Create(deviceId, validityMinutes: 30);

            // 模拟签名（简化版本）
            var signature = ComputeMockSignature(token);
            var signedToken = new LicenseToken
            {
                DeviceId = token.DeviceId,
                IssuedAt = token.IssuedAt,
                ValidityMinutes = token.ValidityMinutes,
                Signature = signature
            };

            _logger?.LogInformation("Device {DeviceId} license verified: {Status}", deviceId, "Authorized");
            return Result<LicenseToken>.Success(signedToken);
        }
        catch (OperationCanceledException)
        {
            _logger?.LogWarning("License verification canceled for device {DeviceId}", deviceId);
            return Result<LicenseToken>.Failure(ErrorCode.IpcTimeout, "License verification timeout");
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "License verification failed for device {DeviceId}", deviceId);
            return Result<LicenseToken>.Failure(ErrorCode.IpcConnectionFailed, $"License verification error: {ex.Message}");
        }
    }

    /// <summary>
    /// 查询设备是否在授权名单中。
    /// </summary>
    public async Task<bool> IsDeviceAuthorizedAsync(string deviceId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            return false;

        try
        {
            // 模拟查询授权名单
            await Task.Delay(5, cancellationToken);

            // 简化版本：所有设备都在授权名单中
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 生成动态解锁码（TOTP）。
    /// </summary>
    public async Task<Result<string>> GenerateDynamicCodeAsync(string deviceId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return Result<string>.Failure(ErrorCode.InvalidParameter, "DeviceId is required");
        }

        try
        {
            // 生成设备特定的共享密钥
            var secret = DeriveDeviceSecret(deviceId);

            // 生成TOTP码（每5分钟一档，标准60s太短）
            // 这里使用自定义的5分钟步长
            var code = GenerateTotpWithCustomStep(secret, stepSeconds: 300);

            await Task.CompletedTask; // 满足async方法签名

            _logger?.LogInformation("Dynamic code generated for device {DeviceId}", deviceId);
            return Result<string>.Success(code);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to generate dynamic code for device {DeviceId}", deviceId);
            return Result<string>.Failure(ErrorCode.EncryptionFailed, $"Code generation error: {ex.Message}");
        }
    }

    /// <summary>
    /// 从设备ID派生共享密钥。
    /// </summary>
    private byte[] DeriveDeviceSecret(string deviceId)
    {
        // 使用设备ID的SHA256哈希作为密钥
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

        // 为了演示，这里返回标准TOTP码
        return code;
    }

    /// <summary>
    /// 计算模拟签名（简化版本）。
    /// </summary>
    private string ComputeMockSignature(LicenseToken token)
    {
        var data = $"{token.DeviceId}|{token.IssuedAt:O}|{token.ValidityMinutes}";
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data));
        return Convert.ToBase64String(hash);
    }
}