using Winknow.Core.Results;
using Microsoft.Extensions.Logging;

namespace Winknow.Licensing;

/// <summary>
/// 云后端授权验证端点（V7.1预留）。
/// 为云后端预留，加后端不重写。
/// </summary>
public sealed class CloudProvider : ILicenseProvider
{
    private readonly string _cloudApiEndpoint;
    private readonly ILogger<CloudProvider>? _logger;

    /// <summary>
    /// 创建云授权提供者。
    /// </summary>
    /// <param name="cloudApiEndpoint">云API端点。</param>
    /// <param name="logger">可选的日志记录器。</param>
    public CloudProvider(
        string cloudApiEndpoint = "https://api.winknow.cloud/v1",
        ILogger<CloudProvider>? logger = null)
    {
        _cloudApiEndpoint = cloudApiEndpoint;
        _logger = logger;
    }

    /// <summary>
    /// 验证设备授权状态。
    /// </summary>
    public async Task<Result<LicenseToken>> VerifyLicenseAsync(string deviceId, CancellationToken cancellationToken = default)
    {
        // V7.1 云后端实现预留
        _logger?.LogWarning("Cloud provider not yet implemented (V7.1 feature)");

        await Task.CompletedTask;
        return Result<LicenseToken>.Failure(ErrorCode.Unknown, "Cloud provider not available in V7.0");
    }

    /// <summary>
    /// 查询设备是否在授权名单中。
    /// </summary>
    public async Task<bool> IsDeviceAuthorizedAsync(string deviceId, CancellationToken cancellationToken = default)
    {
        // V7.1 云后端实现预留
        _logger?.LogWarning("Cloud provider not yet implemented (V7.1 feature)");

        await Task.CompletedTask;
        return false;
    }

    /// <summary>
    /// 生成动态解锁码（TOTP）。
    /// </summary>
    public async Task<Result<string>> GenerateDynamicCodeAsync(string deviceId, CancellationToken cancellationToken = default)
    {
        // V7.1 云后端实现预留
        _logger?.LogWarning("Cloud provider not yet implemented (V7.1 feature)");

        await Task.CompletedTask;
        return Result<string>.Failure(ErrorCode.Unknown, "Cloud provider not available in V7.0");
    }
}