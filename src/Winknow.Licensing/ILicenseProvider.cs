using Winknow.Core.Results;

namespace Winknow.Licensing;

/// <summary>
/// 授权验证端点抽象接口。
/// 支持：LanProvider（教师机） / CloudProvider（V7.1云后端）。
/// 为云后端预留，加后端不重写。
/// </summary>
public interface ILicenseProvider
{
    /// <summary>
    /// 验证设备授权状态。
    /// </summary>
    /// <param name="deviceId">设备唯一标识符。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    /// <returns>成功返回授权令牌，失败返回错误码。</returns>
    Task<Result<LicenseToken>> VerifyLicenseAsync(string deviceId, CancellationToken cancellationToken = default);

    /// <summary>
    /// 查询设备是否在授权名单中。
    /// </summary>
    /// <param name="deviceId">设备唯一标识符。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    /// <returns>设备是否在授权名单中。</returns>
    Task<bool> IsDeviceAuthorizedAsync(string deviceId, CancellationToken cancellationToken = default);

    /// <summary>
    /// 生成动态解锁码（TOTP）。
    /// </summary>
    /// <param name="deviceId">设备唯一标识符。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    /// <returns>成功返回当前TOTP码，失败返回错误码。</returns>
    Task<Result<string>> GenerateDynamicCodeAsync(string deviceId, CancellationToken cancellationToken = default);
}