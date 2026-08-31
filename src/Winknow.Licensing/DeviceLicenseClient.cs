using Winknow.Core;
using Winknow.Core.Results;
using Microsoft.Extensions.Logging;

namespace Winknow.Licensing;

/// <summary>
/// 设备授权客户端：每30秒报DeviceId，收签名令牌。
/// </summary>
public sealed class DeviceLicenseClient
{
    private readonly ILicenseProvider _provider;
    private readonly string _deviceId;
    private readonly ILogger<DeviceLicenseClient>? _logger;
    private readonly TimeSpan _heartbeatInterval = TimeSpan.FromSeconds(30);
    private readonly CancellationTokenSource _cancellationTokenSource;

    private Task? _heartbeatTask;
    private LicenseToken? _currentToken;

    /// <summary>当前授权令牌（只读）。</summary>
    public LicenseToken? CurrentToken => _currentToken;

    /// <summary>
    /// 创建设备授权客户端。
    /// </summary>
    /// <param name="provider">授权提供者。</param>
    /// <param name="deviceId">设备唯一标识符。</param>
    /// <param name="logger">可选的日志记录器。</param>
    public DeviceLicenseClient(
        ILicenseProvider provider,
        string deviceId,
        ILogger<DeviceLicenseClient>? logger = null)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _deviceId = deviceId ?? throw new ArgumentNullException(nameof(deviceId));
        _logger = logger;
        _cancellationTokenSource = new CancellationTokenSource();
    }

    /// <summary>
    /// 启动心跳客户端。
    /// </summary>
    public void Start()
    {
        if (_heartbeatTask != null)
        {
            _logger?.LogWarning("License client already started");
            return;
        }

        _logger?.LogInformation("Starting license client for device {DeviceId}", _deviceId);
        _heartbeatTask = RunHeartbeatLoopAsync(_cancellationTokenSource.Token);
    }

    /// <summary>
    /// 停止心跳客户端。
    /// </summary>
    public void Stop()
    {
        if (_heartbeatTask == null)
            return;

        _logger?.LogInformation("Stopping license client for device {DeviceId}", _deviceId);
        _cancellationTokenSource.Cancel();

        try
        {
            _heartbeatTask.Wait(TimeSpan.FromSeconds(5));
        }
        catch (AggregateException)
        {
            // 忽略取消异常
        }

        _heartbeatTask = null;
    }

    /// <summary>
    /// 立即刷新授权令牌。
    /// </summary>
    public async Task<Result<LicenseToken>> RefreshTokenAsync()
    {
        _logger?.LogDebug("Refreshing license token for device {DeviceId}", _deviceId);

        var result = await _provider.VerifyLicenseAsync(_deviceId, _cancellationTokenSource.Token);
        if (result.IsSuccess)
        {
            _currentToken = result.Data;
            _logger?.LogInformation("License token refreshed for device {DeviceId}, expires at {ExpiresAt}",
                _deviceId, _currentToken?.ExpiresAt);
        }
        else
        {
            _logger?.LogError("Failed to refresh license token for device {DeviceId}: {Error}",
                _deviceId, result.ErrorMessage);
        }

        return result;
    }

    /// <summary>
    /// 生成动态解锁码。
    /// </summary>
    public async Task<Result<string>> GenerateDynamicCodeAsync()
    {
        _logger?.LogDebug("Generating dynamic code for device {DeviceId}", _deviceId);

        var result = await _provider.GenerateDynamicCodeAsync(_deviceId, _cancellationTokenSource.Token);
        if (result.IsSuccess)
        {
            _logger?.LogInformation("Dynamic code generated for device {DeviceId}", _deviceId);
        }
        else
        {
            _logger?.LogError("Failed to generate dynamic code for device {DeviceId}: {Error}",
                _deviceId, result.ErrorMessage);
        }

        return result;
    }

    /// <summary>
    /// 运行心跳循环。
    /// </summary>
    private async Task RunHeartbeatLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                // 首次立即刷新，然后按间隔
                await RefreshTokenAsync();

                // 等待下一次心跳
                await Task.Delay(_heartbeatInterval, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                // 正常退出
                break;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Heartbeat loop error for device {DeviceId}", _deviceId);

                // 避免无限循环，等待一小段时间再重试
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        _logger?.LogInformation("Heartbeat loop ended for device {DeviceId}", _deviceId);
    }

    /// <summary>
    /// 释放资源。
    /// </summary>
    public void Dispose()
    {
        Stop();
        _cancellationTokenSource.Dispose();
    }
}