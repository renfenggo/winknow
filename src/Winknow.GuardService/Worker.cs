using System.ServiceProcess;
using Microsoft.Extensions.Logging;

namespace Winknow.GuardService;

/// <summary>
/// GuardService 守护服务工作器。
/// 运行身份：LocalSystem | 服务名：Winknow Guard Service
///
/// 职责：监控 Winknow Control Service 运行状态，停止时尝试拉起。
/// 注意：完整的对端验证、指数退避、重启阈值、Safe Degraded Mode 在第 10 周实现。
/// </summary>
internal sealed class Worker : BackgroundService
{
    private const string ControlServiceName = "Winknow Control Service";
    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromMinutes(1);

    private readonly ILogger<Worker> _logger;
    private TimeSpan _currentBackoff = ScanInterval;

    internal Worker(ILogger<Worker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Guard service started, monitoring {Service}", ControlServiceName);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (IsControlServiceStopped())
                {
                    _logger.LogWarning("{Service} is not running, attempting to start", ControlServiceName);
                    TryStartControlService();
                }
                else
                {
                    // 服务正常运行，重置退避
                    if (_currentBackoff != ScanInterval)
                    {
                        _logger.LogInformation("{Service} is running, backoff reset", ControlServiceName);
                        _currentBackoff = ScanInterval;
                    }
                }
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                _logger.LogError(exception, "Failed to check {Service} status", ControlServiceName);
            }

            try
            {
                await Task.Delay(_currentBackoff, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger.LogInformation("Guard service stopping");
    }

    private static bool IsControlServiceStopped()
    {
        using ServiceController controller = new(ControlServiceName);
        return controller.Status is ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending;
    }

    private void TryStartControlService()
    {
        try
        {
            using ServiceController controller = new(ControlServiceName);
            controller.Start();
            _logger.LogInformation("{Service} start requested", ControlServiceName);
            // 启动后重置退避，等待下次检查确认
            _currentBackoff = ScanInterval;
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Failed to start {Service}", ControlServiceName);
            // 启动失败，退避加倍避免重启风暴（完整指数退避在第 10 周实现）
            _currentBackoff = _currentBackoff >= MaxBackoff
                ? MaxBackoff
                : TimeSpan.FromTicks(_currentBackoff.Ticks * 2);
            _logger.LogWarning("Backoff increased to {Backoff}s", _currentBackoff.TotalSeconds);
        }
    }
}
