using Microsoft.Extensions.Logging;
using System.ServiceProcess;

namespace Winknow.GuardService;

/// <summary>
/// GuardService 守护进程工作器。
/// 运行身份：LocalSystem | 服务名：Winknow Guard Service
/// 职责：监控 ControlService 运行状态，服务被停止时自动重启。
/// 不承担交互式键盘钩子。
/// </summary>
internal sealed class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private const string ControlServiceName = "Winknow Control Service";
    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(3);

    internal Worker(ILogger<Worker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("GuardService started - monitoring {Service}", ControlServiceName);

        var restartAttempts = 0;
        var maxRestartAttempts = 5;
        var resetTimer = TimeSpan.FromMinutes(2);

        using var resetTimer_cts = new CancellationTokenSource();
        var lastRestartTime = DateTime.MinValue;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var isRunning = false;
                try
                {
                    using var sc = new ServiceController(ControlServiceName);
                    isRunning = sc.Status == ServiceControllerStatus.Running;
                }
                catch
                {
                    // 服务未安装或无法访问
                    isRunning = false;
                }

                if (!isRunning)
                {
                    // 重启限流：2 分钟内最多重启 5 次
                    if (restartAttempts >= maxRestartAttempts &&
                        DateTime.UtcNow - lastRestartTime < resetTimer)
                    {
                        _logger.LogCritical(
                            "ControlService restart limit reached ({Attempts}/{Max}), waiting {Minutes} min before retry",
                            restartAttempts, maxRestartAttempts, resetTimer.TotalMinutes);
                        await Task.Delay(resetTimer, stoppingToken);
                        restartAttempts = 0;
                        continue;
                    }

                    _logger.LogWarning("ControlService not running, attempting restart {Attempt}/{Max}",
                        restartAttempts + 1, maxRestartAttempts);

                    if (TryRestartService())
                    {
                        _logger.LogWarning("ControlService restarted successfully");
                        lastRestartTime = DateTime.UtcNow;
                        restartAttempts++;
                    }
                    else
                    {
                        _logger.LogError("Failed to restart ControlService");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GuardService monitoring error");
            }

            try
            {
                await Task.Delay(CheckInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger.LogInformation("GuardService stopped");
    }

    /// <summary>
    /// 尝试启动 ControlService。
    /// </summary>
    private bool TryRestartService()
    {
        try
        {
            using var sc = new ServiceController(ControlServiceName);
            var timeout = TimeSpan.FromSeconds(30);

            if (sc.Status == ServiceControllerStatus.Stopped)
            {
                sc.Start();
                sc.WaitForStatus(ServiceControllerStatus.Running, timeout);
                return sc.Status == ServiceControllerStatus.Running;
            }
            else if (sc.Status == ServiceControllerStatus.Paused)
            {
                sc.Continue();
                sc.WaitForStatus(ServiceControllerStatus.Running, timeout);
                return sc.Status == ServiceControllerStatus.Running;
            }

            return sc.Status == ServiceControllerStatus.Running;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Restart attempt failed for {Service}", ControlServiceName);
            return false;
        }
    }
}
