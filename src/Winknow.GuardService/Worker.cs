namespace Winknow.GuardService;

/// <summary>
/// GuardService 守护服务的工作器。
/// 运行身份：LocalSystem（NT AUTHORITY\SYSTEM）。
/// 服务名：Winknow Guard Service。
///
/// 核心职责（见《V7.0 组件架构设计》第 3.2 节）：
/// 1. 守护 ControlService（每 1-2 秒查询状态，被停止立即重启）
/// 2. 自保护（与 ControlService 互相守护，DACL 加固）
/// 3. 审计（守护事件写入 Event Log 和 audit.db）
///
/// 禁止：
/// - 不承担软件管控、网络管控、USB 管控等业务逻辑
/// - 不直接与 SessionAgent 通信
/// </summary>
internal sealed class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;

    internal Worker(ILogger<Worker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // TODO 第5周：实现 ControlService 状态监控循环
        // TODO 第5周：实现被停止后自动重启逻辑
        // TODO 第5周：实现维护模式标志检查（维护模式下不重启）

        while (!stoppingToken.IsCancellationRequested)
        {
            if (_logger.IsEnabled(LogLevel.Information))
            {
                _logger.LogInformation("GuardService running at: {time}", DateTimeOffset.Now);
            }
            await Task.Delay(1000, stoppingToken);
        }
    }
}
