namespace Winknow.ControlService;

/// <summary>
/// ControlService 核心管控服务的工作器。
/// 运行身份：LocalSystem（NT AUTHORITY\SYSTEM）。
/// 服务名：Winknow Control Service。
///
/// 核心职责（见《V7.0 组件架构设计》第 3.1 节）：
/// 1. 软件管控（WMI ProcessStartTrace + 全量扫描 + 周期扫描）
/// 2. 策略执行（加载并验证策略文件）
/// 3. IPC 服务端（Named Pipe + SID 校验 + 防重放）
/// 4. 自保护（DACL + ACL）
/// 5. 日志审计（audit.db Hash Chain + Event Log）
///
/// 禁止：
/// - 不承担交互式键盘钩子（由 SessionAgent 负责）
/// - 不直接显示 UI（通过 AdminUI 管理）
/// - 不持有学生用户令牌
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
        // TODO 第2周：初始化 Named Pipe 服务端
        // TODO 第3周：启动 WMI ProcessStartTrace 监听 + 全量进程扫描 + 周期扫描定时器
        // TODO 第4周：加载并验证策略文件
        // TODO 第5周：配置服务 DACL + 文件 ACL + 注册表 ACL

        while (!stoppingToken.IsCancellationRequested)
        {
            if (_logger.IsEnabled(LogLevel.Information))
            {
                _logger.LogInformation("ControlService running at: {time}", DateTimeOffset.Now);
            }
            await Task.Delay(1000, stoppingToken);
        }
    }
}
