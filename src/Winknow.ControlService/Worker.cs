using Microsoft.Extensions.Logging;
using Winknow.Core;
using Winknow.Ipc;

namespace Winknow.ControlService;

/// <summary>
/// ControlService 核心管控服务的工作器。
/// 运行身份：LocalSystem | 服务名：Winknow Control Service
///
/// 禁止：不承担交互式键盘钩子（由 SessionAgent 负责）
/// </summary>
internal sealed class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private IpcServer? _ipcServer;

    internal Worker(ILogger<Worker> logger, ILoggerFactory loggerFactory)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // 1. 启动 IPC 服务端
        var deviceId = DeviceId.Generate();
        var authenticator = IpcAuthenticator.CreateForControlService(deviceId);
        _ipcServer = new IpcServer(
            IpcConstants.ControlPipeName,
            authenticator,
            _loggerFactory.CreateLogger<IpcServer>());

        _ipcServer.MessageReceived += OnMessageReceived;
        _ = _ipcServer.StartAsync();
        _logger.LogInformation("ControlService IPC server started on pipe {PipeName}", IpcConstants.ControlPipeName);

        // 2. 启动会话监控
        _ = SessionMonitorLoopAsync(stoppingToken);

        // TODO 第3周：启动 WMI ProcessStartTrace + 全量进程扫描 + 周期扫描
        // TODO 第4周：加载并验证策略文件
        // TODO 第5周：配置服务 DACL + 文件 ACL + 注册表 ACL

        try
        {
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            // 正常关闭
        }
        finally
        {
            if (_ipcServer is not null)
            {
                _ipcServer.MessageReceived -= OnMessageReceived;
                await _ipcServer.StopAsync();
            }
            authenticator.Dispose();
        }
    }

    private Task OnMessageReceived(IpcMessage message, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Received IPC message: Type={MessageType} RequestId={RequestId}",
            message.MessageType, message.RequestId);

        // TODO 第3周：根据消息类型处理策略查询、会话状态等
        return Task.CompletedTask;
    }

    private async Task SessionMonitorLoopAsync(CancellationToken cancellationToken)
    {
        // TODO 第3周：实现 WTS_SESSION_LOGON/LOGOFF 事件监听
        // TODO 第3周：用户登录时启动 SessionAgent（由独立的 SessionLauncher 负责）
        // TODO 第3周：用户注销时向 SessionAgent 发送退出信号

        while (!cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(5000, cancellationToken);
        }
    }
}
