using Microsoft.Extensions.Logging;
using Winknow.Core;
using Winknow.Ipc;
using Winknow.ProcessControl;

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
    private WmiProcessMonitor? _wmiMonitor;
    private ProcessScanner? _scanner;
    private ProcessJudge? _judge;
    private ProcessTerminator? _terminator;

    internal Worker(ILogger<Worker> logger, ILoggerFactory loggerFactory)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // 1. 初始化进程管控
        var whitelist = WhitelistRuleSet.CreateDefault();
        _judge = new ProcessJudge(whitelist, _loggerFactory.CreateLogger<ProcessJudge>());
        _terminator = new ProcessTerminator(_loggerFactory.CreateLogger<ProcessTerminator>());

        // 2. 启动 IPC 服务端
        var deviceId = DeviceId.Generate();
        var authenticator = IpcAuthenticator.CreateForControlService(deviceId);
        _ipcServer = new IpcServer(
            IpcConstants.ControlPipeName,
            authenticator,
            _loggerFactory.CreateLogger<IpcServer>());
        _ipcServer.MessageReceived += OnMessageReceived;
        await _ipcServer.StartAsync();
        _logger.LogInformation("IPC server started on pipe {PipeName}", IpcConstants.ControlPipeName);

        // 3. 启动 WMI 进程实时监听
        _wmiMonitor = new WmiProcessMonitor(_loggerFactory.CreateLogger<WmiProcessMonitor>());
        _wmiMonitor.ProcessStarted += OnProcessStarted;
        _wmiMonitor.Start();
        _logger.LogInformation("WMI ProcessStartTrace monitor started");

        // 4. 启动全量扫描 + 周期扫描
        _scanner = new ProcessScanner(
            scanInterval: TimeSpan.FromSeconds(2),
            logger: _loggerFactory.CreateLogger<ProcessScanner>());
        _scanner.ScanCompleted += OnScanCompleted;

        // 启动时执行一次全量扫描
        _logger.LogInformation("Performing initial full process scan...");
        _scanner.ScanAll();

        // 启动周期扫描
        _scanner.StartPeriodicScan();
        _logger.LogInformation("Periodic scan started (interval: 2s)");

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
            _wmiMonitor?.Dispose();
            _scanner?.Dispose();
            authenticator.Dispose();

            if (_ipcServer is not null)
            {
                _ipcServer.MessageReceived -= OnMessageReceived;
                await _ipcServer.StopAsync();
            }
        }
    }

    /// <summary>
    /// WMI 检测到新进程启动时的处理。
    /// </summary>
    private void OnProcessStarted(ProcessInfo info)
    {
        if (_judge is null || _terminator is null)
        {
            return;
        }

        var result = _judge.Judge(info);
        if (!result.IsSuccess)
        {
            _logger.LogWarning("Blocking process: {Pid} {Name} {Path} - {Reason}",
                info.ProcessId, info.ProcessName, info.FilePath, result.ErrorMessage);
            _terminator.Terminate(info.ProcessId, result.ErrorMessage ?? "Blocked by policy");
        }
    }

    /// <summary>
    /// 周期扫描完成时的处理。
    /// </summary>
    private void OnScanCompleted(IReadOnlyList<ProcessInfo> processes)
    {
        if (_judge is null || _terminator is null)
        {
            return;
        }

        var blockedCount = 0;
        foreach (var info in processes)
        {
            var result = _judge.Judge(info);
            if (!result.IsSuccess)
            {
                _logger.LogWarning("Blocking process (scan): {Pid} {Name} - {Reason}",
                    info.ProcessId, info.ProcessName, result.ErrorMessage);
                if (_terminator.Terminate(info.ProcessId, result.ErrorMessage ?? "Blocked by scan"))
                {
                    blockedCount++;
                }
            }
        }

        if (blockedCount > 0)
        {
            _logger.LogWarning("Scan completed: {Total} processes, {Blocked} blocked",
                processes.Count, blockedCount);
        }
    }

    private Task OnMessageReceived(IpcMessage message, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Received IPC message: Type={MessageType} RequestId={RequestId}",
            message.MessageType, message.RequestId);
        return Task.CompletedTask;
    }
}
