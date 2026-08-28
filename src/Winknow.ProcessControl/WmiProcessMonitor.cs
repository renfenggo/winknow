using System.Diagnostics;
using System.Management;
using Microsoft.Extensions.Logging;

namespace Winknow.ProcessControl;

/// <summary>
/// WMI ProcessStartTrace 实时监听器。
/// 在 ControlService（LocalSystem）下运行，监听所有会话的新进程启动事件。
/// </summary>
public sealed class WmiProcessMonitor : IDisposable
{
    private readonly ILogger<WmiProcessMonitor>? _logger;
    private ManagementEventWatcher? _watcher;
    private bool _disposed;

    /// <summary>检测到新进程启动时触发。</summary>
    public event Action<ProcessInfo>? ProcessStarted;

    /// <summary>创建 WMI 进程监听器。</summary>
    /// <param name="logger">可选的日志记录器。</param>
    public WmiProcessMonitor(ILogger<WmiProcessMonitor>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// 启动 WMI 进程启动事件监听。
    /// </summary>
    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Win32_ProcessStartTrace 事件查询
        var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
        _watcher = new ManagementEventWatcher(query);

        _watcher.EventArrived += OnEventArrived;
        _watcher.Start();

        _logger?.LogInformation("WMI ProcessStartTrace monitor started");
    }

    private void OnEventArrived(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var args = e.NewEvent;
            if (args is null)
            {
                return;
            }

            var processId = Convert.ToInt32(args["ProcessID"]);
            var processName = args["ProcessName"]?.ToString() ?? string.Empty;
            var sid = args["SID"]?.ToString() ?? string.Empty;

            // 异步获取详细信息
            var info = ProcessInfoCollector.Collect(processId, processName, sid);
            ProcessStarted?.Invoke(info);

            _logger?.LogDebug("Process started: {ProcessId} {ProcessName} {FilePath}",
                processId, processName, info.FilePath);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error processing process start event");
        }
    }

    /// <summary>
    /// 停止监听。
    /// </summary>
    public void Stop()
    {
        if (_watcher is not null)
        {
            _watcher.Stop();
            _watcher.EventArrived -= OnEventArrived;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;

        Stop();
        _watcher?.Dispose();
    }
}
