using System.Diagnostics;
using System.Management;
using Microsoft.Extensions.Logging;

namespace Winknow.ProcessControl;

/// <summary>
/// WMI ProcessStartTrace 实时监听器（弹性版，V7.0 第 13 周增强）。
///
/// 在 ControlService（LocalSystem）下运行，监听所有会话的新进程启动事件。
///
/// 弹性机制（对应综合测试"WMI 丢事件和重连"）：
/// - watcher 收到 <see cref="ManagementEventWatcher.Stopped"/>（WMI 服务重启/系统压力导致静默失效）→ 退避重建；
/// - <see cref="StartWatcher"/> 抛异常（开机早期 WMI 未就绪等）→ 退避重试；
/// - 主动 <see cref="Stop"/> 不触发重建（_running 标志区分意外停与主动停）；
/// - 事件正常到达即 <see cref="WatcherReconnectPolicy.OnSuccess"/> 归零退避。
/// 周期扫描（ProcessScanner 2s）仍是独立兜底层——watcher 故障期间管控不中断。
/// </summary>
public sealed class WmiProcessMonitor : IDisposable
{
    private readonly ILogger<WmiProcessMonitor>? _logger;
    private readonly WatcherReconnectPolicy _policy;
    private ManagementEventWatcher? _watcher;
    private volatile bool _running;
    private int _rebuilding; // 重建互斥（Interlocked）
    private bool _disposed;

    /// <summary>检测到新进程启动时触发。</summary>
    public event Action<ProcessInfo>? ProcessStarted;

    /// <summary>累计重连次数（灰度观察指标"WMI 重连次数"）。</summary>
    public int ReconnectCount => _policy.ReconnectCount;

    /// <summary>当前连续失败次数（0 = 实时监听健康）。</summary>
    public int ConsecutiveFailures => _policy.ConsecutiveFailures;

    /// <summary>创建 WMI 进程监听器。</summary>
    /// <param name="logger">可选日志。</param>
    /// <param name="policy">可选重连策略（测试注入）。</param>
    public WmiProcessMonitor(
        ILogger<WmiProcessMonitor>? logger = null,
        WatcherReconnectPolicy? policy = null)
    {
        _logger = logger;
        _policy = policy ?? new WatcherReconnectPolicy();
    }

    /// <summary>
    /// 启动 WMI 进程启动事件监听（失败自动进入退避重连循环）。
    /// </summary>
    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _running = true;
        StartWatcher();
    }

    private void StartWatcher()
    {
        if (!_running || _disposed)
        {
            return;
        }

        try
        {
            var watcher = new ManagementEventWatcher(
                new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            watcher.EventArrived += OnEventArrived;
            watcher.Stopped += OnWatcherStopped;
            watcher.Start();

            _watcher = watcher;
            _policy.OnSuccess();
            _logger?.LogInformation(
                "WMI ProcessStartTrace monitor started (reconnects so far: {Reconnects})",
                _policy.ReconnectCount);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "WMI watcher 启动失败，进入退避重连");
            ScheduleReconnect();
        }
    }

    private void OnWatcherStopped(object sender, StoppedEventArgs e)
    {
        // 主动 Stop 不重建（_running=false 先行）；意外停止才重连
        if (_running)
        {
            _logger?.LogWarning("WMI watcher 意外停止（WMI 服务重启或系统压力），准备重建");
            ScheduleReconnect();
        }
    }

    private void ScheduleReconnect()
    {
        if (!_running || _disposed)
        {
            return;
        }

        // 防并发重建（Stopped 与 Start 异常可能叠加）
        if (Interlocked.Exchange(ref _rebuilding, 1) == 1)
        {
            return;
        }

        var delay = _policy.OnWatcherFailure();
        _logger?.LogWarning(
            "WMI watcher 将在 {Delay:s\\.fff}s 后重建（连续失败 {Failures} 次）",
            delay, _policy.ConsecutiveFailures);

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(delay);
                TeardownWatcher();
                StartWatcher();
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "WMI watcher 重建循环异常");
                StartWatcher(); // 再试（策略继续退避）
            }
            finally
            {
                Volatile.Write(ref _rebuilding, 0);
            }
        });
    }

    private void TeardownWatcher()
    {
        if (_watcher is null)
        {
            return;
        }
        try
        {
            _watcher.EventArrived -= OnEventArrived;
            _watcher.Stopped -= OnWatcherStopped;
            _watcher.Stop();
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "拆除旧 watcher 时异常（可忽略）");
        }
        finally
        {
            _watcher.Dispose();
            _watcher = null;
        }
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

            // 事件正常到达 = 实时链路健康
            _policy.OnSuccess();

            var processId = Convert.ToInt32(args["ProcessID"]);
            var processName = args["ProcessName"]?.ToString() ?? string.Empty;
            var sid = args["SID"]?.ToString() ?? string.Empty;

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
    /// 停止监听（主动停止不触发重连）。
    /// </summary>
    public void Stop()
    {
        _running = false;
        TeardownWatcher();
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
    }
}
