using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Winknow.ProcessControl;

/// <summary>
/// 进程扫描器：全量扫描 + 周期扫描。
/// </summary>
public sealed class ProcessScanner : IDisposable
{
    private readonly ILogger<ProcessScanner>? _logger;
    private readonly TimeSpan _scanInterval;
    private PeriodicTimer? _timer;
    private CancellationTokenSource? _cts;
    private bool _disposed;

    /// <summary>扫描完成时触发，参数为当前所有进程信息。</summary>
    public event Action<IReadOnlyList<ProcessInfo>>? ScanCompleted;

    /// <summary>创建进程扫描器。</summary>
    /// <param name="scanInterval">扫描间隔（默认 2 秒）。</param>
    /// <param name="logger">可选的日志记录器。</param>
    public ProcessScanner(TimeSpan? scanInterval = null, ILogger<ProcessScanner>? logger = null)
    {
        _scanInterval = scanInterval ?? TimeSpan.FromSeconds(2);
        _logger = logger;
    }

    /// <summary>
    /// 执行一次全量进程扫描。
    /// </summary>
    public IReadOnlyList<ProcessInfo> ScanAll()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var processes = Process.GetProcesses();
        var result = new List<ProcessInfo>(processes.Length);

        foreach (var proc in processes)
        {
            try
            {
                var info = ProcessInfoCollector.Collect(proc.Id, proc.ProcessName);
                result.Add(info);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to collect info for PID {ProcessId}", proc.Id);
            }
            finally
            {
                proc.Dispose();
            }
        }

        _logger?.LogDebug("Full scan completed: {Count} processes", result.Count);
        ScanCompleted?.Invoke(result);
        return result;
    }

    /// <summary>
    /// 启动周期扫描。
    /// </summary>
    public void StartPeriodicScan()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _cts = new CancellationTokenSource();
        _timer = new PeriodicTimer(_scanInterval);

        _ = PeriodicScanLoopAsync(_cts.Token);
    }

    private async Task PeriodicScanLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (await _timer!.WaitForNextTickAsync(cancellationToken))
            {
                ScanAll();
            }
        }
        catch (OperationCanceledException)
        {
            // 正常关闭
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Periodic scan loop error");
        }
    }

    /// <summary>
    /// 停止周期扫描。
    /// </summary>
    public void StopPeriodicScan()
    {
        _cts?.Cancel();
        _timer?.Dispose();
        _timer = null;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;

        StopPeriodicScan();
        _cts?.Dispose();
    }
}
