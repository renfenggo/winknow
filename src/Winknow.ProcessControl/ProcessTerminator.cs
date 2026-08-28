using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Winknow.ProcessControl;

/// <summary>
/// 进程终止器。
/// 在 ControlService（LocalSystem）下运行，可终止任意用户进程。
/// </summary>
public sealed class ProcessTerminator
{
    private readonly ILogger<ProcessTerminator>? _logger;

    /// <summary>创建进程终止器。</summary>
    /// <param name="logger">可选的日志记录器。</param>
    public ProcessTerminator(ILogger<ProcessTerminator>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// 终止指定进程。
    /// </summary>
    /// <param name="processId">进程 ID。</param>
    /// <param name="reason">终止原因（用于日志）。</param>
    /// <returns>true 表示成功终止，false 表示进程已退出或终止失败。</returns>
    public bool Terminate(int processId, string reason)
    {
        try
        {
            using var proc = Process.GetProcessById(processId);

            // 防止终止自身组件
            if (IsWinknowComponent(proc.ProcessName))
            {
                _logger?.LogWarning("Refused to terminate Winknow component: {Pid} {Name}",
                    processId, proc.ProcessName);
                return false;
            }

            proc.Kill(entireProcessTree: true);
            _logger?.LogWarning("Process terminated: {Pid} {Name} Reason: {Reason}",
                processId, proc.ProcessName, reason);
            return true;
        }
        catch (ArgumentException)
        {
            // 进程已退出
            return false;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            _logger?.LogError(ex, "Failed to terminate process {Pid}: {Message}",
                processId, ex.Message);
            return false;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Unexpected error terminating process {Pid}", processId);
            return false;
        }
    }

    /// <summary>
    /// 检查是否为 Winknow 自身组件（不可终止）。
    /// </summary>
    private static bool IsWinknowComponent(string processName)
    {
        return processName.StartsWith("Winknow.", StringComparison.OrdinalIgnoreCase);
    }
}
