using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Winknow.Security;

/// <summary>
/// 策略执行器：通过注册表禁用任务管理器、注册表编辑器等危险工具。
/// 保护 Run 键防止自启动篡改。
/// </summary>
public sealed class PolicyEnforcer
{
    private readonly ILogger<PolicyEnforcer>? _logger;

    /// <summary>创建策略执行器。</summary>
    /// <param name="logger">可选的日志记录器。</param>
    public PolicyEnforcer(ILogger<PolicyEnforcer>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// 禁用任务管理器（防止学生通过 Ctrl+Shift+Esc 终止进程）。
    /// 注册表：HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr = 1
    /// </summary>
    public bool DisableTaskManager()
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Policies\System", writable: true);
            key.SetValue("DisableTaskMgr", 1, RegistryValueKind.DWord);

            _logger?.LogWarning("Task Manager disabled");
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to disable Task Manager");
            return false;
        }
    }

    /// <summary>
    /// 恢复任务管理器。
    /// </summary>
    public bool EnableTaskManager()
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Policies\System", writable: true);
            key.SetValue("DisableTaskMgr", 0, RegistryValueKind.DWord);

            _logger?.LogInformation("Task Manager enabled");
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to enable Task Manager");
            return false;
        }
    }

    /// <summary>
    /// 禁用注册表编辑器（防止学生修改注册表绕过管控）。
    /// 注册表：HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableRegistryTools = 1
    /// </summary>
    public bool DisableRegistryEditor()
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Policies\System", writable: true);
            key.SetValue("DisableRegistryTools", 1, RegistryValueKind.DWord);

            _logger?.LogWarning("Registry Editor disabled");
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to disable Registry Editor");
            return false;
        }
    }

    /// <summary>
    /// 禁用命令提示符（防止通过 cmd 绕过管控）。
    /// 注册表：HKCU\Software\Policies\Microsoft\Windows\System\DisableCMD = 1
    /// </summary>
    public bool DisableCommandPrompt()
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(
                @"Software\Policies\Microsoft\Windows\System", writable: true);
            key.SetValue("DisableCMD", 1, RegistryValueKind.DWord);

            _logger?.LogWarning("Command Prompt disabled");
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to disable Command Prompt");
            return false;
        }
    }

    /// <summary>
    /// 监控 Run 键：检测并清除非白名单自启动项。
    /// 进程名不能作为唯一放行依据，需综合判断。
    /// </summary>
    public List<string> CheckRunKeyForModifications()
    {
        var suspicious = new List<string>();

        try
        {
            // 检查 HKCU Run 键
            using var runKey = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Run", writable: false);

            if (runKey is not null)
            {
                foreach (var name in runKey.GetValueNames())
                {
                    var value = runKey.GetValue(name)?.ToString() ?? string.Empty;
                    if (IsSuspiciousAutoStart(name, value))
                    {
                        suspicious.Add($"HKCU\\Run\\{name}: {value}");
                    }
                }
            }

            // 检查 HKLM Run 键
            using var runKeyLm = Registry.LocalMachine.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Run", writable: false);

            if (runKeyLm is not null)
            {
                foreach (var name in runKeyLm.GetValueNames())
                {
                    var value = runKeyLm.GetValue(name)?.ToString() ?? string.Empty;
                    if (IsSuspiciousAutoStart(name, value))
                    {
                        suspicious.Add($"HKLM\\Run\\{name}: {value}");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to check Run key");
        }

        return suspicious;
    }

    /// <summary>
    /// 判断自启动项是否可疑。
    /// 进程名不能作为唯一放行依据。
    /// </summary>
    private static bool IsSuspiciousAutoStart(string name, string value)
    {
        // 白名单自启动项
        var knownGoodNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "SecurityHealth", "OneDrive", "MicrosoftEdgeAutoLaunch",
            "Winknow.ControlService", "Winknow.GuardService", "Winknow.SessionAgent"
        };

        if (knownGoodNames.Contains(name))
        {
            return false;
        }

        // 检查可疑路径
        var suspiciousPaths = new[] { "AppData", "Temp", "Downloads", "Desktop" };
        foreach (var path in suspiciousPaths)
        {
            if (value.Contains(path, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        // 检查可疑命令行
        var suspiciousCmds = new[] { "-enc", "EncodedCommand", "iex", "DownloadString", "Invoke-" };
        foreach (var cmd in suspiciousCmds)
        {
            if (value.Contains(cmd, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
