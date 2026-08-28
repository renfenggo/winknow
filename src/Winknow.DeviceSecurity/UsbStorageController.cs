using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Winknow.DeviceSecurity;

/// <summary>
/// USB Mass Storage 管控器。
/// 通过注册表控制 USB 存储设备的可用性。
/// </summary>
public sealed class UsbStorageController
{
    private readonly ILogger<UsbStorageController>? _logger;

    /// <summary>注册表路径：USBSTOR 驱动启动类型。</summary>
    private const string UsbStorRegistryPath = @"SYSTEM\CurrentControlSet\Services\USBSTOR";

    /// <summary>注册表路径：可移动磁盘访问。</summary>
    private const string RemovableStoragePath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\RemovableStorage";

    /// <summary>创建 USB 存储管控器。</summary>
    /// <param name="logger">可选的日志记录器。</param>
    public UsbStorageController(ILogger<UsbStorageController>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// 禁用 USB Mass Storage 设备。
    /// </summary>
    public bool Disable()
    {
        try
        {
            // 1. 设置 USBSTOR 驱动启动类型为禁用 (4)
            using var key = Registry.LocalMachine.OpenSubKey(UsbStorRegistryPath, writable: true);
            if (key is not null)
            {
                key.SetValue("Start", 4, RegistryValueKind.DWord);
            }

            // 2. 设置可移动存储策略
            using var remKey = Registry.LocalMachine.CreateSubKey(RemovableStoragePath, writable: true);
            remKey.SetValue("DenyAll", 1, RegistryValueKind.DWord);

            _logger?.LogWarning("USB Mass Storage disabled");
            return true;
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger?.LogError(ex, "Access denied (need admin to disable USB)");
            return false;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to disable USB Mass Storage");
            return false;
        }
    }

    /// <summary>
    /// 启用 USB Mass Storage 设备。
    /// </summary>
    public bool Enable()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(UsbStorRegistryPath, writable: true);
            if (key is not null)
            {
                key.SetValue("Start", 3, RegistryValueKind.DWord);
            }

            using var remKey = Registry.LocalMachine.CreateSubKey(RemovableStoragePath, writable: true);
            remKey.SetValue("DenyAll", 0, RegistryValueKind.DWord);

            _logger?.LogInformation("USB Mass Storage enabled");
            return true;
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger?.LogError(ex, "Access denied (need admin to enable USB)");
            return false;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to enable USB Mass Storage");
            return false;
        }
    }

    /// <summary>
    /// 检查 USB Mass Storage 当前是否已禁用。
    /// </summary>
    public bool IsDisabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(UsbStorRegistryPath);
            if (key is not null)
            {
                var start = key.GetValue("Start");
                if (start is int startValue)
                {
                    return startValue == 4;
                }
            }
            return false;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to check USB status");
            return false;
        }
    }
}
