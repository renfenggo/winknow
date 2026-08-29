using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Winknow.Core.Results;

namespace Winknow.Security;

/// <summary>
/// SafeBoot 注册：将核心服务注册到安全模式（Minimal / Network）启动白名单。
///
/// 背景：Windows 安全模式下仅启动注册到
/// HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\{Minimal|Network}\&lt;ServiceName&gt;
/// 的服务与驱动。未注册的服务在安全模式下不会启动，会导致管控失效且无恢复通道。
///
/// 本类将 Winknow 核心服务同时注册到 Minimal 和 Network，满足 V7.0 第 5 周验收项
/// “安全模式下服务正常运行”与“不破坏 Windows 默认恢复环境”。
///
/// 需管理员权限运行；仅在安装/恢复阶段调用，不在运行时反复写注册表。
/// </summary>
public static class SafeBootRegistrar
{
    private const string SafeBootRoot = @"SYSTEM\CurrentControlSet\Control\SafeBoot";
    private const string MinimalKey = "Minimal";
    private const string NetworkKey = "Network";

    // REG_OPTION_BACKUP_RESTORE：写入时强制持久化到磁盘，避免 SafeBoot 键丢失
    private const int REG_OPTION_BACKUP_RESTORE = 0x00000004;
    private const int KEY_SET_VALUE = 0x0004;
    private const int KEY_QUERY_VALUE = 0x0001;
    private const int KEY_CREATE_SUB_KEY = 0x0004;

    /// <summary>
    /// 将服务同时注册到 Minimal 和 Network 安全模式启动白名单。
    /// </summary>
    /// <param name="serviceName">注册到 SCM 的服务名（与 ChangeServiceConfig 一致）。</param>
    /// <param name="description">可选显示描述，写入注册表默认值。</param>
    /// <param name="logger">可选日志记录器。</param>
    public static Result Register(string serviceName, string? description = null, ILogger? logger = null)
    {
        if (string.IsNullOrWhiteSpace(serviceName))
        {
            return Result.Failure(ErrorCode.InvalidArgument, "服务名不能为空");
        }

        if (!ServiceSecurity.IsRunningAsAdministrator())
        {
            logger?.LogError("SafeBootRegistrar.Register requires administrator privileges");
            return Result.Failure(ErrorCode.AccessDenied, "需要管理员权限");
        }

        var minimalOk = WriteSafeBootEntry(MinimalKey, serviceName, description, logger);
        if (!minimalOk.IsSuccess)
        {
            return minimalOk;
        }

        var networkOk = WriteSafeBootEntry(NetworkKey, serviceName, description, logger);
        if (!networkOk.IsSuccess)
        {
            // Minimal 已写入但 Network 失败：回滚 Minimal 以保持一致
            _ = DeleteSafeBootEntry(MinimalKey, serviceName, logger);
            return networkOk;
        }

        logger?.LogInformation("SafeBoot registered {Name} under Minimal and Network", serviceName);
        return Result.Success();
    }

    /// <summary>
    /// 从 Minimal 和 Network 安全模式白名单移除服务（卸载时调用）。
    /// </summary>
    /// <param name="serviceName">注册到 SCM 的服务名。</param>
    /// <param name="logger">可选日志记录器。</param>
    public static Result Unregister(string serviceName, ILogger? logger = null)
    {
        if (string.IsNullOrWhiteSpace(serviceName))
        {
            return Result.Failure(ErrorCode.InvalidArgument, "服务名不能为空");
        }

        if (!ServiceSecurity.IsRunningAsAdministrator())
        {
            logger?.LogError("SafeBootRegistrar.Unregister requires administrator privileges");
            return Result.Failure(ErrorCode.AccessDenied, "需要管理员权限");
        }

        // 两个键都尝试删除，即使其中一个不存在也不视为失败
        _ = DeleteSafeBootEntry(MinimalKey, serviceName, logger);
        _ = DeleteSafeBootEntry(NetworkKey, serviceName, logger);

        logger?.LogInformation("SafeBoot unregistered {Name} from Minimal and Network", serviceName);
        return Result.Success();
    }

    /// <summary>
    /// 检查服务是否同时注册在 Minimal 和 Network 下。
    /// </summary>
    public static bool IsRegistered(string serviceName)
    {
        if (string.IsNullOrWhiteSpace(serviceName))
        {
            return false;
        }

        return EntryExists(MinimalKey, serviceName) && EntryExists(NetworkKey, serviceName);
    }

    private static Result WriteSafeBootEntry(string mode, string serviceName, string? description, ILogger? logger)
    {
        var subKey = $@"{SafeBootRoot}\{mode}\{serviceName}";
        var root = SafeBootNative.HKEY_LOCAL_MACHINE;

        var disposition = 0;
        var handle = SafeBootNative.RegCreateKeyEx(
            root, subKey, 0, IntPtr.Zero, REG_OPTION_BACKUP_RESTORE,
            KEY_SET_VALUE, IntPtr.Zero, out var createdKey, ref disposition);

        if (handle != 0) // ERROR_SUCCESS = 0
        {
            logger?.LogError("RegCreateKeyEx({Key}) failed: Win32Error={Error}", subKey, handle);
            return Result.Failure(ErrorCode.ExternalError, $"RegCreateKeyEx({mode}) 失败: {handle}");
        }

        try
        {
            // 写入默认值（服务描述），帮助管理员识别该条目归属
            if (!string.IsNullOrEmpty(description))
            {
                var setValue = SafeBootNative.RegSetValueEx(
                    createdKey, null, 0, 1 /* REG_SZ */,
                    System.Text.Encoding.Unicode.GetBytes(description + "\0"),
                    (description.Length + 1) * 2);
                if (setValue != 0)
                {
                    logger?.LogWarning("RegSetValueEx({Key}) failed: Win32Error={Error}", subKey, setValue);
                    // 默认值写入失败不致命，服务仍可在安全模式启动，继续
                }
            }

            logger?.LogDebug("SafeBoot entry {Mode}/{Name} written (disposition={Disp})", mode, serviceName, disposition);
            return Result.Success();
        }
        finally
        {
            SafeBootNative.RegCloseKey(createdKey);
        }
    }

    private static Result DeleteSafeBootEntry(string mode, string serviceName, ILogger? logger)
    {
        var subKey = $@"{SafeBootRoot}\{mode}\{serviceName}";
        var ret = SafeBootNative.RegDeleteKey(SafeBootNative.HKEY_LOCAL_MACHINE, subKey);
        if (ret != 0 && ret != 2) // 2 = ERROR_FILE_NOT_FOUND，视为已清理
        {
            logger?.LogWarning("RegDeleteKey({Key}) returned Win32Error={Error}", subKey, ret);
        }
        return Result.Success();
    }

    private static bool EntryExists(string mode, string serviceName)
    {
        var subKey = $@"{SafeBootRoot}\{mode}\{serviceName}";
        var ret = SafeBootNative.RegOpenKeyEx(
            SafeBootNative.HKEY_LOCAL_MACHINE, subKey, 0, KEY_QUERY_VALUE, out var handle);
        if (ret != 0)
        {
            return false;
        }
        SafeBootNative.RegCloseKey(handle);
        return true;
    }

    private static class SafeBootNative
    {
        public static readonly IntPtr HKEY_LOCAL_MACHINE = new(0x80000002);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int RegCreateKeyEx(
            IntPtr hKey, string lpSubKey, int reserved, IntPtr lpClass,
            int dwOptions, int samDesired, IntPtr lpSecurityAttributes,
            out IntPtr phkResult, ref int lpdwDisposition);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int RegSetValueEx(
            IntPtr hKey, string? lpValueName, int reserved, int dwType,
            byte[] lpData, int cbData);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int RegDeleteKey(IntPtr hKey, string lpSubKey);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int RegOpenKeyEx(
            IntPtr hKey, string lpSubKey, int ulOptions, int samDesired, out IntPtr phkResult);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegCloseKey(IntPtr hKey);
    }
}
