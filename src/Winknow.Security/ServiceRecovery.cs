using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Winknow.Core.Results;

namespace Winknow.Security;

/// <summary>
/// SCM Failure Actions：服务异常退出时自动重启（第一层服务恢复）。
/// 配置前 3 次失败均重启服务，延迟 1 秒，重置周期 1 天。
/// </summary>
public static class ServiceRecovery
{
    private const int SC_MANAGER_CONNECT = 0x0001;
    private const int SERVICE_CHANGE_CONFIG = 0x0002;
    private const int SERVICE_QUERY_CONFIG = 0x0004;
    private const int SERVICE_CONFIG_FAILURE_ACTIONS = 2;

    /// <summary>
    /// 为服务配置失败自动恢复：连续 3 次失败均重启，每次延迟 1 秒，重置周期 1 天。
    /// 需管理员权限。
    /// </summary>
    public static Result ApplyServiceRecovery(string serviceName, ILogger? logger = null)
    {
        if (string.IsNullOrWhiteSpace(serviceName))
        {
            return Result.Failure(ErrorCode.InvalidArgument, "服务名不能为空");
        }

        if (!ServiceSecurity.IsRunningAsAdministrator())
        {
            logger?.LogError("ApplyServiceRecovery requires administrator privileges");
            return Result.Failure(ErrorCode.AccessDenied, "需要管理员权限");
        }

        IntPtr scm = IntPtr.Zero;
        IntPtr service = IntPtr.Zero;
        IntPtr actionsPtr = IntPtr.Zero;

        try
        {
            scm = RecoveryNative.OpenSCManager(null, null, SC_MANAGER_CONNECT);
            if (scm == IntPtr.Zero)
            {
                var err = Marshal.GetLastWin32Error();
                logger?.LogError("OpenSCManager failed: Win32Error={Error}", err);
                return Result.Failure(ErrorCode.ExternalError, $"OpenSCManager 失败: {err}");
            }

            service = RecoveryNative.OpenService(scm, serviceName, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG);
            if (service == IntPtr.Zero)
            {
                var err = Marshal.GetLastWin32Error();
                logger?.LogError("OpenService({Name}) failed: Win32Error={Error}", serviceName, err);
                return Result.Failure(ErrorCode.ExternalError, $"OpenService 失败: {err}");
            }

            // 构造 3 个 SC_ACTION（均 RESTART，延迟 1000ms）
            var actions = new SC_ACTION[3];
            for (var i = 0; i < 3; i++)
            {
                actions[i] = new SC_ACTION { Type = SC_ACTION_RESTART, Delay = 1000 };
            }

            actionsPtr = Marshal.AllocHGlobal(3 * 8); // 每个 SC_ACTION 8 字节
            for (var i = 0; i < 3; i++)
            {
                Marshal.WriteInt32(actionsPtr + i * 8, actions[i].Type);
                Marshal.WriteInt32(actionsPtr + i * 8 + 4, (int)actions[i].Delay);
            }

            var failureActions = new SERVICE_FAILURE_ACTIONS
            {
                dwResetPeriod = 86400, // 1 天重置计数
                lpRebootMsg = null,
                lpCommand = null,
                cActions = 3,
                lpsaActions = actionsPtr
            };

            if (!RecoveryNative.ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, ref failureActions))
            {
                var err = Marshal.GetLastWin32Error();
                logger?.LogError("ChangeServiceConfig2(FailureActions) failed: Win32Error={Error}", err);
                return Result.Failure(ErrorCode.ExternalError, $"配置失败恢复失败: {err}");
            }

            logger?.LogInformation("Service recovery configured for {Name}: 3x restart (delay 1s, reset 1d)", serviceName);
            return Result.Success();
        }
        finally
        {
            if (actionsPtr != IntPtr.Zero) Marshal.FreeHGlobal(actionsPtr);
            if (service != IntPtr.Zero) RecoveryNative.CloseServiceHandle(service);
            if (scm != IntPtr.Zero) RecoveryNative.CloseServiceHandle(scm);
        }
    }

    private const int SC_ACTION_RESTART = 1;

    [StructLayout(LayoutKind.Sequential)]
    private struct SC_ACTION
    {
        public int Type;
        public uint Delay;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SERVICE_FAILURE_ACTIONS
    {
        public uint dwResetPeriod;
        public string? lpRebootMsg;
        public string? lpCommand;
        public uint cActions;
        public IntPtr lpsaActions;
    }

    private static class RecoveryNative
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenSCManager(string? lpMachineName, string? lpDatabaseName, int dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, int dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ChangeServiceConfig2(IntPtr hService, int dwInfoLevel, ref SERVICE_FAILURE_ACTIONS lpInfo);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);
    }
}
