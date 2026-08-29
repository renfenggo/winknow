using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Winknow.Core.Results;

namespace Winknow.Security;

/// <summary>
/// 进程 DACL 保护：限制标准用户终止核心服务进程。
/// 仅 SYSTEM 和 Administrators 拥有 PROCESS_TERMINATE 权限。
/// </summary>
public static class ProcessSecurity
{
    private const int WRITE_DAC = 0x40000;
    private const int READ_CONTROL = 0x20000;
    private const int PROCESS_ALL_ACCESS = 0x1F0FFF;
    private const int SE_KERNEL_OBJECT = 6;
    private const int DACL_SECURITY_INFORMATION = 4;

    /// <summary>
    /// 为进程应用保护性 DACL：仅 SYSTEM 与 Administrators 可终止进程，
    /// 标准用户（学生）taskkill 失败。
    /// </summary>
    public static Result ProtectProcess(int processId, ILogger? logger = null)
    {
        if (processId <= 0)
        {
            return Result.Failure(ErrorCode.InvalidArgument, "进程 ID 无效");
        }

        if (!ServiceSecurity.IsRunningAsAdministrator())
        {
            logger?.LogError("ProtectProcess requires administrator privileges");
            return Result.Failure(ErrorCode.AccessDenied, "需要管理员权限");
        }

        var sidSystem = IntPtr.Zero;
        var sidAdmins = IntPtr.Zero;
        var newAcl = IntPtr.Zero;
        var handle = IntPtr.Zero;

        try
        {
            handle = ProcessNative.OpenProcess(WRITE_DAC | READ_CONTROL, false, processId);
            if (handle == IntPtr.Zero)
            {
                var err = Marshal.GetLastWin32Error();
                logger?.LogError("OpenProcess({Pid}) failed: Win32Error={Error}", processId, err);
                return Result.Failure(ErrorCode.ExternalError, $"OpenProcess 失败: {err}");
            }

            // 构造 DACL：允许 SYSTEM 和 Administrators 全访问，标准用户默认无终止权限
            if (!NativeMethods.ConvertStringSidToSid("S-1-5-18", out sidSystem))
            {
                return Result.Failure(ErrorCode.ExternalError, "ConvertStringSidToSid(SYSTEM) 失败");
            }
            if (!NativeMethods.ConvertStringSidToSid("S-1-5-32-544", out sidAdmins))
            {
                return Result.Failure(ErrorCode.ExternalError, "ConvertStringSidToSid(Administrators) 失败");
            }

            var entries = new[]
            {
                new EXPLICIT_ACCESS
                {
                    grfAccessPermissions = PROCESS_ALL_ACCESS,
                    grfAccessMode = ACCESS_MODE.SET_ACCESS,
                    grfInheritance = 0,
                    Trustee = BuildTrustee(sidSystem)
                },
                new EXPLICIT_ACCESS
                {
                    grfAccessPermissions = PROCESS_ALL_ACCESS,
                    grfAccessMode = ACCESS_MODE.SET_ACCESS,
                    grfInheritance = 0,
                    Trustee = BuildTrustee(sidAdmins)
                }
            };

            var setResult = NativeMethods.SetEntriesInAcl(entries.Length, entries, IntPtr.Zero, out newAcl);
            if (setResult != 0)
            {
                logger?.LogError("SetEntriesInAcl failed: {Error}", setResult);
                return Result.Failure(ErrorCode.ExternalError, $"SetEntriesInAcl 失败: {setResult}");
            }

            var ret = ProcessNative.SetSecurityInfo(handle, SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, newAcl, IntPtr.Zero);
            if (ret != 0)
            {
                logger?.LogError("SetSecurityInfo failed: {Error}", ret);
                return Result.Failure(ErrorCode.ExternalError, $"SetSecurityInfo 失败: {ret}");
            }

            logger?.LogInformation("Process DACL applied to pid {Pid}: SYSTEM+Administrators only", processId);
            return Result.Success();
        }
        finally
        {
            if (handle != IntPtr.Zero) ProcessNative.CloseHandle(handle);
            if (sidSystem != IntPtr.Zero) NativeMethods.FreeSid(sidSystem);
            if (sidAdmins != IntPtr.Zero) NativeMethods.FreeSid(sidAdmins);
            if (newAcl != IntPtr.Zero) NativeMethods.LocalFree(newAcl);
        }
    }

    /// <summary>
    /// 保护当前进程（ControlService/GuardService 启动时调用自身）。
    /// </summary>
    public static Result ProtectCurrentProcess(ILogger? logger = null)
    {
        using var proc = System.Diagnostics.Process.GetCurrentProcess();
        return ProtectProcess(proc.Id, logger);
    }

    private static TRUSTEE BuildTrustee(IntPtr sid)
    {
        return new TRUSTEE
        {
            TrusteeForm = TRUSTEE_FORM.TRUSTEE_IS_SID,
            TrusteeType = TRUSTEE_TYPE.TRUSTEE_IS_GROUP,
            ptstrName = sid
        };
    }

    private static class ProcessNative
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int SetSecurityInfo(
            IntPtr handle, int ObjectType, int SecurityInfo,
            IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
}
