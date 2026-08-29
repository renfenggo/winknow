using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using Winknow.Core.Results;

namespace Winknow.Security;

/// <summary>
/// 服务 DACL 保护：限制标准用户停止/修改/删除核心服务。
/// 仅 SYSTEM 和 Administrators 拥有服务控制权限。
/// </summary>
public static class ServiceSecurity
{
    private const int SC_MANAGER_CONNECT = 0x0001;
    private const int SERVICE_QUERY_CONFIG = 0x0004;
    private const int SERVICE_CHANGE_CONFIG = 0x0002;
    private const int SERVICE_ALL_ACCESS = 0xF01FF;
    private const int SERVICE_CONFIG_DACL = 4;
    private const int SECURITY_DESCRIPTOR_REVISION = 1;

    /// <summary>
    /// 为服务应用保护性 DACL：仅 SYSTEM 与 Administrators 可控制服务，
    /// 标准用户（学生）无法 Stop-Service、sc stop、sc delete。
    /// 需管理员权限运行。
    /// </summary>
    public static Result ApplyServiceProtection(string serviceName, ILogger? logger = null)
    {
        if (string.IsNullOrWhiteSpace(serviceName))
        {
            return Result.Failure(ErrorCode.InvalidArgument, "服务名不能为空");
        }

        if (!IsRunningAsAdministrator())
        {
            logger?.LogError("ApplyServiceProtection requires administrator privileges");
            return Result.Failure(ErrorCode.AccessDenied, "需要管理员权限");
        }

        var sidSystem = IntPtr.Zero;
        var sidAdmins = IntPtr.Zero;
        var newAcl = IntPtr.Zero;
        var sd = IntPtr.Zero;

        try
        {
            var scm = NativeMethods.OpenSCManager(null, null, SC_MANAGER_CONNECT);
            if (scm == IntPtr.Zero)
            {
                var err = Marshal.GetLastWin32Error();
                logger?.LogError("OpenSCManager failed: Win32Error={Error}", err);
                return Result.Failure(ErrorCode.ExternalError, $"OpenSCManager 失败: {err}");
            }

            try
            {
                var service = NativeMethods.OpenService(scm, serviceName,
                    SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG);
                if (service == IntPtr.Zero)
                {
                    var err = Marshal.GetLastWin32Error();
                    logger?.LogError("OpenService({Name}) failed: Win32Error={Error}", serviceName, err);
                    return Result.Failure(ErrorCode.ExternalError, $"OpenService 失败: {err}");
                }

                try
                {
                    // 1. 构造 DACL：允许 SYSTEM 和 Administrators 全访问，标准用户默认无权限
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
                            grfAccessPermissions = SERVICE_ALL_ACCESS,
                            grfAccessMode = ACCESS_MODE.SET_ACCESS,
                            grfInheritance = 0,
                            Trustee = BuildTrustee(sidSystem)
                        },
                        new EXPLICIT_ACCESS
                        {
                            grfAccessPermissions = SERVICE_ALL_ACCESS,
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

                    // 2. 构造自相对 SECURITY_DESCRIPTOR 并设置 DACL
                    sd = Marshal.AllocHGlobal(NativeMethods.SECURITY_DESCRIPTOR_MIN_LENGTH);
                    if (!NativeMethods.InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION))
                    {
                        return Result.Failure(ErrorCode.ExternalError, "InitializeSecurityDescriptor 失败");
                    }
                    if (!NativeMethods.SetSecurityDescriptorDacl(sd, true, newAcl, false))
                    {
                        var err = Marshal.GetLastWin32Error();
                        return Result.Failure(ErrorCode.ExternalError, $"SetSecurityDescriptorDacl 失败: {err}");
                    }

                    // 3. 应用到服务（SERVICE_CONFIG_DACL 的 lpInfo 指向 SERVICE_DACL，其 Dacl 字段为 PSECURITY_DESCRIPTOR）
                    var daclInfo = new SERVICE_DACL_INFO { Dacl = sd };
                    if (!NativeMethods.ChangeServiceConfig2(service, SERVICE_CONFIG_DACL, ref daclInfo))
                    {
                        var err = Marshal.GetLastWin32Error();
                        logger?.LogError("ChangeServiceConfig2(DACL) failed: Win32Error={Error}", err);
                        return Result.Failure(ErrorCode.ExternalError, $"ChangeServiceConfig2(DACL) 失败: {err}");
                    }

                    logger?.LogInformation("Service DACL applied to {Name}: SYSTEM+Administrators only", serviceName);
                    return Result.Success();
                }
                finally
                {
                    NativeMethods.CloseServiceHandle(service);
                }
            }
            finally
            {
                NativeMethods.CloseServiceHandle(scm);
            }
        }
        finally
        {
            if (sidSystem != IntPtr.Zero) NativeMethods.FreeSid(sidSystem);
            if (sidAdmins != IntPtr.Zero) NativeMethods.FreeSid(sidAdmins);
            if (newAcl != IntPtr.Zero) NativeMethods.LocalFree(newAcl);
            if (sd != IntPtr.Zero) Marshal.FreeHGlobal(sd);
        }
    }

    /// <summary>
    /// 检查当前进程是否以管理员级权限运行。
    /// 识别 LocalSystem（Windows 服务默认运行身份）与 Administrators 组成员，
    /// 两者均具备应用服务/进程保护所需的权限。
    /// </summary>
    public static bool IsRunningAsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        // LocalSystem（NT AUTHORITY\SYSTEM）具备 SCM/进程 DACL 写入权限
        if (string.Equals(identity.Name, "NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
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
}

[StructLayout(LayoutKind.Sequential)]
internal struct SERVICE_DACL_INFO
{
    public IntPtr Dacl;
}

internal enum TRUSTEE_FORM
{
    TRUSTEE_IS_SID = 0
}

internal enum TRUSTEE_TYPE
{
    TRUSTEE_IS_GROUP = 1
}

internal enum ACCESS_MODE
{
    SET_ACCESS = 2
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct TRUSTEE
{
    public IntPtr pMultipleTrustee;
    public TRUSTEE_FORM TrusteeForm;
    public TRUSTEE_TYPE TrusteeType;
    public IntPtr ptstrName;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct EXPLICIT_ACCESS
{
    public int grfAccessPermissions;
    public ACCESS_MODE grfAccessMode;
    public int grfInheritance;
    public TRUSTEE Trustee;
}

internal static class NativeMethods
{
    public const int SECURITY_DESCRIPTOR_MIN_LENGTH = 40;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr OpenSCManager(string? lpMachineName, string? lpDatabaseName, int dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, int dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ChangeServiceConfig2(IntPtr hService, int dwInfoLevel, ref SERVICE_DACL_INFO lpInfo);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int SetEntriesInAcl(int cCount, EXPLICIT_ACCESS[] pAccess, IntPtr oldAcl, out IntPtr newAcl);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ConvertStringSidToSid(string stringSid, out IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool InitializeSecurityDescriptor(IntPtr pSecurityDescriptor, int dwRevision);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetSecurityDescriptorDacl(IntPtr pSecurityDescriptor, [MarshalAs(UnmanagedType.Bool)] bool daclPresent, IntPtr dacl, [MarshalAs(UnmanagedType.Bool)] bool daclDefaulted);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern void FreeSid(IntPtr pSid);
}
