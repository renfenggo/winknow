using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Winknow.CodeRunner.Sandbox;

/// <summary>
/// 沙箱受限令牌构造器（ADR-003：Restricted Token）。
/// 从当前进程令牌派生：禁用全部特权（DISABLE_MAX_PRIVILEGE）+ 组 SID 转为 deny-only
/// （保留 Everyone 以维持系统目录读）+ 完整性级别降为 Low（NO_WRITE_UP：
/// 低完整性进程无法写入中完整性对象——用户目录/配置文件天然只读）。
/// 生产部署可由安装器改用专用 WinknowRunner 账号（见 ADR-003 偏差记录）。
/// </summary>
public static class RestrictedTokenSource
{
    private const uint TokenAllAccess = 0x000F_01FF;
    private const int TokenPrimary = 1;
    private const int SecurityImpersonation = 2;

    private const int TokenGroupsClass = 2;
    private const int TokenPrivilegesClass = 3;
    private const int TokenUserClass = 1;
    // TOKEN_INFORMATION_CLASS：25=TokenIntegrityLevel（TOKEN_MANDATORY_LABEL，读/写同码）；
    // 26 是 TokenUIAccess（ULONG），误用会导致 4 字节缓冲被当 16 字节结构解析
    private const int TokenIntegrityLevelClass = 25;

    private const uint DisableMaxPrivilege = 0x1;

    private const uint SeGroupEnabled = 0x0000_0004;
    private const uint SeGroupEnabledByDefault = 0x0000_0001;
    private const uint SeGroupIntegrity = 0x0000_0020;
    private const uint SeGroupLogonId = 0xC000_0000;
    private const uint SePrivilegeEnabled = 0x0000_0002;

    /// <summary>SeChangeNotifyPrivilege 的 LUID（23；8 是 SeSecurityPrivilege，勿混）。</summary>
    private const long SeChangeNotifyLuid = 23;

    /// <summary>低完整性级别 SID（S-1-16-4096）。</summary>
    public const string LowIntegritySid = "S-1-16-4096";

    /// <summary>
    /// 构造沙箱令牌：无可用特权 + 组 deny-only（Everyone 除外）+ 低完整性。
    /// 调用方负责释放返回的句柄（Dispose）。
    /// </summary>
    /// <returns>可直接用于 CreateProcessAsUser 的主令牌句柄。</returns>
    public static SafeAccessTokenHandle CreateSandboxToken()
    {
        if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), TokenAllAccess, out var currentToken))
        {
            throw new Win32Exception();
        }

        try
        {
            if (!NativeMethods.DuplicateTokenEx(currentToken, TokenAllAccess, IntPtr.Zero,
                    SecurityImpersonation, TokenPrimary, out var primary))
            {
                throw new Win32Exception();
            }

            try
            {
                var (disableList, disableCount) = BuildDisableSidList(primary);
                var restricted = CreateRestricted(primary, disableList, disableCount);
                try
                {
                    SetLowIntegrity(restricted);
                    return new SafeAccessTokenHandle(restricted);
                }
                catch
                {
                    NativeMethods.CloseHandle(restricted);
                    throw;
                }
            }
            finally
            {
                NativeMethods.CloseHandle(primary);
            }
        }
        finally
        {
            NativeMethods.CloseHandle(currentToken);
        }
    }

    /// <summary>查询令牌完整性级别 SID 字符串（测试与审计用）。</summary>
    /// <param name="token">令牌句柄。</param>
    /// <returns>形如 S-1-16-xxxx 的 SID 字符串。</returns>
    public static string QueryIntegrityLevel(SafeAccessTokenHandle token)
    {
        ArgumentNullException.ThrowIfNull(token);

        NativeMethods.GetTokenInformation(token.DangerousGetHandle(), TokenIntegrityLevelClass,
            IntPtr.Zero, 0, out var length);
        var buffer = Marshal.AllocHGlobal((int)length);
        try
        {
            if (!NativeMethods.GetTokenInformation(token.DangerousGetHandle(), TokenIntegrityLevelClass,
                    buffer, length, out _))
            {
                throw new Win32Exception();
            }

            var label = Marshal.PtrToStructure<NativeMethods.TOKEN_MANDATORY_LABEL>(buffer);
            if (!NativeMethods.ConvertSidToStringSidW(label.Sid, out var sidString))
            {
                throw new Win32Exception();
            }

            try
            {
                return Marshal.PtrToStringUni(sidString) ?? string.Empty;
            }
            finally
            {
                NativeMethods.LocalFree(sidString);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>统计令牌中已启用的危险特权数量（沙箱令牌应为 0）。</summary>
    /// <param name="token">令牌句柄。</param>
    /// <returns>启用特权数（不含 SeChangeNotifyPrivilege——系统对受限令牌按设计保留它，
    /// 该特权等价于 Everyone 的遍历豁免，无安全影响）。</returns>
    public static int CountEnabledPrivileges(SafeAccessTokenHandle token)
    {
        ArgumentNullException.ThrowIfNull(token);

        NativeMethods.GetTokenInformation(token.DangerousGetHandle(), TokenPrivilegesClass,
            IntPtr.Zero, 0, out var length);
        var buffer = Marshal.AllocHGlobal((int)length);
        try
        {
            if (!NativeMethods.GetTokenInformation(token.DangerousGetHandle(), TokenPrivilegesClass,
                    buffer, length, out _))
            {
                throw new Win32Exception();
            }

            // TOKEN_PRIVILEGES: PrivilegeCount(4) + LUID_AND_ATTRIBUTES{LUID(8)+Attributes(4)} 数组
            var count = Marshal.ReadInt32(buffer);
            var enabled = 0;
            for (var i = 0; i < count; i++)
            {
                var luid = Marshal.ReadInt64(buffer, sizeof(int) + i * 12);
                if (luid == SeChangeNotifyLuid)
                {
                    continue; // 系统保留项，非危险特权
                }

                var attributes = (uint)Marshal.ReadInt32(buffer, sizeof(int) + i * 12 + 8);
                if ((attributes & SePrivilegeEnabled) != 0)
                {
                    enabled++;
                }
            }

            return enabled;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static (IntPtr List, int Count) BuildDisableSidList(IntPtr token)
    {
        NativeMethods.GetTokenInformation(token, TokenGroupsClass, IntPtr.Zero, 0, out var length);
        var buffer = Marshal.AllocHGlobal((int)length);
        try
        {
            if (!NativeMethods.GetTokenInformation(token, TokenGroupsClass, buffer, length, out _))
            {
                throw new Win32Exception();
            }

            // TOKEN_GROUPS: GroupCount(4) + [x64 对齐填充 4] + SID_AND_ATTRIBUTES 数组
            // 数组起始偏移 = 指针大小（x64=8，x86=4），直接用 4 会错位读出垃圾 SID 指针
            var count = Marshal.ReadInt32(buffer);
            var arrayOffset = IntPtr.Size;
            if (!NativeMethods.ConvertStringSidToSidW("S-1-1-0", out var everyone))
            {
                throw new Win32Exception();
            }

            // TokenUser：用户 SID 指针指向查询缓冲内部，缓冲须存活到比较结束
            NativeMethods.GetTokenInformation(token, TokenUserClass, IntPtr.Zero, 0, out var userLength);
            var userBuffer = Marshal.AllocHGlobal((int)userLength);
            try
            {
                if (!NativeMethods.GetTokenInformation(token, TokenUserClass, userBuffer, userLength, out _))
                {
                    throw new Win32Exception();
                }

                var userSid = Marshal.ReadIntPtr(userBuffer);
                var entrySize = Marshal.SizeOf<NativeMethods.SID_AND_ATTRIBUTES>();
                var disabled = new List<IntPtr>();
                for (var i = 0; i < count; i++)
                {
                    var entry = Marshal.PtrToStructure<NativeMethods.SID_AND_ATTRIBUTES>(buffer + arrayOffset + i * entrySize);
                    if ((entry.Attributes & SeGroupIntegrity) != 0)
                    {
                        continue; // 完整性 SID 由 SetTokenInformation 单独管理
                    }

                    if ((entry.Attributes & SeGroupLogonId) != 0)
                    {
                        continue; // 登录会话 SID：deny 会破坏会话资源（窗口站等）访问
                    }

                    if ((entry.Attributes & (SeGroupEnabled | SeGroupEnabledByDefault)) == 0)
                    {
                        continue; // 本就未启用的组无需 deny-only
                    }

                    if (NativeMethods.EqualSid(entry.Sid, everyone))
                    {
                        continue; // Everyone 保留：系统目录（System32 等）读权限依赖
                    }

                    if (userSid != IntPtr.Zero && NativeMethods.EqualSid(entry.Sid, userSid))
                    {
                        continue; // 用户 SID 保留：工作区 ACL 与工具链（用户目录）访问依赖
                    }

                    disabled.Add(entry.Sid);
                }

                if (disabled.Count == 0)
                {
                    return (IntPtr.Zero, 0);
                }

                var list = Marshal.AllocHGlobal(disabled.Count * entrySize);
                for (var i = 0; i < disabled.Count; i++)
                {
                    Marshal.StructureToPtr(new NativeMethods.SID_AND_ATTRIBUTES { Sid = disabled[i], Attributes = 0 },
                        list + i * entrySize, false);
                }

                return (list, disabled.Count);
            }
            finally
            {
                Marshal.FreeHGlobal(userBuffer);
                // ConvertStringSidToSidW 用 LocalAlloc 分配，须用 LocalFree 释放
                NativeMethods.LocalFree(everyone);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IntPtr CreateRestricted(IntPtr token, IntPtr sidsToDisable, int disableCount)
    {
        try
        {
            if (!NativeMethods.CreateRestrictedToken(token, DisableMaxPrivilege,
                    (uint)disableCount, sidsToDisable,
                    0, IntPtr.Zero, 0, IntPtr.Zero, out var restricted))
            {
                throw new Win32Exception();
            }

            return restricted;
        }
        finally
        {
            if (sidsToDisable != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(sidsToDisable);
            }
        }
    }

    /// <summary>
    /// 把指定进程的令牌完整性降为 Low（须在挂起态、任何用户代码运行前调用）。
    /// 降级路径专用：非特权环境无法用受限令牌启动进程时，以调用方令牌启动后改降完整性，
    /// NO_WRITE_UP（工作区外只读）隔离仍然成立。
    /// </summary>
    /// <param name="processHandle">目标进程句柄（挂起态子进程）。</param>
    public static void LowerProcessTokenIntegrity(IntPtr processHandle)
    {
        // 实证（diag 矩阵 V6/V7）：TOKEN_ADJUST_DEFAULT|TOKEN_QUERY(0x108) 打开的令牌
        // SetTokenInformation 降 IL 报拒绝访问(5)，TOKEN_ALL_ACCESS(0xF01FF) 才可行
        if (!NativeMethods.OpenProcessToken(processHandle, TokenAllAccess, out var token))
        {
            throw new Win32Exception();
        }

        try
        {
            SetLowIntegrity(token);
        }
        finally
        {
            NativeMethods.CloseHandle(token);
        }
    }

    private static void SetLowIntegrity(IntPtr token)
    {
        if (!NativeMethods.ConvertStringSidToSidW(LowIntegritySid, out var sid))
        {
            throw new Win32Exception();
        }

        try
        {
            var label = new NativeMethods.TOKEN_MANDATORY_LABEL
            {
                Sid = sid,
                Attributes = SeGroupIntegrity,
            };
            var size = Marshal.SizeOf<NativeMethods.TOKEN_MANDATORY_LABEL>() + GetSidLength(sid);
            if (!NativeMethods.SetTokenInformation(token, TokenIntegrityLevelClass, ref label, (uint)size))
            {
                throw new Win32Exception();
            }
        }
        finally
        {
            NativeMethods.LocalFree(sid);
        }
    }

    private static int GetSidLength(IntPtr sid)
    {
        // SID 布局：Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthority(4×N)
        var subAuthorities = Marshal.ReadByte(sid, 1);
        return 8 + subAuthorities * 4;
    }
}

/// <summary>
/// 受限令牌句柄包装（进程启动用；Dispose 关闭底层句柄）。
/// </summary>
public sealed class SafeAccessTokenHandle : IDisposable
{
    /// <summary>创建句柄包装。</summary>
    /// <param name="handle">Win32 令牌句柄。</param>
    public SafeAccessTokenHandle(IntPtr handle)
    {
        Handle = handle;
    }

    /// <summary>底层 Win32 句柄。</summary>
    public IntPtr Handle { get; private set; }

    /// <summary>内部访问：P/Invoke 直用句柄。</summary>
    internal IntPtr DangerousGetHandle() => Handle;

    /// <summary>关闭句柄（幂等）。</summary>
    public void Dispose()
    {
        if (Handle != IntPtr.Zero)
        {
            NativeMethods.CloseHandle(Handle);
            Handle = IntPtr.Zero;
        }
    }
}
