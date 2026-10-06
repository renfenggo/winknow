using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Winknow.CodeRunner.Sandbox;

/// <summary>
/// 每请求独立临时工作区（ADR-003）：
/// 仅当前用户显式 FullControl（切断继承 ACL）+ 低完整性标签（允许低完整性学生进程写入；
/// 目录之外的中完整性对象对同一进程 NO_WRITE_UP 只读）。
/// 用毕 <see cref="TryCleanup"/> 递归清除并上报 artifacts_cleaned。
/// </summary>
public sealed class RunnerWorkspace : IDisposable
{
    private bool _cleaned;

    private RunnerWorkspace(string directory)
    {
        Directory = directory;
    }

    /// <summary>工作区绝对路径。</summary>
    public string Directory { get; }

    /// <summary>
    /// 在 runner 根目录下创建一次性工作区（目录名 = 时间戳 + 随机后缀，请求 ID 只用于审计不进路径）。
    /// </summary>
    /// <param name="runnerRoot">runner 根目录（ProductPaths.RunnerWork）。</param>
    /// <returns>已建好 ACL 与完整性标签的工作区。</returns>
    public static RunnerWorkspace Create(string runnerRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runnerRoot);

        System.IO.Directory.CreateDirectory(runnerRoot);
        var directory = Path.Combine(runnerRoot, $"run-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}");

        var identity = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("failed to resolve current user sid.");
        var security = new DirectorySecurity();
        security.SetOwner(identity);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false); // 不继承父目录 ACL
        security.AddAccessRule(new FileSystemAccessRule(
            identity, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));

        var dirInfo = System.IO.Directory.CreateDirectory(directory);
        dirInfo.SetAccessControl(security);
        SetLowIntegrityLabel(directory);

        return new RunnerWorkspace(directory);
    }

    /// <summary>递归删除工作区（尽力而为，短重试）。</summary>
    /// <returns>是否完全清除。</returns>
    public bool TryCleanup()
    {
        if (_cleaned)
        {
            return true;
        }

        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                if (!System.IO.Directory.Exists(Directory))
                {
                    break;
                }

                System.IO.Directory.Delete(Directory, recursive: true);
                break;
            }
            catch (IOException)
            {
                Thread.Sleep(100); // 句柄延迟释放（AV 扫描等）
            }
            catch (UnauthorizedAccessException)
            {
                break; // ACL 异常不重试
            }
        }

        _cleaned = true;
        return !System.IO.Directory.Exists(Directory);
    }

    /// <summary>未显式清理时释放兜底（不等待、不重试）。</summary>
    public void Dispose()
    {
        if (!_cleaned)
        {
            try
            {
                if (System.IO.Directory.Exists(Directory))
                {
                    System.IO.Directory.Delete(Directory, recursive: true);
                }
            }
            catch (IOException)
            {
                // 句柄未释放，留给周期清理
            }
            catch (UnauthorizedAccessException)
            {
                // 忽略
            }

            _cleaned = true;
        }
    }

    /// <summary>
    /// 给目录设置低完整性强制标签（SACL LABEL_SECURITY_INFORMATION）。
    /// 学生进程运行于低完整性：与其完整性相同的对象不受 NO_WRITE_UP 约束 → 工作区可写。
    /// </summary>
    private static void SetLowIntegrityLabel(string directory)
    {
        if (!NativeMethods.ConvertStringSidToSidW(RestrictedTokenSource.LowIntegritySid, out var sid))
        {
            throw new Win32Exception();
        }

        try
        {
            // ACL 头(8) + SYSTEM_MANDATORY_LABEL_ACE(4+4) + SID(12)，4 字节对齐
            var sidLength = 8 + Marshal.ReadByte(sid, 1) * 4;
            var aclSize = 8 + 8 + sidLength;
            var acl = Marshal.AllocHGlobal(aclSize);
            try
            {
                var offset = 0;
                Marshal.WriteByte(acl, offset, 4); // ACL_REVISION_DS（标签 ACE 需要）
                Marshal.WriteByte(acl, offset + 1, 0);
                Marshal.WriteInt16(acl, offset + 2, (short)aclSize);
                Marshal.WriteInt16(acl, offset + 4, 1); // AceCount
                Marshal.WriteInt16(acl, offset + 6, 0);

                offset += 8;
                Marshal.WriteByte(acl, offset, 0x11); // SYSTEM_MANDATORY_LABEL_ACE_TYPE
                Marshal.WriteByte(acl, offset + 1, 0); // AceFlags
                Marshal.WriteInt16(acl, offset + 2, (short)(8 + sidLength)); // AceSize
                Marshal.WriteInt32(acl, offset + 4, 0); // Mask：同完整性级别不受限

                offset += 8;
                var sidBytes = new byte[sidLength];
                Marshal.Copy(sid, sidBytes, 0, sidLength);
                Marshal.Copy(sidBytes, 0, acl + offset, sidLength);

                const int seFileObject = 1;
                const uint labelSecurityInformation = 0x10;
                var rc = NativeMethods.SetNamedSecurityInfoW(directory, seFileObject, labelSecurityInformation,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, acl);
                if (rc != 0)
                {
                    throw new Win32Exception(unchecked((int)rc));
                }
            }
            finally
            {
                Marshal.FreeHGlobal(acl);
            }
        }
        finally
        {
            // ConvertStringSidToSidW 用 LocalAlloc 分配，须用 LocalFree 释放
            NativeMethods.LocalFree(sid);
        }
    }
}
