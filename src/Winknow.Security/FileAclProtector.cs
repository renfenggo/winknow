using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;

namespace Winknow.Security;

/// <summary>
/// 文件 ACL 保护器：保护 Winknow 程序文件不被修改/删除。
/// 仅 SYSTEM 和 Administrators 可写入，标准用户只读。
/// </summary>
public sealed class FileAclProtector
{
    private readonly ILogger<FileAclProtector>? _logger;

    /// <summary>创建文件 ACL 保护器。</summary>
    /// <param name="logger">可选的日志记录器。</param>
    public FileAclProtector(ILogger<FileAclProtector>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// 保护单个文件：SYSTEM+Admins 完全控制，Users 只读。
    /// </summary>
    public bool ProtectFile(string filePath)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            var security = fileInfo.GetAccessControl();

            // 清除现有规则
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

            // SYSTEM: 完全控制
            security.AddAccessRule(new FileSystemAccessRule(
                system,
                FileSystemRights.FullControl,
                AccessControlType.Allow));

            // Administrators: 完全控制
            security.AddAccessRule(new FileSystemAccessRule(
                admins,
                FileSystemRights.FullControl,
                AccessControlType.Allow));

            // Users: 只读 + 执行
            security.AddAccessRule(new FileSystemAccessRule(
                users,
                FileSystemRights.Read | FileSystemRights.ExecuteFile,
                AccessControlType.Allow));

            fileInfo.SetAccessControl(security);

            _logger?.LogInformation("File protected: {Path}", filePath);
            return true;
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger?.LogError(ex, "Access denied protecting file: {Path}", filePath);
            return false;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error protecting file: {Path}", filePath);
            return false;
        }
    }

    /// <summary>
    /// 保护目录及其下所有文件。
    /// </summary>
    public bool ProtectDirectory(string directoryPath, bool recursive = true)
    {
        try
        {
            var dirInfo = new DirectoryInfo(directoryPath);
            var security = dirInfo.GetAccessControl();

            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

            security.AddAccessRule(new FileSystemAccessRule(
                system, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));

            security.AddAccessRule(new FileSystemAccessRule(
                admins, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));

            security.AddAccessRule(new FileSystemAccessRule(
                users, FileSystemRights.Read | FileSystemRights.ExecuteFile, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));

            dirInfo.SetAccessControl(security);

            if (recursive)
            {
                foreach (var file in dirInfo.GetFiles("*", SearchOption.AllDirectories))
                {
                    ProtectFile(file.FullName);
                }
            }

            _logger?.LogWarning("Directory protected: {Path}", directoryPath);
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error protecting directory: {Path}", directoryPath);
            return false;
        }
    }
}
