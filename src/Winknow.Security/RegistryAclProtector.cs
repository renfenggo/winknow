using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Winknow.Security;

/// <summary>
/// 注册表 ACL 保护器：保护 Winknow 注册表键不被修改。
/// 保护 Run 键（防止自启动项被篡改）和 Winknow 服务配置。
/// </summary>
public sealed class RegistryAclProtector
{
    private readonly ILogger<RegistryAclProtector>? _logger;

    /// <summary>创建注册表 ACL 保护器。</summary>
    /// <param name="logger">可选的日志记录器。</param>
    public RegistryAclProtector(ILogger<RegistryAclProtector>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// 保护注册表键：SYSTEM+Admins 完全控制，Users 只读。
    /// </summary>
    public bool ProtectKey(RegistryKey baseKey, string subKeyPath)
    {
        try
        {
            using var key = baseKey.OpenSubKey(subKeyPath, writable: true);
            if (key is null)
            {
                _logger?.LogWarning("Registry key not found: {Path}", subKeyPath);
                return false;
            }

            var security = key.GetAccessControl();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

            // SYSTEM: 完全控制
            security.AddAccessRule(new RegistryAccessRule(
                system,
                RegistryRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            // Administrators: 完全控制
            security.AddAccessRule(new RegistryAccessRule(
                admins,
                RegistryRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            // Users: 只读
            security.AddAccessRule(new RegistryAccessRule(
                users,
                RegistryRights.ReadKey,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            key.SetAccessControl(security);

            _logger?.LogWarning("Registry key protected: {Path}", subKeyPath);
            return true;
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger?.LogError(ex, "Access denied protecting registry: {Path}", subKeyPath);
            return false;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error protecting registry: {Path}", subKeyPath);
            return false;
        }
    }

    /// <summary>
    /// 保护 Winknow 服务注册表配置。
    /// </summary>
    public bool ProtectWinknowServiceKeys()
    {
        var allProtected = true;

        // 保护服务配置
        var servicePath = @"SYSTEM\CurrentControlSet\Services\Winknow Control Service";
        allProtected &= ProtectKey(Registry.LocalMachine, servicePath);

        var guardPath = @"SYSTEM\CurrentControlSet\Services\Winknow Guard Service";
        allProtected &= ProtectKey(Registry.LocalMachine, guardPath);

        // 保护 Winknow 策略注册表
        var policyPath = @"SOFTWARE\Winknow\V7.0";
        using var policyKey = Registry.LocalMachine.CreateSubKey(policyPath);
        allProtected &= ProtectKey(Registry.LocalMachine, policyPath);

        return allProtected;
    }
}
