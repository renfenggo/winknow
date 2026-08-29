using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Extensions.Logging;

namespace Winknow.Security;

/// <summary>
/// 服务 DACL 加固器：限制标准用户停止/禁用 Winknow 服务。
/// 只有 SYSTEM 和 Administrators 可以控制服务。
/// </summary>
public sealed class ServiceDaclProtector
{
    private readonly ILogger<ServiceDaclProtector>? _logger;

    /// <summary>创建服务 DACL 加固器。</summary>
    /// <param name="logger">可选的日志记录器。</param>
    public ServiceDaclProtector(ILogger<ServiceDaclProtector>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// 加固服务 DACL：仅 SYSTEM 和 Administrators 可控制。
    /// </summary>
    /// <param name="serviceName">服务名称。</param>
    /// <returns>true 表示成功。</returns>
    public bool Harden(string serviceName)
    {
        try
        {
            // DACL SDDL: SYSTEM 和 Administrators 完全控制，其他用户只读
            // D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)
            // SY = SYSTEM, BA = Built-in Administrators, IU = Interactive Users (只读)
            var sddl = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)" +
                       "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" +
                       "(A;;CCLCSWLOCRRC;;;IU)";

            // 使用 sc.exe 设置服务安全描述符
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"sdset \"{serviceName}\" \"{sddl}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc is null)
            {
                return false;
            }

            proc.WaitForExit(5000);
            var output = proc.StandardOutput.ReadToEnd();

            if (proc.ExitCode == 0)
            {
                _logger?.LogWarning("Service DACL hardened: {Service}", serviceName);
                return true;
            }

            _logger?.LogError("Failed to set DACL for {Service}: {Output}", serviceName, output);
            return false;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error hardening service DACL: {Service}", serviceName);
            return false;
        }
    }

    /// <summary>
    /// 禁用服务的停止命令（通过拒绝 Everyone 的 STOP 权限）。
    /// </summary>
    public bool DisableStopForUsers(string serviceName)
    {
        try
        {
            // 设置拒绝标准用户停止服务
            var sddl = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)" +
                       "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" +
                       "(A;;CCLCSWLOCRRC;;;IU)" +
                       "(D;;WPDTLO;;;IU)";  // 拒绝 Interactive Users 停止/暂停

            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"sdset \"{serviceName}\" \"{sddl}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            proc?.WaitForExit(5000);

            if (proc?.ExitCode == 0)
            {
                _logger?.LogWarning("Stop disabled for users on service: {Service}", serviceName);
                return true;
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error disabling stop for users: {Service}", serviceName);
            return false;
        }
    }

    /// <summary>
    /// 检查服务是否正在运行。
    /// </summary>
    public bool IsServiceRunning(string serviceName)
    {
        try
        {
            using var sc = new ServiceController(serviceName);
            return sc.Status == ServiceControllerStatus.Running;
        }
        catch
        {
            return false;
        }
    }
}
