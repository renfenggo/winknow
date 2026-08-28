using System.Diagnostics;
using System.Management;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Winknow.ProcessControl;

/// <summary>
/// 进程信息采集器：路径 + 签名 + Hash + 用户 + 父进程 + 命令行。
/// </summary>
internal static class ProcessInfoCollector
{
    /// <summary>
    /// 采集指定进程的完整信息。
    /// </summary>
    public static ProcessInfo Collect(int processId, string processName = "", string? sid = null)
    {
        string filePath = string.Empty;
        string commandLine = string.Empty;
        int parentProcessId = 0;
        string userName = string.Empty;
        DateTime startTime = DateTime.MinValue;

        try
        {
            using var proc = Process.GetProcessById(processId);
            processName = processName.Length > 0 ? processName : proc.ProcessName;

            try
            {
                filePath = proc.MainModule?.FileName ?? string.Empty;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // 64位进程无法从32位代码读取，或权限不足
            }
            catch (InvalidOperationException)
            {
                // 进程已退出
            }

            try
            {
                startTime = proc.StartTime;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // 权限不足或进程已退出
            }
        }
        catch (ArgumentException)
        {
            return new ProcessInfo
            {
                ProcessId = processId,
                ProcessName = processName,
                UserSid = sid ?? string.Empty
            };
        }

        // 通过 WMI 获取命令行和父进程
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT ProcessId, ParentProcessId, CommandLine FROM Win32_Process WHERE ProcessId = {processId}");

            foreach (var mo in searcher.Get().Cast<ManagementObject>())
            {
                commandLine = mo["CommandLine"]?.ToString() ?? string.Empty;
                parentProcessId = Convert.ToInt32(mo["ParentProcessId"]);
                break;
            }
        }
        catch (Exception)
        {
            // WMI 查询失败，忽略
        }

        // 获取用户名
        if (!string.IsNullOrEmpty(sid))
        {
            try
            {
                userName = GetUserNameFromSid(sid);
            }
            catch
            {
                // SID 转换失败，忽略
            }
        }

        // 计算文件 Hash
        var fileHash = string.Empty;
        if (!string.IsNullOrEmpty(filePath) && File.Exists(filePath))
        {
            try
            {
                fileHash = ComputeFileHash(filePath);
            }
            catch (Exception)
            {
                // Hash 计算失败，忽略
            }
        }

        // 获取数字签名
        var signatureSubject = string.Empty;
        if (!string.IsNullOrEmpty(filePath))
        {
            try
            {
                signatureSubject = GetFileSignatureSubject(filePath);
            }
            catch (Exception)
            {
                // 签名验证失败，忽略
            }
        }

        return new ProcessInfo
        {
            ProcessId = processId,
            ProcessName = processName,
            FilePath = filePath,
            CommandLine = commandLine,
            ParentProcessId = parentProcessId,
            UserSid = sid ?? string.Empty,
            UserName = userName,
            FileHash = fileHash,
            SignatureSubject = signatureSubject,
            StartTime = startTime
        };
    }

    /// <summary>
    /// 计算 SHA-256 文件哈希。
    /// </summary>
    public static string ComputeFileHash(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// 获取文件数字签名主体名称（简化版）。
    /// </summary>
    public static string GetFileSignatureSubject(string filePath)
    {
        try
        {
            var cert = new X509Certificate2(filePath);
            return cert.Subject;
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// SID 转用户名。
    /// </summary>
    public static string GetUserNameFromSid(string sid)
    {
        var sidObj = new System.Security.Principal.SecurityIdentifier(sid);
        return sidObj.Translate(typeof(System.Security.Principal.NTAccount)).Value;
    }
}
