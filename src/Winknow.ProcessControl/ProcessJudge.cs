using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Winknow.Core.Results;

namespace Winknow.ProcessControl;

/// <summary>
/// 综合判断引擎：路径 + 签名 + Hash + 用户 + 父进程 + 命令行。
/// </summary>
public sealed class ProcessJudge
{
    private readonly ILogger<ProcessJudge>? _logger;
    private readonly WhitelistRuleSet _whitelist;

    /// <summary>创建综合判断引擎。</summary>
    /// <param name="whitelist">白名单规则集。</param>
    /// <param name="logger">可选的日志记录器。</param>
    public ProcessJudge(WhitelistRuleSet whitelist, ILogger<ProcessJudge>? logger = null)
    {
        _whitelist = whitelist ?? throw new ArgumentNullException(nameof(whitelist));
        _logger = logger;
    }

    /// <summary>
    /// 判断进程是否允许运行。
    /// </summary>
    /// <returns>Success = 允许运行；Failure = 应终止，ErrorMessage 为原因。</returns>
    public Result<ProcessInfo> Judge(ProcessInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);

        // 1. 系统关键进程直接放行
        if (IsSystemCriticalProcess(info))
        {
            return Result<ProcessInfo>.Success(info);
        }

        // 2. 路径匹配检查
        if (!IsPathAllowed(info.FilePath, out var matchRule))
        {
            _logger?.LogWarning("Process blocked (path not allowed): {Pid} {Path}",
                info.ProcessId, info.FilePath);
            return Result<ProcessInfo>.Failure(ErrorCode.ProcessBlocked, $"Path not in whitelist: {info.FilePath}");
        }

        // 3. Hash 校验
        if (!string.IsNullOrEmpty(matchRule!.ExpectedHash) &&
            !string.Equals(info.FileHash, matchRule.ExpectedHash, StringComparison.OrdinalIgnoreCase))
        {
            _logger?.LogWarning("Process blocked (hash mismatch): {Pid} {Path} expected={Expected} actual={Actual}",
                info.ProcessId, info.FilePath, matchRule.ExpectedHash, info.FileHash);
            return Result<ProcessInfo>.Failure(ErrorCode.ProcessBlocked, "File hash mismatch");
        }

        // 4. 签名校验
        if (!string.IsNullOrEmpty(matchRule.RequiredSigner) &&
            !info.SignatureSubject.Contains(matchRule.RequiredSigner, StringComparison.OrdinalIgnoreCase))
        {
            _logger?.LogWarning("Process blocked (signature mismatch): {Pid} {Path}",
                info.ProcessId, info.FilePath);
            return Result<ProcessInfo>.Failure(ErrorCode.ProcessBlocked, "Signature mismatch");
        }

        // 5. 用户检查
        if (matchRule.AllowedUsers.Count > 0 &&
            !matchRule.AllowedUsers.Contains(info.UserName, StringComparer.OrdinalIgnoreCase))
        {
            _logger?.LogWarning("Process blocked (user not allowed): {Pid} {User}",
                info.ProcessId, info.UserName);
            return Result<ProcessInfo>.Failure(ErrorCode.ProcessBlocked, "User not allowed");
        }

        // 6. 父进程检查
        if (matchRule.AllowedParents.Count > 0 &&
            !IsParentAllowed(info.ParentProcessId, matchRule.AllowedParents))
        {
            _logger?.LogWarning("Process blocked (parent not allowed): {Pid} parent={ParentPid}",
                info.ProcessId, info.ParentProcessId);
            return Result<ProcessInfo>.Failure(ErrorCode.ProcessBlocked, "Parent process not allowed");
        }

        // 7. 命令行检查（可选，用于黑名单模式）
        if (IsCommandLineBlocked(info.CommandLine))
        {
            _logger?.LogWarning("Process blocked (command line blocked): {Pid} {Cmd}",
                info.ProcessId, info.CommandLine);
            return Result<ProcessInfo>.Failure(ErrorCode.ProcessBlocked, "Command line blocked");
        }

        return Result<ProcessInfo>.Success(info);
    }

    /// <summary>
    /// 判断是否为系统关键进程（直接放行，不经过白名单）。
    /// </summary>
    private static bool IsSystemCriticalProcess(ProcessInfo info)
    {
        // 系统关键进程列表
        var criticalProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "System", "Idle", "Registry", "smss", "csrss", "wininit", "services",
            "lsass", "svchost", "fontdrvhost", "dwm", "winlogon", "spoolsv",
            "MsMpEng", "SearchIndexer", "SecurityHealthService", "WmiPrvSE",
            "sihost", "taskhostw", "explorer", "RuntimeBroker", "ShellExperienceHost",
            "ApplicationFrameHost", "SearchApp", "StartMenuExperienceHost",
            "Widgets", "TextInputHost", "ctfmon", "conhost", "Winknow.ControlService",
            "Winknow.GuardService", "Winknow.SessionAgent"
        };

        return criticalProcesses.Contains(info.ProcessName);
    }

    /// <summary>
    /// 路径白名单匹配。
    /// </summary>
    private bool IsPathAllowed(string filePath, out WhitelistRule? matchedRule)
    {
        matchedRule = null;

        if (string.IsNullOrEmpty(filePath))
        {
            // 无路径的进程（如系统进程），暂时放行
            return true;
        }

        foreach (var rule in _whitelist.PathRules)
        {
            if (rule.Matches(filePath))
            {
                matchedRule = rule;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// 父进程白名单检查。
    /// </summary>
    private bool IsParentAllowed(int parentProcessId, ISet<string> allowedParentNames)
    {
        try
        {
            using var parent = Process.GetProcessById(parentProcessId);
            return allowedParentNames.Contains(parent.ProcessName);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 命令行黑名单检查（如 powershell -enc 等危险参数）。
    /// </summary>
    private static bool IsCommandLineBlocked(string commandLine)
    {
        if (string.IsNullOrEmpty(commandLine))
        {
            return false;
        }

        // 危险命令行模式
        var dangerousPatterns = new[]
        {
            "-EncodedCommand", "-enc ", "-e ", "Invoke-Expression", "iex ",
            "DownloadString", "DownloadFile", "Invoke-WebRequest", "iwr ",
            "Start-Process", "Stop-Service", "sc delete", "sc stop"
        };

        foreach (var pattern in dangerousPatterns)
        {
            if (commandLine.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
