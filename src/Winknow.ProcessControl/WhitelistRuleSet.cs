using System.Text.Json.Serialization;
using Winknow.Policy;

namespace Winknow.ProcessControl;

/// <summary>
/// 白名单规则集。
/// </summary>
public sealed class WhitelistRuleSet
{
    /// <summary>路径白名单规则列表。</summary>
    public List<WhitelistRule> PathRules { get; init; } = new();

    /// <summary>
    /// 从策略文件构建白名单规则集（单一可信源）。
    /// 课堂软件白名单来自策略 ByPath/ByPublisher/StudentOutput，
    /// 系统基础设施目录内置补充（运行前提，非课堂配置）。
    /// </summary>
    public static WhitelistRuleSet FromPolicy(PolicyFile policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var sw = policy.SoftwareControl;
        var rules = new List<WhitelistRule>();

        // 1. 系统基础设施目录（内置，运行前提）
        rules.Add(new WhitelistRule { PathPattern = @"C:\Windows\System32\*", Description = "System32 目录" });
        rules.Add(new WhitelistRule { PathPattern = @"C:\Windows\SysWOW64\*", Description = "SysWOW64 目录" });
        rules.Add(new WhitelistRule { PathPattern = @"C:\Windows\*", Description = "Windows 根目录" });
        rules.Add(new WhitelistRule { PathPattern = @"C:\Program Files\dotnet\*", Description = ".NET 运行时" });
        rules.Add(new WhitelistRule { PathPattern = @"C:\Program Files\Winknow\*", Description = "Winknow 管控系统" });

        // 2. 策略按路径白名单
        foreach (var pr in sw.Whitelist.ByPath)
        {
            rules.Add(new WhitelistRule
            {
                PathPattern = pr.Path,
                ExpectedHash = pr.Hash,
                Description = string.IsNullOrEmpty(pr.Description) ? "策略路径白名单" : pr.Description
            });
        }

        // 3. 学生输出目录
        foreach (var dir in sw.StudentOutput.AllowedDirectories)
        {
            rules.Add(new WhitelistRule
            {
                PathPattern = dir,
                Description = "学生输出目录"
            });
        }

        // 4. 策略按发布者白名单（任意路径 + 签名校验，兜底）
        foreach (var publisher in sw.Whitelist.ByPublisher)
        {
            rules.Add(new WhitelistRule
            {
                PathPattern = "*",
                RequiredSigner = publisher,
                Description = $"发布者白名单: {publisher}"
            });
        }

        return new WhitelistRuleSet { PathRules = rules };
    }

    /// <summary>
    /// 创建默认白名单（系统基础设施兜底，无策略文件时使用）。
    /// 课堂软件白名单应来自策略文件，见 <see cref="FromPolicy"/>。
    /// </summary>
    public static WhitelistRuleSet CreateDefault()
    {
        return new WhitelistRuleSet
        {
            PathRules = new List<WhitelistRule>
            {
                new() { PathPattern = @"C:\Windows\System32\*", Description = "System32 目录" },
                new() { PathPattern = @"C:\Windows\SysWOW64\*", Description = "SysWOW64 目录" },
                new() { PathPattern = @"C:\Windows\*", Description = "Windows 根目录" },
                new() { PathPattern = @"C:\Program Files\dotnet\*", Description = ".NET 运行时" },
                new() { PathPattern = @"C:\Program Files\Winknow\*", Description = "Winknow 管控系统" }
            }
        };
    }
}

/// <summary>
/// 单条白名单规则。
/// </summary>
public sealed class WhitelistRule
{
    /// <summary>路径匹配模式（支持 * 和 ? 通配符）。</summary>
    public string PathPattern { get; init; } = string.Empty;

    /// <summary>规则描述。</summary>
    public string Description { get; init; } = string.Empty;

    /// <summary>期望的文件 SHA-256 哈希（空表示不校验）。</summary>
    public string ExpectedHash { get; init; } = string.Empty;

    /// <summary>要求的签名主体关键字（空表示不校验）。</summary>
    public string RequiredSigner { get; init; } = string.Empty;

    /// <summary>允许运行该程序的用户列表（空表示不限制）。</summary>
    public HashSet<string> AllowedUsers { get; init; } = new();

    /// <summary>允许的父进程名列表（空表示不限制）。</summary>
    public HashSet<string> AllowedParents { get; init; } = new();

    /// <summary>
    /// 检查文件路径是否匹配本规则。
    /// </summary>
    public bool Matches(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || string.IsNullOrEmpty(PathPattern))
        {
            return false;
        }

        // 通配符匹配（不区分大小写，Windows 文件系统不区分）
        return MatchesPattern(filePath, PathPattern);
    }

    /// <summary>
    /// 通配符匹配（* 匹配任意字符，? 匹配单个字符）。
    /// </summary>
    private static bool MatchesPattern(string path, string pattern)
    {
        // 简化实现：将通配符转为正则
        var regexPattern = "^" + System.Text.RegularExpressions.Regex.Escape(pattern)
            .Replace("\\*", ".*")
            .Replace("\\?", ".") + "$";

        return System.Text.RegularExpressions.Regex.IsMatch(
            path,
            regexPattern,
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }
}
