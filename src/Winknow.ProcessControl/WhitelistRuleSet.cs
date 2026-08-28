using System.Text.Json.Serialization;

namespace Winknow.ProcessControl;

/// <summary>
/// 白名单规则集。
/// </summary>
public sealed class WhitelistRuleSet
{
    /// <summary>路径白名单规则列表。</summary>
    public List<WhitelistRule> PathRules { get; init; } = new();

    /// <summary>
    /// 创建默认白名单（编程课堂环境）。
    /// </summary>
    public static WhitelistRuleSet CreateDefault()
    {
        return new WhitelistRuleSet
        {
            PathRules = new List<WhitelistRule>
            {
                // 系统目录
                new()
                {
                    PathPattern = @"C:\Windows\System32\*",
                    Description = "System32 目录"
                },
                new()
                {
                    PathPattern = @"C:\Windows\SysWOW64\*",
                    Description = "SysWOW64 目录"
                },
                new()
                {
                    PathPattern = @"C:\Windows\*",
                    Description = "Windows 根目录"
                },
                // .NET 运行时
                new()
                {
                    PathPattern = @"C:\Program Files\dotnet\*",
                    Description = ".NET 运行时"
                },
                // Visual Studio
                new()
                {
                    PathPattern = @"C:\Program Files\Microsoft Visual Studio\*",
                    Description = "Visual Studio",
                    RequiredSigner = "Microsoft"
                },
                new()
                {
                    PathPattern = @"C:\Program Files (x86)\Microsoft Visual Studio\*",
                    Description = "Visual Studio (x86)",
                    RequiredSigner = "Microsoft"
                },
                // VS Code
                new()
                {
                    PathPattern = @"C:\Users\*\AppData\Local\Programs\Microsoft VS Code\*",
                    Description = "VS Code"
                },
                // Dev-C++
                new()
                {
                    PathPattern = @"C:\Program Files\Dev-Cpp\*",
                    Description = "Dev-C++"
                },
                // 浏览器
                new()
                {
                    PathPattern = @"C:\Program Files\Google\Chrome\Application\*",
                    Description = "Chrome 浏览器",
                    RequiredSigner = "Google"
                },
                new()
                {
                    PathPattern = @"C:\Program Files (x86)\Microsoft\Edge\Application\*",
                    Description = "Edge 浏览器",
                    RequiredSigner = "Microsoft"
                },
                // Winknow 自身
                new()
                {
                    PathPattern = @"C:\Program Files\Winknow\*",
                    Description = "Winknow 管控系统"
                },
                // 学生输出目录（编译产物）
                new()
                {
                    PathPattern = @"C:\Users\*\source\repos\*\bin\*\*.exe",
                    Description = "学生编译产物"
                },
                new()
                {
                    PathPattern = @"C:\Users\*\source\repos\*\obj\*\*.exe",
                    Description = "学生编译中间产物"
                }
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
