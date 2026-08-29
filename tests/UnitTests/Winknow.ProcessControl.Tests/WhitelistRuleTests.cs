using Winknow.Policy;
using Winknow.ProcessControl;

namespace Winknow.ProcessControl.Tests;

/// <summary>
/// 白名单规则匹配与策略加载测试。
/// </summary>
public class WhitelistRuleTests
{
    [Theory(DisplayName = "路径通配符匹配")]
    [InlineData(@"C:\Windows\System32\notepad.exe", @"C:\Windows\System32\*", true)]
    [InlineData(@"C:\Windows\System32\drivers\etc\hosts", @"C:\Windows\System32\*", true)]
    [InlineData(@"C:\Program Files\dotnet\dotnet.exe", @"C:\Program Files\dotnet\*", true)]
    [InlineData(@"C:\Users\student\source\repos\MyApp\bin\Debug\MyApp.exe",
        @"C:\Users\*\source\repos\**", true)]
    [InlineData(@"D:\Games\game.exe", @"C:\Windows\System32\*", false)]
    [InlineData(@"C:\Users\student\Downloads\crack.exe", @"C:\Program Files\*", false)]
    public void Matches_PathWildcards(string path, string pattern, bool expected)
    {
        var rule = new WhitelistRule { PathPattern = pattern };
        Assert.Equal(expected, rule.Matches(path));
    }

    [Fact(DisplayName = "空路径不匹配")]
    public void Matches_EmptyPath_ReturnsFalse()
    {
        var rule = new WhitelistRule { PathPattern = @"C:\Windows\*" };
        Assert.False(rule.Matches(string.Empty));
    }

    [Fact(DisplayName = "空模式不匹配")]
    public void Matches_EmptyPattern_ReturnsFalse()
    {
        var rule = new WhitelistRule { PathPattern = string.Empty };
        Assert.False(rule.Matches(@"C:\Windows\notepad.exe"));
    }

    [Fact(DisplayName = "CreateDefault 仅含系统基础设施（无课堂软件）")]
    public void CreateDefault_ContainsSystemPathsOnly()
    {
        var whitelist = WhitelistRuleSet.CreateDefault();

        // 系统基础设施保留
        Assert.Contains(whitelist.PathRules,
            r => r.PathPattern == @"C:\Windows\System32\*");
        Assert.Contains(whitelist.PathRules,
            r => r.PathPattern == @"C:\Windows\SysWOW64\*");
        Assert.Contains(whitelist.PathRules,
            r => r.PathPattern == @"C:\Program Files\Winknow\*");

        // 课堂软件已迁移到策略文件，CreateDefault 不再硬编码
        Assert.DoesNotContain(whitelist.PathRules,
            r => r.PathPattern.Contains("VS Code"));
        Assert.DoesNotContain(whitelist.PathRules,
            r => r.PathPattern.Contains("Dev-Cpp"));
    }

    [Fact(DisplayName = "FromPolicy 合并系统目录与策略白名单")]
    public void FromPolicy_MergesSystemAndPolicyRules()
    {
        var policy = CreateTestPolicy();
        var whitelist = WhitelistRuleSet.FromPolicy(policy);

        // 系统基础设施（内置）
        Assert.Contains(whitelist.PathRules, r => r.PathPattern == @"C:\Windows\System32\*");
        Assert.Contains(whitelist.PathRules, r => r.PathPattern == @"C:\Program Files\Winknow\*");

        // 策略 ByPath
        Assert.Contains(whitelist.PathRules,
            r => r.PathPattern == @"C:\Program Files\Dev-Cpp\*");

        // 学生输出目录
        Assert.Contains(whitelist.PathRules,
            r => r.PathPattern == @"C:\Users\*\source\repos\**");

        // ByPublisher（兜底，任意路径+签名）
        var publisherRule = Assert.Single(whitelist.PathRules,
            r => r.PathPattern == "*");
        Assert.Equal("Microsoft", publisherRule.RequiredSigner);
    }

    [Fact(DisplayName = "FromPolicy 空策略仍含系统基础设施")]
    public void FromPolicy_EmptyPolicy_StillContainsSystemDirs()
    {
        var policy = new PolicyFile { Version = "7.0.0", PolicyId = "empty" };
        var whitelist = WhitelistRuleSet.FromPolicy(policy);

        // 即使策略无白名单，系统目录仍内置
        Assert.Contains(whitelist.PathRules, r => r.PathPattern == @"C:\Windows\System32\*");
        Assert.Contains(whitelist.PathRules, r => r.PathPattern == @"C:\Windows\*");
    }

    /// <summary>构造测试用策略文件（内存）。</summary>
    private static PolicyFile CreateTestPolicy()
    {
        return new PolicyFile
        {
            Version = "7.0.0",
            PolicyId = "test",
            SoftwareControl = new SoftwareControlSection
            {
                Whitelist = new SoftwareWhitelist
                {
                    ByPublisher = new List<string> { "Microsoft" },
                    ByPath = new List<PathRule>
                    {
                        new() { Path = @"C:\Program Files\Dev-Cpp\*", Description = "Dev-C++" }
                    }
                },
                StudentOutput = new StudentOutputSection
                {
                    AllowedDirectories = new List<string> { @"C:\Users\*\source\repos\**" }
                }
            }
        };
    }
}
