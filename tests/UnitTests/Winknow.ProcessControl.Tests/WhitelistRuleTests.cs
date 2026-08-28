using Winknow.ProcessControl;

namespace Winknow.ProcessControl.Tests;

/// <summary>
/// 白名单规则匹配测试。
/// </summary>
public class WhitelistRuleTests
{
    [Theory(DisplayName = "路径通配符匹配")]
    [InlineData(@"C:\Windows\System32\notepad.exe", @"C:\Windows\System32\*", true)]
    [InlineData(@"C:\Windows\System32\drivers\etc\hosts", @"C:\Windows\System32\*", true)]
    [InlineData(@"C:\Program Files\dotnet\dotnet.exe", @"C:\Program Files\dotnet\*", true)]
    [InlineData(@"C:\Users\student\source\repos\MyApp\bin\Debug\MyApp.exe",
        @"C:\Users\*\source\repos\*\bin\*\*.exe", true)]
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

    [Fact(DisplayName = "默认白名单包含系统目录")]
    public void CreateDefault_ContainsSystemPaths()
    {
        var whitelist = WhitelistRuleSet.CreateDefault();

        Assert.Contains(whitelist.PathRules,
            r => r.PathPattern == @"C:\Windows\System32\*");
        Assert.Contains(whitelist.PathRules,
            r => r.PathPattern == @"C:\Windows\SysWOW64\*");
        Assert.Contains(whitelist.PathRules,
            r => r.PathPattern == @"C:\Program Files\Winknow\*");
    }

    [Fact(DisplayName = "默认白名单包含 IDE 路径")]
    public void CreateDefault_ContainsIdePaths()
    {
        var whitelist = WhitelistRuleSet.CreateDefault();

        Assert.Contains(whitelist.PathRules,
            r => r.PathPattern == @"C:\Program Files\Microsoft Visual Studio\*");
        Assert.Contains(whitelist.PathRules,
            r => r.PathPattern == @"C:\Users\*\AppData\Local\Programs\Microsoft VS Code\*");
    }
}
