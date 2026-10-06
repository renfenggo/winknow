using Winknow.Core.Results;
using Winknow.Policy;
using Winknow.ProcessControl;

namespace Winknow.ProcessControl.Tests;

/// <summary>
/// Runner 策略豁免测试（ADR-003）：最小白名单豁免仅覆盖可信工具链与
/// 工作区产物；高风险解释器黑名单与豁免正交，不因豁免放开。
/// </summary>
public class RunnerExemptionTests
{
    [Fact(DisplayName = "豁免未启用（默认）不产生豁免规则")]
    public void FromPolicy_Disabled_NoExemptionRules()
    {
        var policy = CreatePolicy(enabled: false);
        var whitelist = WhitelistRuleSet.FromPolicy(policy);

        Assert.DoesNotContain(whitelist.PathRules,
            r => r.Description.Contains("runner_exemptions", StringComparison.Ordinal));
    }

    [Fact(DisplayName = "豁免启用产生工具链与工作区两条规则")]
    public void FromPolicy_Enabled_AddsToolchainAndWorkspaceRules()
    {
        var policy = CreatePolicy(enabled: true);
        var whitelist = WhitelistRuleSet.FromPolicy(policy);

        var toolchainRule = Assert.Single(whitelist.PathRules,
            r => r.PathPattern == @"C:\Program Files (x86)\Dev-Cpp\**");
        Assert.Contains("runner_exemptions", toolchainRule.Description, StringComparison.Ordinal);

        var workspaceRule = Assert.Single(whitelist.PathRules,
            r => r.PathPattern == @"C:\ProgramData\Winknow\runner\*");
        Assert.Contains("runner_exemptions", workspaceRule.Description, StringComparison.Ordinal);
    }

    [Fact(DisplayName = "WorkspaceRoot 尾部反斜杠归一化（无双反斜杠）")]
    public void FromPolicy_WorkspaceRootTrailingBackslash_Normalized()
    {
        var policy = CreatePolicy(enabled: true, workspaceRoot: @"C:\ProgramData\Winknow\runner\");
        var whitelist = WhitelistRuleSet.FromPolicy(policy);

        var workspaceRule = Assert.Single(whitelist.PathRules,
            r => r.Description.Contains("工作区", StringComparison.Ordinal));
        Assert.Equal(@"C:\ProgramData\Winknow\runner\*", workspaceRule.PathPattern);
        Assert.True(workspaceRule.Matches(@"C:\ProgramData\Winknow\runner\req-001\submission.exe"));
    }

    [Fact(DisplayName = "豁免启用时工作区编译产物放行")]
    public void Judge_WorkspaceArtifact_Enabled_Allowed()
    {
        var judge = CreateJudge(enabled: true);
        var info = new ProcessInfo
        {
            ProcessId = 7001,
            ProcessName = "submission",
            FilePath = @"C:\ProgramData\Winknow\runner\req-001\submission.exe"
        };

        var result = judge.Judge(info);
        Assert.True(result.IsSuccess);
    }

    [Fact(DisplayName = "豁免启用时工具链 g++ 放行")]
    public void Judge_ToolchainCompiler_Enabled_Allowed()
    {
        var judge = CreateJudge(enabled: true);
        var info = new ProcessInfo
        {
            ProcessId = 7002,
            ProcessName = "g++",
            FilePath = @"C:\Program Files (x86)\Dev-Cpp\MinGW64\bin\g++.exe"
        };

        var result = judge.Judge(info);
        Assert.True(result.IsSuccess);
    }

    [Fact(DisplayName = "豁免未启用时工作区产物阻止")]
    public void Judge_WorkspaceArtifact_Disabled_Blocked()
    {
        var judge = CreateJudge(enabled: false);
        var info = new ProcessInfo
        {
            ProcessId = 7003,
            ProcessName = "submission",
            FilePath = @"C:\ProgramData\Winknow\runner\req-001\submission.exe"
        };

        var result = judge.Judge(info);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.ProcessBlocked, result.ErrorCode);
    }

    [Fact(DisplayName = "高风险解释器位于豁免路径仍被阻止（豁免与黑名单正交）")]
    public void Judge_HighRiskInterpreterInWorkspace_StillBlocked()
    {
        // powershell.exe 被放进豁免工作区（路径命中豁免白名单），
        // 但 ProcessJudge 黑名单检查在白名单命中之后独立执行，仍须阻止
        var judge = CreateJudge(enabled: true);
        var info = new ProcessInfo
        {
            ProcessId = 7004,
            ProcessName = "powershell.exe",
            FilePath = @"C:\ProgramData\Winknow\runner\powershell.exe"
        };

        var result = judge.Judge(info);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.ProcessBlocked, result.ErrorCode);
    }

    /// <summary>构造带 Runner 豁免配置的测试策略（内存）。</summary>
    private static PolicyFile CreatePolicy(bool enabled, string workspaceRoot = @"C:\ProgramData\Winknow\runner")
    {
        return new PolicyFile
        {
            Version = "7.0.0",
            PolicyId = "runner-exemption-test",
            SoftwareControl = new SoftwareControlSection
            {
                Whitelist = new SoftwareWhitelist(),
                HighRiskInterpreters = new HighRiskInterpretersSection
                {
                    Blocked = new List<string> { "powershell.exe", "wscript.exe", "cscript.exe" }
                },
                RunnerExemptions = new RunnerExemptionsSection
                {
                    Enabled = enabled,
                    TrustedToolchainPaths = new List<string> { @"C:\Program Files (x86)\Dev-Cpp\**" },
                    WorkspaceRoot = workspaceRoot,
                    MaxSessionMinutes = 120
                }
            }
        };
    }

    /// <summary>从测试策略构建判定引擎（与生产装配方式一致）。</summary>
    private static ProcessJudge CreateJudge(bool enabled)
    {
        var policy = CreatePolicy(enabled);
        return new ProcessJudge(
            WhitelistRuleSet.FromPolicy(policy),
            highRiskInterpreters: policy.SoftwareControl.HighRiskInterpreters.Blocked);
    }
}
