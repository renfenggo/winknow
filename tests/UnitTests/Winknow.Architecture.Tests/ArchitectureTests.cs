namespace Winknow.Architecture.Tests;

/// <summary>
/// 第1周架构测试：验证 V7.0 解决方案结构符合《V7.0 组件架构设计》。
/// </summary>
public sealed class ArchitectureTests
{
    private static string RepoRoot
    {
        get
        {
            var dir = AppContext.BaseDirectory;
            while (dir is not null && !File.Exists(Path.Combine(dir, "WinknowV7.sln")))
            {
                dir = Directory.GetParent(dir)?.FullName;
            }
            return dir ?? AppContext.BaseDirectory;
        }
    }

    [Fact]
    public void SolutionFile_ShouldExist()
    {
        var slnPath = Path.Combine(RepoRoot, "WinknowV7.sln");
        Assert.True(File.Exists(slnPath), $"解决方案文件应存在：{slnPath}");
    }

    [Fact]
    public void ProductionProjects_ShouldBeFifteen()
    {
        var srcDir = Path.Combine(RepoRoot, "src");
        var csprojs = Directory.GetFiles(srcDir, "*.csproj", SearchOption.AllDirectories);
        Assert.Equal(15, csprojs.Length);
    }

    [Fact]
    public void ControlService_ShouldNotUseKeyboardHook()
    {
        var workerPath = Path.Combine(RepoRoot, "src", "Winknow.ControlService", "Worker.cs");
        var content = File.ReadAllText(workerPath);
        Assert.DoesNotContain("SetWindowsHookEx", content, StringComparison.Ordinal);
        Assert.DoesNotContain("WH_KEYBOARD_LL", content, StringComparison.Ordinal);
    }

    [Fact]
    public void SessionAgent_ShouldBeWinExe()
    {
        var csprojPath = Path.Combine(RepoRoot, "src", "Winknow.SessionAgent", "Winknow.SessionAgent.csproj");
        var content = File.ReadAllText(csprojPath);
        Assert.Contains("<OutputType>WinExe</OutputType>", content, StringComparison.Ordinal);
    }

    [Fact]
    public void UpdaterAndRecovery_ShouldHaveIndependentEntry()
    {
        var updaterCsproj = Path.Combine(RepoRoot, "src", "Winknow.TrustedUpdater", "Winknow.TrustedUpdater.csproj");
        var updaterProgram = Path.Combine(RepoRoot, "src", "Winknow.TrustedUpdater", "Program.cs");
        var recoveryCsproj = Path.Combine(RepoRoot, "src", "Winknow.RecoveryTool", "Winknow.RecoveryTool.csproj");
        var recoveryProgram = Path.Combine(RepoRoot, "src", "Winknow.RecoveryTool", "Program.cs");

        Assert.True(File.Exists(updaterCsproj), "TrustedUpdater 应有独立 csproj");
        Assert.True(File.Exists(updaterProgram), "TrustedUpdater 应有 Program.cs");
        Assert.True(File.Exists(recoveryCsproj), "RecoveryTool 应有独立 csproj");
        Assert.True(File.Exists(recoveryProgram), "RecoveryTool 应有 Program.cs");
    }

    [Fact]
    public void ArchitectureDocument_ShouldExist()
    {
        var docPath = Path.Combine(RepoRoot, "docs", "V7.0_组件架构设计.md");
        Assert.True(File.Exists(docPath), "《V7.0 组件架构设计》文档应存在");
    }

    [Fact]
    public void ThreatModelDocument_ShouldExist()
    {
        var docPath = Path.Combine(RepoRoot, "docs", "V7.0_威胁模型与安全边界.md");
        Assert.True(File.Exists(docPath), "《V7.0 威胁模型与安全边界》文档应存在");
    }

    [Theory]
    [InlineData("Winknow.ControlService", "ServiceNames.ControlService")]
    [InlineData("Winknow.GuardService", "ServiceNames.GuardService")]
    public void WindowsServices_ShouldUseAddWindowsService(string projectName, string serviceNamesMember)
    {
        var programPath = Path.Combine(RepoRoot, "src", projectName, "Program.cs");
        var content = File.ReadAllText(programPath);

        Assert.Contains("AddWindowsService", content, StringComparison.Ordinal);
        Assert.Contains(serviceNamesMember, content, StringComparison.Ordinal);
        Assert.DoesNotContain("UseWindowsService", content, StringComparison.Ordinal);
    }

    /// <summary>
    /// PR-01（ADR-001/TD-01）：生产代码禁止出现服务名字符串字面量，
    /// 服务名只能引用 <see cref="Winknow.Core.ServiceNames"/>（唯一可信源在 Winknow.Core.ServiceNames.cs）。
    /// </summary>
    [Fact]
    public void ProductionCode_ShouldNotHardcodeServiceNames()
    {
        var srcRoot = Path.Combine(RepoRoot, "src");
        var soleSource = Path.Combine("Winknow.Core", "ServiceNames.cs");
        var checkedFiles = 0;

        foreach (var file in Directory.EnumerateFiles(srcRoot, "*.cs", SearchOption.AllDirectories))
        {
            var relative = file.Substring(srcRoot.Length + 1);
            if (relative.Equals(soleSource, StringComparison.OrdinalIgnoreCase)) continue;

            // 剔除注释行（/// 文档注释允许提及显示名）
            var code = string.Join(Environment.NewLine,
                File.ReadAllLines(file)
                    .Where(l => !l.TrimStart().StartsWith("///") && !l.TrimStart().StartsWith("//")));

            Assert.DoesNotContain("Winknow Control Service", code, StringComparison.Ordinal);
            Assert.DoesNotContain("Winknow Guard Service", code, StringComparison.Ordinal);
            Assert.DoesNotContain("\"WinknowControl\"", code, StringComparison.Ordinal);
            Assert.DoesNotContain("\"WinknowGuard\"", code, StringComparison.Ordinal);
            checkedFiles++;
        }

        Assert.True(checkedFiles > 10, "应扫描到足够多的源文件，否则测试失效");
    }

    [Fact]
    public void ControlServiceWorker_ShouldNotDirectlyCallCreateProcessAsUser()
    {
        var workerPath = Path.Combine(RepoRoot, "src", "Winknow.ControlService", "Worker.cs");
        var content = File.ReadAllText(workerPath);
        Assert.DoesNotContain("CreateProcessAsUser", content, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("global.json")]
    [InlineData("Directory.Build.props")]
    [InlineData("Directory.Packages.props")]
    [InlineData(".editorconfig")]
    [InlineData(".gitignore")]
    public void EngineeringBaselineFiles_ShouldExist(string fileName)
    {
        var path = Path.Combine(RepoRoot, fileName);
        Assert.True(File.Exists(path), $"工程基线文件应存在：{fileName}");
    }

    [Theory]
    [InlineData("installer")]
    [InlineData("tools")]
    public void PlaceholderDirectories_ShouldExist(string dirName)
    {
        var path = Path.Combine(RepoRoot, dirName);
        Assert.True(Directory.Exists(path), $"占位目录应存在：{dirName}");
    }

    [Fact]
    public void CiConfiguration_ShouldExist()
    {
        var ciPath = Path.Combine(RepoRoot, ".github", "workflows", "ci.yml");
        Assert.True(File.Exists(ciPath), "CI 配置文件应存在：.github/workflows/ci.yml");
    }

    [Fact]
    public void DefaultPolicy_ShouldExistAndContainRequiredFields()
    {
        var policyPath = Path.Combine(RepoRoot, "policies", "default_policy_v7.0.json");
        Assert.True(File.Exists(policyPath), "默认策略文件应存在");

        var content = File.ReadAllText(policyPath);
        Assert.Contains("\"Version\"", content, StringComparison.Ordinal);
        Assert.Contains("\"SoftwareControl\"", content, StringComparison.Ordinal);
        Assert.Contains("\"NetworkControl\"", content, StringComparison.Ordinal);
        Assert.Contains("\"UsbControl\"", content, StringComparison.Ordinal);
    }
}
