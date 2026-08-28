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
    public void ProductionProjects_ShouldBeFourteen()
    {
        var srcDir = Path.Combine(RepoRoot, "src");
        var csprojs = Directory.GetFiles(srcDir, "*.csproj", SearchOption.AllDirectories);
        Assert.Equal(14, csprojs.Length);
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
    [InlineData("Winknow.ControlService", "Winknow Control Service")]
    [InlineData("Winknow.GuardService", "Winknow Guard Service")]
    public void WindowsServices_ShouldUseAddWindowsService(string projectName, string expectedServiceName)
    {
        var programPath = Path.Combine(RepoRoot, "src", projectName, "Program.cs");
        var content = File.ReadAllText(programPath);

        Assert.Contains("AddWindowsService", content, StringComparison.Ordinal);
        Assert.Contains(expectedServiceName, content, StringComparison.Ordinal);
        Assert.DoesNotContain("UseWindowsService", content, StringComparison.Ordinal);
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
