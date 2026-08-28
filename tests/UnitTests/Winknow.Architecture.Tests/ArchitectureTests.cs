namespace Winknow.Architecture.Tests;

/// <summary>
/// 第1周架构测试：验证 V7.0 解决方案结构符合《V7.0 组件架构设计》。
///
/// 验收项：
/// - Service 不承担交互式键盘钩子（由 SessionAgent 负责）
/// - Agent 可在当前用户会话启动（SessionAgent 为 WinExe）
/// - Updater 和 Recovery 有独立入口（独立项目）
/// - 所有组件运行身份有书面说明（文档存在）
/// </summary>
public sealed class ArchitectureTests
{
    private static readonly string RepoRoot = GetRepoRoot();

    private static string GetRepoRoot()
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "WinknowV7.sln")))
        {
            dir = Directory.GetParent(dir)?.FullName;
        }
        return dir ?? AppContext.BaseDirectory;
    }

    /// <summary>
    /// 验证解决方案文件存在。
    /// </summary>
    [Fact]
    public void SolutionFile_ShouldExist()
    {
        var slnPath = Path.Combine(RepoRoot, "WinknowV7.sln");
        Assert.True(File.Exists(slnPath), $"解决方案文件应存在：{slnPath}");
    }

    /// <summary>
    /// 验证生产项目数量为 14。
    /// </summary>
    [Fact]
    public void ProductionProjects_ShouldBeFourteen()
    {
        var srcDir = Path.Combine(RepoRoot, "src");
        var csprojs = Directory.GetFiles(srcDir, "*.csproj", SearchOption.AllDirectories);
        Assert.Equal(14, csprojs.Length);
    }

    /// <summary>
    /// 验收项：Service 不承担交互式键盘钩子。
    /// ControlService 的 Worker.cs 不得直接引用 SetWindowsHookEx。
    /// </summary>
    [Fact]
    public void ControlService_ShouldNotUseKeyboardHook()
    {
        var workerPath = Path.Combine(RepoRoot, "src", "Winknow.ControlService", "Worker.cs");
        var content = File.ReadAllText(workerPath);

        Assert.DoesNotContain("SetWindowsHookEx", content, StringComparison.Ordinal);
        Assert.DoesNotContain("WH_KEYBOARD_LL", content, StringComparison.Ordinal);
    }

    /// <summary>
    /// 验收项：Agent 可在当前用户会话启动。
    /// SessionAgent 的输出类型必须为 WinExe（无控制台窗口）。
    /// </summary>
    [Fact]
    public void SessionAgent_ShouldBeWinExe()
    {
        var csprojPath = Path.Combine(RepoRoot, "src", "Winknow.SessionAgent", "Winknow.SessionAgent.csproj");
        var content = File.ReadAllText(csprojPath);

        Assert.Contains("<OutputType>WinExe</OutputType>", content, StringComparison.Ordinal);
    }

    /// <summary>
    /// 验收项：Updater 和 Recovery 有独立入口。
    /// 两个项目必须各自有独立的 csproj 和 Program.cs。
    /// </summary>
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

    /// <summary>
    /// 验收项：所有组件运行身份有书面说明。
    /// 《V7.0 组件架构设计》文档必须存在。
    /// </summary>
    [Fact]
    public void ArchitectureDocument_ShouldExist()
    {
        var docPath = Path.Combine(RepoRoot, "docs", "V7.0_组件架构设计.md");
        Assert.True(File.Exists(docPath), "《V7.0 组件架构设计》文档应存在");
    }

    /// <summary>
    /// 验收项：威胁模型文档存在。
    /// </summary>
    [Fact]
    public void ThreatModelDocument_ShouldExist()
    {
        var docPath = Path.Combine(RepoRoot, "docs", "V7.0_威胁模型与安全边界.md");
        Assert.True(File.Exists(docPath), "《V7.0 威胁模型与安全边界》文档应存在");
    }

    /// <summary>
    /// 验证 ControlService 和 GuardService 使用 AddWindowsService（V7.0 规范）。
    /// </summary>
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

    /// <summary>
    /// 验证 ControlService 不持有学生用户令牌（不直接调用 CreateProcessAsUser）。
    /// CreateProcessAsUser 应在第2周 SessionAgent 启动逻辑中实现，不在 ControlService 的 Worker 中。
    /// </summary>
    [Fact]
    public void ControlServiceWorker_ShouldNotDirectlyCallCreateProcessAsUser()
    {
        var workerPath = Path.Combine(RepoRoot, "src", "Winknow.ControlService", "Worker.cs");
        var content = File.ReadAllText(workerPath);

        // Worker 不得直接包含 CreateProcessAsUser 调用（应在独立的 SessionAgentLauncher 类中）
        Assert.DoesNotContain("CreateProcessAsUser", content, StringComparison.Ordinal);
    }

    /// <summary>
    /// 验证工程基线文件齐全。
    /// </summary>
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

    /// <summary>
    /// 验证占位目录存在。
    /// </summary>
    [Theory]
    [InlineData("installer")]
    [InlineData("tools")]
    public void PlaceholderDirectories_ShouldExist(string dirName)
    {
        var path = Path.Combine(RepoRoot, dirName);
        Assert.True(Directory.Exists(path), $"占位目录应存在：{dirName}");
    }

    /// <summary>
    /// 验证 CI 配置存在。
    /// </summary>
    [Fact]
    public void CiConfiguration_ShouldExist()
    {
        var ciPath = Path.Combine(RepoRoot, ".github", "workflows", "ci.yml");
        Assert.True(File.Exists(ciPath), "CI 配置文件应存在：.github/workflows/ci.yml");
    }

    /// <summary>
    /// 验证默认策略文件存在且包含必要字段。
    /// </summary>
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
