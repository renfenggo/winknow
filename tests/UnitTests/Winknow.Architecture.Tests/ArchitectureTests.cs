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
    public void ProductionProjects_ShouldBeEighteen()
    {
        // M2-6 新增 Winknow.DesktopBridge；M3 新增 Winknow.CodeRunner（ADR-003）；Lane W 新增 Winknow.Telemetry（云端心跳与事件上报）
        var srcDir = Path.Combine(RepoRoot, "src");
        var csprojs = Directory.GetFiles(srcDir, "*.csproj", SearchOption.AllDirectories);
        Assert.Equal(18, csprojs.Length);
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
    [InlineData("Winknow.ControlService", "Constants.Services.Control")]
    [InlineData("Winknow.GuardService", "Constants.Services.Guard")]
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

    /// <summary>
    /// N05（2026-10-08 第二轮复核）：ApplyPolicyToExecutors 必须检查
    /// ProxyGuard.CheckAndRestore / DnsMonitor.Check 的 Result 与
    /// UsbStorageController.Enable / Disable 的 bool 返回值，失败进
    /// apply_errors——丢弃返回值会以空错误清单 + applied=true 掩盖
    /// "执行器未生效"（如注册表被锁、DNS 违规未纠正）。
    ///
    /// Worker.ApplyPolicyToExecutors 直接单测会真改注册表/DNS/hosts，
    /// 无法在 CI 执行——用源码文本断言钉住装配层检查逻辑
    /// （先例：ControlServiceWorker_ShouldNotDirectlyCallCreateProcessAsUser）；
    /// 执行器各自的失败语义由其单元测试覆盖。
    /// </summary>
    [Fact]
    public void ControlServiceWorker_ShouldCheckExecutorReturnValuesInApplyPolicy()
    {
        var workerPath = Path.Combine(RepoRoot, "src", "Winknow.ControlService", "Worker.cs");
        var content = File.ReadAllText(workerPath);

        // 返回值已被检查且失败进 errors（ApplyPolicyToExecutors）。
        Assert.Contains("var proxyCheck = _proxyGuard.CheckAndRestore();", content, StringComparison.Ordinal);
        Assert.Contains("!proxyCheck.IsSuccess", content, StringComparison.Ordinal);
        Assert.Contains("var dnsCheck = _dnsMonitor.Check();", content, StringComparison.Ordinal);
        Assert.Contains("!dnsCheck.IsSuccess", content, StringComparison.Ordinal);
        Assert.Contains("!_usbController.Enable()", content, StringComparison.Ordinal);
        Assert.Contains("!_usbController.Disable()", content, StringComparison.Ordinal);
        Assert.Contains("errors.Add(\"usb_controller: Enable() failed", content, StringComparison.Ordinal);
        Assert.Contains("errors.Add(\"usb_controller: Disable() failed", content, StringComparison.Ordinal);

        // 启动路径（ExecuteAsync 初始化）同样检查返回值，失败 LogError 如实记录。
        Assert.Contains("var dnsStartupCheck = _dnsMonitor.Check();", content, StringComparison.Ordinal);
        Assert.Contains("DNS monitor initial check failed", content, StringComparison.Ordinal);
        Assert.Contains("Disable() failed on startup", content, StringComparison.Ordinal);
        Assert.Contains("Enable() failed on startup", content, StringComparison.Ordinal);

        // 不存在丢弃返回值的裸调用（去掉已检查的赋值语句后应零残留）。
        var withoutChecked = content
            .Replace("var proxyCheck = _proxyGuard.CheckAndRestore();", string.Empty, StringComparison.Ordinal)
            .Replace("var dnsCheck = _dnsMonitor.Check();", string.Empty, StringComparison.Ordinal)
            .Replace("var dnsStartupCheck = _dnsMonitor.Check();", string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain("_proxyGuard.CheckAndRestore();", withoutChecked, StringComparison.Ordinal);
        Assert.DoesNotContain("_dnsMonitor.Check();", withoutChecked, StringComparison.Ordinal);
        Assert.DoesNotContain("_usbController.Enable();", content, StringComparison.Ordinal);
        Assert.DoesNotContain("_usbController.Disable();", content, StringComparison.Ordinal);
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
        // R04：默认策略已由 PolicySignTool 以规范化 camelCase 格式签名回写
        Assert.Contains("\"version\"", content, StringComparison.Ordinal);
        Assert.Contains("\"softwareControl\"", content, StringComparison.Ordinal);
        Assert.Contains("\"networkControl\"", content, StringComparison.Ordinal);
        Assert.Contains("\"usbControl\"", content, StringComparison.Ordinal);
        Assert.Contains("\"signature\"", content, StringComparison.Ordinal);
    }
}
