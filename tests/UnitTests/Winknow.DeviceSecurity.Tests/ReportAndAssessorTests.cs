using Winknow.DeviceSecurity;

namespace Winknow.DeviceSecurity.Tests;

/// <summary>
/// 报告导出 + 检测逻辑映射 + 评估门面集成测试。
/// </summary>
public sealed class ReportAndAssessorTests : IDisposable
{
    private readonly string _tempDir =
        Path.Combine(Path.GetTempPath(), $"winknow_w11r_{Guid.NewGuid():N}");

    public ReportAndAssessorTests() => Directory.CreateDirectory(_tempDir);

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch (IOException) { }
    }

    private static DeviceSecurityReport SampleReport() => new()
    {
        DeviceId = "DEV-TEST",
        Firmware = new FirmwareInfo
        {
            BiosVendor = "AMI", BiosVersion = "5.6.7", FirmwareType = "UEFI",
            BoardVendor = "ASUS", BoardModel = "H610M-K", BoardSerial = "SN-1",
            SystemVendor = "Lenovo", SystemModel = "M760T"
        },
        SecureBootState = "Enabled",
        BootConfig = new BootConfigInfo
        {
            SystemDiskIndex = 0, PartitionStyle = "GPT", SystemPartitionType = "GPT: System"
        },
        Checks = new List<CheckItem>
        {
            new() { Id = "secure-boot", Title = "Secure Boot 已启用", Category = "auto", Weight = 30, Status = CheckStatus.Pass, Detail = "Secure Boot 已启用" },
            new() { Id = "uefi-mode", Title = "UEFI 固件模式", Category = "auto", Weight = 20, Status = CheckStatus.Pass, Detail = "UEFI" },
            new() { Id = "usb-boot", Title = "USB 外部启动已禁用", Category = "manual", Weight = 15, Status = CheckStatus.Pending, Detail = "需人工核验", Remediation = "BIOS 中禁用 USB Boot" }
        },
        Score = 50,
        Grade = SecurityGrade.NeedsManualReview,
        VerificationCurrent = null,
        GeneratedAt = "2026-08-29T12:00:00Z"
    };

    // ───────────────────────── SecureBootDetector.Evaluate ─────────────────────────

    [Fact]
    public void SecureBoot_Evaluate_Mapping()
    {
        var (pass, _, _) = SecureBootDetector.Evaluate(SecureBootDetector.SecureBootState.Enabled);
        Assert.Equal(CheckStatus.Pass, pass);

        var (fail, _, fixFail) = SecureBootDetector.Evaluate(SecureBootDetector.SecureBootState.Disabled);
        Assert.Equal(CheckStatus.Fail, fail);
        Assert.Contains("Secure Boot", fixFail);

        // 读取不到 → 需人工核验（不显示为通过）
        var (pending, detail, fixPending) = SecureBootDetector.Evaluate(SecureBootDetector.SecureBootState.Unknown);
        Assert.Equal(CheckStatus.Pending, pending);
        Assert.Contains("人工", detail);
        Assert.NotEmpty(fixPending);
    }

    [Fact]
    public void SecureBoot_Detect_NeverThrows()
    {
        // 真实注册表读取烟测：本机无论键是否存在都应返回合法枚举值
        var state = new SecureBootDetector().Detect();
        Assert.True(Enum.IsDefined(state));
    }

    // ───────────────────────── BootConfigCollector 逻辑 ─────────────────────────

    [Theory]
    [InlineData(new[] { "GPT: System", "GPT: Basic data partition" }, "GPT")]
    [InlineData(new[] { "Installable File System" }, "MBR")]
    [InlineData(new string[0], "Unknown")]
    public void PartitionStyle_Determination(string[] types, string expected)
    {
        Assert.Equal(expected, BootConfigCollector.DeterminePartitionStyle(types));
    }

    // ───────────────────────── ReportExporter ─────────────────────────

    [Fact]
    public void Markdown_ContainsAllSections_AndBitLockerBoundary()
    {
        var md = ReportExporter.ToMarkdown(SampleReport());

        Assert.Contains("设备启动安全核验报告", md);
        Assert.Contains("固件信息", md);
        Assert.Contains("AMI 5.6.7", md);
        Assert.Contains("Secure Boot：**Enabled**", md);
        Assert.Contains("检查项明细", md);
        Assert.Contains("需人工核验", md);            // Pending 项如实展示
        Assert.Contains("评分：**50 / 100**", md);   // 评分可追溯展示
        Assert.Contains("等级：**需人工核验**", md);
        Assert.Contains("BIOS 中禁用 USB Boot", md); // 整改建议
        Assert.Contains("尚未做过人工核验", md);
        Assert.Contains("BitLocker 边界", md);        // 验收：边界声明固定出现
        Assert.Contains("不使用", md);
    }

    [Fact]
    public void Csv_HasHeaderAndRows_EscapesCommas()
    {
        var report = SampleReport();
        report.Checks[2].Detail = "含,逗号的详情";

        var csv = ReportExporter.ToCsv(report);
        Assert.True(csv.IsSuccess);
        Assert.StartsWith("Id,检查项,类别,权重,状态,详情,整改建议", csv.Data);
        Assert.Equal(4, csv.Data!.Split('\n').Count(l => l.Length > 0)); // 表头 + 3 行
        Assert.Contains("\"含,逗号的详情\"", csv.Data); // CSV 转义
    }

    [Fact]
    public void WriteFiles_CreatesMarkdownAndCsv()
    {
        var result = ReportExporter.WriteFiles(SampleReport(), _tempDir);
        Assert.True(result.IsSuccess, result.ErrorMessage);

        Assert.True(File.Exists(result.Data!.MarkdownPath));
        Assert.True(File.Exists(result.Data.CsvPath));
        Assert.EndsWith(".md", result.Data.MarkdownPath);
        Assert.EndsWith(".csv", result.Data.CsvPath);

        // UTF-8 BOM（Excel 直开不乱码）
        var csvBytes = File.ReadAllBytes(result.Data.CsvPath);
        Assert.Equal(0xEF, csvBytes[0]);
        Assert.Equal(0xBB, csvBytes[1]);
        Assert.Equal(0xBF, csvBytes[2]);
    }

    // ───────────────────────── Assessor 集成（真实 WMI/注册表烟测） ─────────────────────────

    [Fact]
    public void Assessor_FullRun_ProducesConsistentReport()
    {
        var assessor = new DeviceSecurityAssessor(dataDir: Path.Combine(_tempDir, "ds"));
        var report = assessor.Assess("DEV-INTEGRATION");

        // 7 项检查（2 自动 + 5 人工），权重和 100
        Assert.Equal(7, report.Checks.Count);
        Assert.Equal(100, report.Checks.Sum(c => c.Weight));

        // 未核验 → 人工项全 Pending → 等级需人工核验
        Assert.Equal(SecurityGrade.NeedsManualReview, report.Grade);
        Assert.Equal(5, report.Checks.Count(c =>
            c.Category == "manual" && c.Status == CheckStatus.Pending));

        // 从未核验
        Assert.Null(report.VerificationCurrent);

        // 固件信息采集到了真实数据（任何机器都有厂商）
        Assert.NotEqual(string.Empty, report.Firmware.CollectedAt);
    }

    [Fact]
    public void Assessor_SaveVerification_ThenAssess_ShowsCurrent()
    {
        var assessor = new DeviceSecurityAssessor(dataDir: Path.Combine(_tempDir, "ds2"));
        var first = assessor.Assess("DEV-V");

        // 五项全部人工核验通过
        var save = assessor.SaveVerification(
            "DEV-V",
            first.Firmware,
            ManualChecklist.Definitions.Select(d => (d.Id, CheckStatus.Pass, "")).ToList(),
            "zhangsan");
        Assert.True(save.IsSuccess, save.ErrorMessage);

        var second = assessor.Assess("DEV-V");
        // 指纹未变 → 核验有效；自动项决定最终等级
        Assert.True(second.VerificationCurrent);
        Assert.All(second.Checks.Where(c => c.Category == "manual"),
            c => Assert.Equal(CheckStatus.Pass, c.Status));
    }

    [Fact]
    public void Assessor_SaveVerification_RejectsPendingEntries()
    {
        var assessor = new DeviceSecurityAssessor(dataDir: Path.Combine(_tempDir, "ds3"));
        var first = assessor.Assess("DEV-P");

        var save = assessor.SaveVerification(
            "DEV-P", first.Firmware,
            new[] { ("usb-boot", CheckStatus.Pending, "") },
            "zhangsan");
        Assert.False(save.IsSuccess);
    }
}
