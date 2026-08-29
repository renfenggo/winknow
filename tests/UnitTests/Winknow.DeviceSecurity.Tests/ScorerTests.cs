using Winknow.DeviceSecurity;

namespace Winknow.DeviceSecurity.Tests;

/// <summary>
/// 设备评分器测试（验收：设备评分可追溯到原始检查项；
/// 无法自动检测的项目不得视为通过）。
/// </summary>
public sealed class ScorerTests
{
    private static CheckItem Item(string id, CheckStatus status, int weight) => new()
    {
        Id = id, Title = id, Category = status == CheckStatus.Pass ? "auto" : "manual",
        Weight = weight, Status = status
    };

    private static DeviceSecurityReport ReportOf(params CheckItem[] checks) => new()
    {
        Checks = checks.ToList()
    };

    [Fact]
    public void AllPass_Score100_Secure()
    {
        var report = ReportOf(
            Item(DeviceSecurityScorer.CheckSecureBoot, CheckStatus.Pass, 30),
            Item(DeviceSecurityScorer.CheckUefiMode, CheckStatus.Pass, 20),
            Item("bios-password", CheckStatus.Pass, 15),
            Item("usb-boot", CheckStatus.Pass, 15),
            Item("pxe-boot", CheckStatus.Pass, 10),
            Item("boot-order", CheckStatus.Pass, 5),
            Item("boot-menu", CheckStatus.Pass, 5));

        DeviceSecurityScorer.Score(report);
        Assert.Equal(100, report.Score);
        Assert.Equal(SecurityGrade.Secure, report.Grade);
    }

    [Fact]
    public void Score_EqualsSumOfPassedWeights_Traceable()
    {
        // 验收"评分可追溯到原始检查项"：Score == Σ(Pass 权重)
        var report = ReportOf(
            Item(DeviceSecurityScorer.CheckSecureBoot, CheckStatus.Pass, 30),
            Item(DeviceSecurityScorer.CheckUefiMode, CheckStatus.Fail, 20),
            Item("bios-password", CheckStatus.Pass, 15));

        DeviceSecurityScorer.Score(report);
        Assert.Equal(45, report.Score); // 30+15
    }

    [Fact]
    public void AnyPending_GradeIsNeedsManualReview_EvenWithHighScore()
    {
        // 验收"无法自动检测的项目显示需人工核验，不显示为通过"：
        // 90 分但有一项 Pending → 等级必须降为需人工核验
        var report = ReportOf(
            Item(DeviceSecurityScorer.CheckSecureBoot, CheckStatus.Pass, 30),
            Item(DeviceSecurityScorer.CheckUefiMode, CheckStatus.Pass, 20),
            Item("bios-password", CheckStatus.Pass, 15),
            Item("usb-boot", CheckStatus.Pass, 15),
            Item("pxe-boot", CheckStatus.Pass, 10),
            Item("boot-order", CheckStatus.Pending, 5));

        DeviceSecurityScorer.Score(report);
        Assert.Equal(90, report.Score);
        Assert.Equal(SecurityGrade.NeedsManualReview, report.Grade);
    }

    [Fact]
    public void SecureBootFail_ForcesHighRisk_DespiteScore()
    {
        // 硬规则：Secure Boot 失守 → 至少 HighRisk（90-30+50=... 本例 70 分）
        var report = ReportOf(
            Item(DeviceSecurityScorer.CheckSecureBoot, CheckStatus.Fail, 30),
            Item(DeviceSecurityScorer.CheckUefiMode, CheckStatus.Pass, 20),
            Item("bios-password", CheckStatus.Pass, 15),
            Item("usb-boot", CheckStatus.Pass, 15),
            Item("pxe-boot", CheckStatus.Pass, 10),
            Item("boot-order", CheckStatus.Pass, 5),
            Item("boot-menu", CheckStatus.Pass, 5));

        DeviceSecurityScorer.Score(report);
        Assert.Equal(70, report.Score);
        Assert.Equal(SecurityGrade.HighRisk, report.Grade); // 而非 Attention
    }

    [Fact]
    public void UsbBootFail_ForcesHighRisk()
    {
        var report = ReportOf(
            Item(DeviceSecurityScorer.CheckSecureBoot, CheckStatus.Pass, 30),
            Item(DeviceSecurityScorer.CheckUefiMode, CheckStatus.Pass, 20),
            Item("bios-password", CheckStatus.Pass, 15),
            Item("usb-boot", CheckStatus.Fail, 15),
            Item("pxe-boot", CheckStatus.Pass, 10),
            Item("boot-order", CheckStatus.Pass, 5),
            Item("boot-menu", CheckStatus.Pass, 5));

        DeviceSecurityScorer.Score(report);
        Assert.Equal(85, report.Score); // 达到 Secure 阈值
        Assert.Equal(SecurityGrade.HighRisk, report.Grade); // 硬规则压过阈值
    }

    [Fact]
    public void GradeThresholds()
    {
        // 无 Pending、无关键 Fail：
        // 85 → Secure；84 → Attention；70 → Attention；69 → HighRisk
        Assert.Equal(SecurityGrade.Secure, DeviceSecurityScorer.ComputeGrade(
            Array.Empty<CheckItem>(), 85, hasPending: false));
        Assert.Equal(SecurityGrade.Attention, DeviceSecurityScorer.ComputeGrade(
            Array.Empty<CheckItem>(), 84, hasPending: false));
        Assert.Equal(SecurityGrade.Attention, DeviceSecurityScorer.ComputeGrade(
            Array.Empty<CheckItem>(), 70, hasPending: false));
        Assert.Equal(SecurityGrade.HighRisk, DeviceSecurityScorer.ComputeGrade(
            Array.Empty<CheckItem>(), 69, hasPending: false));
    }

    [Fact]
    public void Remediations_OrderedByWeightDesc_AndIncludePending()
    {
        var checks = new[]
        {
            Item("pxe-boot", CheckStatus.Fail, 10),
            Item("boot-order", CheckStatus.Pending, 5),
            Item("usb-boot", CheckStatus.Fail, 15)
        };
        // 补整改文案
        checks[0].Remediation = "禁用 PXE";
        checks[1].Remediation = "调整顺序";
        checks[2].Remediation = "禁用 USB 启动";

        var list = DeviceSecurityScorer.BuildRemediations(checks);
        Assert.Equal(3, list.Count);
        Assert.Contains("usb-boot", list[0]);   // 权重 15 最前
        Assert.Contains("pxe-boot", list[1]);
        Assert.Contains("boot-order", list[2]); // 待核验也给出指引
        Assert.Contains("待核验", list[2]);
    }

    [Fact]
    public void ManualDefinitions_TotalWeight50_FiveItems()
    {
        // 权重模型一致性：自动 50 + 人工 50 = 100
        Assert.Equal(5, ManualChecklist.Definitions.Count);
        Assert.Equal(50, ManualChecklist.Definitions.Sum(d => d.Weight));
    }
}
