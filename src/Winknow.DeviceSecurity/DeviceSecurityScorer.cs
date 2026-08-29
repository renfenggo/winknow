namespace Winknow.DeviceSecurity;

/// <summary>
/// 设备安全评分器（V7.0 第 11 周"设备评分：权重、等级、整改建议"）。
///
/// 评分模型（权重合计 100，自动项 50 + 人工项 50）：
///
/// | 检查项 | 类别 | 权重 |
/// |--------|------|------|
/// | Secure Boot 启用 | 自动 | 30 |
/// | UEFI 模式 | 自动 | 20 |
/// | BIOS 管理员密码 | 人工 | 15 |
/// | USB Boot 禁用 | 人工 | 15 |
/// | PXE 禁用 | 人工 | 10 |
/// | Boot Order | 人工 | 5 |
/// | Boot Menu 禁用 | 人工 | 5 |
///
/// 评分规则（验收"设备评分可追溯到原始检查项"）：
/// - Score = Σ(Pass 项权重)——每 1 分都对应具体检查项，报告逐项列出；
/// - 存在任何 Pending → Grade = NeedsManualReview（评分不完整，不得视为通过）；
/// - 无 Pending 时按失分与 Fail 项权重分级：
///   Score ≥ 85 → Secure；≥ 70 → Attention；&lt; 70 → HighRisk；
///   另有硬规则：Secure Boot Fail 或 usb-boot Fail → 至少 HighRisk
///   （外部启动是 V7.0 威胁模型 A3 的主通道，不容折扣）。
/// </summary>
public static class DeviceSecurityScorer
{
    /// <summary>自动项：Secure Boot（权重 30）。</summary>
    public const string CheckSecureBoot = "secure-boot";

    /// <summary>自动项：UEFI 固件模式（权重 20）。</summary>
    public const string CheckUefiMode = "uefi-mode";

    /// <summary>人工项：USB Boot 禁用（权重 15）——外部启动主通道。</summary>
    public const string CheckUsbBoot = "usb-boot";

    /// <summary>等级阈值：≥85 安全。</summary>
    public const int SecureThreshold = 85;

    /// <summary>等级阈值：≥70 需关注。</summary>
    public const int AttentionThreshold = 70;

    /// <summary>
    /// 汇总检查项 → 评分与等级（就地填充 report.Score / report.Grade）。
    /// </summary>
    public static void Score(DeviceSecurityReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var passWeight = 0;
        var hasPending = false;

        foreach (var check in report.Checks)
        {
            if (check.Status == CheckStatus.Pass)
            {
                passWeight += check.Weight;
            }
            else if (check.Status == CheckStatus.Pending)
            {
                hasPending = true;
            }
        }

        report.Score = passWeight;
        report.Grade = ComputeGrade(report.Checks, passWeight, hasPending);
    }

    /// <summary>
    /// 等级判定（独立方法便于测试）：
    /// Pending 存在 → NeedsManualReview；否则按分数 + 硬规则。
    /// </summary>
    public static SecurityGrade ComputeGrade(
        IReadOnlyList<CheckItem> checks, int passWeight, bool hasPending)
    {
        if (hasPending)
        {
            return SecurityGrade.NeedsManualReview;
        }

        // 硬规则：外部启动主通道失守 → 至少 HighRisk（无论总分）
        var criticalFailed = checks.Any(c =>
            c.Status == CheckStatus.Fail && c.Id is CheckSecureBoot or CheckUsbBoot);

        if (passWeight >= SecureThreshold)
        {
            return criticalFailed ? SecurityGrade.HighRisk : SecurityGrade.Secure;
        }
        if (passWeight >= AttentionThreshold)
        {
            return criticalFailed ? SecurityGrade.HighRisk : SecurityGrade.Attention;
        }
        return SecurityGrade.HighRisk;
    }

    /// <summary>
    /// 汇总全部未通过/待核验项的整改建议（按权重降序——先修影响最大的）。
    /// </summary>
    public static IReadOnlyList<string> BuildRemediations(IReadOnlyList<CheckItem> checks) =>
        checks
            .Where(c => c.Status is CheckStatus.Fail or CheckStatus.Pending && !string.IsNullOrEmpty(c.Remediation))
            .OrderByDescending(c => c.Weight)
            .Select(c => $"[{c.Status switch
            {
                CheckStatus.Fail => "未通过",
                _ => "待核验"
            }}] {c.Title}（权重 {c.Weight}）：{c.Remediation}")
            .ToList();

    /// <summary>等级中文名（UI/报告展示）。</summary>
    public static string GradeText(SecurityGrade grade) => grade switch
    {
        SecurityGrade.Secure => "安全",
        SecurityGrade.Attention => "需关注",
        SecurityGrade.HighRisk => "高风险",
        _ => "需人工核验"
    };
}
