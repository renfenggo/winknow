using System.IO;
using System.Text;
using Winknow.Core;
using Winknow.Core.Results;

namespace Winknow.DeviceSecurity;

/// <summary>
/// 核验报告导出器（V7.0 第 11 周"导出报告：Markdown/CSV"）。
///
/// Markdown：完整报告（设备/固件/Secure Boot/启动配置/检查项明细/
/// 评分与等级/整改建议/核验记录状态），打印友好；
/// CSV：检查项明细表（Id/标题/类别/权重/状态/详情/建议），可导入表格。
///
/// 每份报告固定包含 BitLocker 边界声明（验收：
/// "文档明确 V7.0 不使用 BitLocker 的边界"）。
/// </summary>
public static class ReportExporter
{
    /// <summary>BitLocker 边界声明（报告固定页脚）。</summary>
    public const string BitLockerBoundaryNote =
        "BitLocker 边界：V7.0 不使用、不检测、不依赖 BitLocker/TPM 全盘加密——"
        + "启动安全防线为 Secure Boot + USB/PXE 启动禁用 + 进程管控；"
        + "若学校镜像统一启用 BitLocker，与本系统正交运行，互不干预。";

    private static string StatusText(CheckStatus s) => s switch
    {
        CheckStatus.Pass => "通过",
        CheckStatus.Fail => "未通过",
        CheckStatus.Pending => "需人工核验",
        _ => "不适用"
    };

    /// <summary>
    /// 生成 Markdown 完整报告。
    /// </summary>
    public static string ToMarkdown(DeviceSecurityReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var sb = new StringBuilder();

        sb.AppendLine("# 设备启动安全核验报告");
        sb.AppendLine();
        sb.AppendLine($"- 生成时间：{report.GeneratedAt}");
        sb.AppendLine($"- 设备 ID：{report.DeviceId}");
        sb.AppendLine();

        sb.AppendLine("## 一、固件信息");
        sb.AppendLine();
        sb.AppendLine($"| 项目 | 值 |");
        sb.AppendLine($"|------|-----|");
        sb.AppendLine($"| BIOS | {report.Firmware.BiosVendor} {report.Firmware.BiosVersion}（{report.Firmware.BiosReleaseDate}） |");
        sb.AppendLine($"| 固件类型 | {report.Firmware.FirmwareType} |");
        sb.AppendLine($"| 主板 | {report.Firmware.BoardVendor} {report.Firmware.BoardModel} |");
        sb.AppendLine($"| 整机 | {report.Firmware.SystemVendor} {report.Firmware.SystemModel} |");
        sb.AppendLine();

        sb.AppendLine("## 二、Secure Boot 与启动配置");
        sb.AppendLine();
        sb.AppendLine($"- Secure Boot：**{report.SecureBootState}**");
        sb.AppendLine($"- 系统盘：磁盘 {report.BootConfig.SystemDiskIndex?.ToString() ?? "Unknown"}（{report.BootConfig.PartitionStyle}）");
        sb.AppendLine($"- 系统分区：{report.BootConfig.SystemPartitionType}");
        if (report.BootConfig.BcdReadable is bool bcd)
        {
            sb.AppendLine($"- BCD 可读：{(bcd ? "是" : "否（需管理员或人工核验）")}");
        }
        sb.AppendLine();

        sb.AppendLine("## 三、检查项明细（评分可追溯）");
        sb.AppendLine();
        sb.AppendLine("| # | 检查项 | 类别 | 权重 | 状态 | 详情 |");
        sb.AppendLine("|---|--------|------|------|------|------|");
        var index = 1;
        foreach (var c in report.Checks)
        {
            sb.AppendLine($"| {index++} | {c.Title} | {(c.Category == "manual" ? "人工核验" : "自动检测")} | {c.Weight} | {StatusText(c.Status)} | {c.Detail} |");
        }
        sb.AppendLine();

        sb.AppendLine("## 四、评分与整改建议");
        sb.AppendLine();
        sb.AppendLine($"- 评分：**{report.Score} / 100**");
        sb.AppendLine($"- 等级：**{DeviceSecurityScorer.GradeText(report.Grade)}**");
        sb.AppendLine();

        var remediations = DeviceSecurityScorer.BuildRemediations(report.Checks);
        if (remediations.Count > 0)
        {
            sb.AppendLine("整改建议（按影响排序）：");
            sb.AppendLine();
            foreach (var r in remediations)
            {
                sb.AppendLine($"1. {r}");
            }
        }
        else
        {
            sb.AppendLine("全部检查项通过，无需整改。");
        }
        sb.AppendLine();

        sb.AppendLine("## 五、核验记录状态");
        sb.AppendLine();
        sb.AppendLine(report.VerificationCurrent switch
        {
            true => "既有核验记录与当前固件匹配，核验有效。",
            false => "⚠ 固件已变化，旧核验记录已自动失效，需重新人工核验。",
            _ => "本机尚未做过人工核验。"
        });
        sb.AppendLine();

        sb.AppendLine("## 六、品牌 BIOS 设置指引（人工核验用）");
        sb.AppendLine();
        var profile = BiosCompatibilityMatrix.Match(
            report.Firmware.BiosVendor, report.Firmware.SystemVendor);
        var hotKeys = string.IsNullOrEmpty(profile.BootMenuHotKey)
            ? profile.BiosHotKey
            : $"{profile.BiosHotKey}；启动菜单 {profile.BootMenuHotKey}";
        sb.AppendLine($"- 匹配品牌：**{profile.DisplayName}**（{hotKeys}）");
        if (!string.IsNullOrEmpty(profile.Notes))
        {
            sb.AppendLine($"- 品牌备注：{profile.Notes}");
        }
        sb.AppendLine();
        sb.AppendLine("| 检查项 | 该品牌菜单路径 | 注意事项 |");
        sb.AppendLine("|--------|----------------|----------|");
        foreach (var c in report.Checks.Where(c => c.Category == "manual"
            || c.Id == DeviceSecurityScorer.CheckSecureBoot))
        {
            var p = BiosCompatibilityMatrix.FindPath(profile, c.Id);
            sb.AppendLine($"| {c.Title} | {p?.Path ?? "见机型手册"} | {p?.Note ?? string.Empty} |");
        }
        sb.AppendLine();

        sb.AppendLine("---");
        sb.AppendLine();
        sb.AppendLine($"> {BitLockerBoundaryNote}");

        return sb.ToString();
    }

    /// <summary>
    /// 生成检查项明细 CSV（UTF-8 BOM，Excel 直接打开不乱码）。
    /// </summary>
    public static Result<string> ToCsv(DeviceSecurityReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("Id,检查项,类别,权重,状态,详情,整改建议");
            foreach (var c in report.Checks)
            {
                sb.AppendLine(string.Join(',',
                    c.Id, Escape(c.Title), c.Category == "manual" ? "人工核验" : "自动检测",
                    c.Weight.ToString(), StatusText(c.Status), Escape(c.Detail), Escape(c.Remediation)));
            }
            return Result<string>.Success(sb.ToString());
        }
        catch (Exception ex)
        {
            return Result<string>.Failure(ErrorCode.ExternalError, $"CSV 生成失败: {ex.Message}");
        }
    }

    /// <summary>
    /// 写报告文件到目录（Markdown + CSV 双格式）。
    /// </summary>
    /// <returns>（Markdown 路径，CSV 路径）；失败返回失败结果。</returns>
    public static Result<(string MarkdownPath, string CsvPath)> WriteFiles(
        DeviceSecurityReport report, string outputDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDir);
        try
        {
            Directory.CreateDirectory(outputDir);
            var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd_HHmmss");
            var mdPath = Path.Combine(outputDir, $"device_security_{stamp}.md");
            var csvPath = Path.Combine(outputDir, $"device_security_{stamp}.csv");

            File.WriteAllText(mdPath, ToMarkdown(report), new UTF8Encoding(true));
            var csv = ToCsv(report);
            if (!csv.IsSuccess) return Result<(string, string)>.Failure(csv.ErrorCode, csv.ErrorMessage);
            File.WriteAllText(csvPath, csv.Data!, new UTF8Encoding(true));

            return Result<(string, string)>.Success((mdPath, csvPath));
        }
        catch (Exception ex)
        {
            return Result<(string, string)>.Failure(ErrorCode.ExternalError, $"报告写出失败: {ex.Message}");
        }
    }

    private static string Escape(string field) =>
        field.Contains(',') || field.Contains('"') || field.Contains('\n')
            ? $"\"{field.Replace("\"", "\"\"")}\""
            : field;
}
