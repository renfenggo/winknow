using System.IO;
using System.Windows;
using System.Windows.Controls;
using Winknow.DeviceSecurity;

namespace Winknow.AdminUI;

/// <summary>
/// 设备安全页面（V7.0 第 11 周 AdminUI，1.5 天）。
/// 状态、评分、报告和风险项展示 + 人工核验操作。
/// </summary>
public partial class DeviceSecurityPage : UserControl
{
    private DeviceSecurityReport? _report;
    private DeviceSecurityAssessor _assessor = new();

    /// <summary>检查项行视图（DataGrid 绑定用）。</summary>
    public sealed class CheckRow
    {
        /// <summary>检查项标题。</summary>
        public required string Title { get; init; }
        /// <summary>类别显示文本（自动检测/人工核验）。</summary>
        public required string CategoryText { get; init; }
        /// <summary>权重。</summary>
        public required int Weight { get; init; }
        /// <summary>状态显示文本（通过/未通过/需人工核验）。</summary>
        public required string StatusText { get; init; }
        /// <summary>详情。</summary>
        public required string Detail { get; init; }
        /// <summary>检查项 Id。</summary>
        public required string CheckId { get; init; }
        /// <summary>原始状态枚举。</summary>
        public required CheckStatus Status { get; init; }
        /// <summary>是否人工核验项。</summary>
        public required bool IsManual { get; init; }
    }

    /// <summary>初始化设备安全页面。</summary>
    public DeviceSecurityPage()
    {
        InitializeComponent();
    }

    private void OnAssessClick(object sender, RoutedEventArgs e)
    {
        AssessBtn.IsEnabled = false;
        AssessStatusText.Text = "正在采集（WMI/注册表/固件类型）…";
        try
        {
            _report = _assessor.Assess();
            RenderReport();
            AssessStatusText.Text = $"检测完成（{_report.GeneratedAt:HH:mm:ss}）";
            ExportBtn.IsEnabled = true;
        }
        catch (Exception ex)
        {
            AssessStatusText.Text = $"检测失败：{ex.Message}";
            MessageBox.Show($"设备安全评估失败：{ex.Message}", "错误",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            AssessBtn.IsEnabled = true;
        }
    }

    private void RenderReport()
    {
        if (_report is null) return;

        ScoreText.Text = $"{_report.Score}";
        GradeTextBlock.Text = DeviceSecurityScorer.GradeText(_report.Grade);
        GradeTextBlock.Foreground = _report.Grade switch
        {
            SecurityGrade.Secure => System.Windows.Media.Brushes.Green,
            SecurityGrade.Attention => System.Windows.Media.Brushes.DarkOrange,
            _ => System.Windows.Media.Brushes.Red
        };
        ScoreText.Foreground = GradeTextBlock.Foreground;

        SecureBootTextBlock.Text = _report.SecureBootState switch
        {
            "Enabled" => "已启用",
            "Disabled" => "已禁用",
            _ => "无法读取（需人工核验）"
        };

        VerificationTextBlock.Text = _report.VerificationCurrent switch
        {
            true => "有效",
            false => "已失效（固件变化，需重新核验）",
            _ => "从未核验"
        };

        var f = _report.Firmware;
        FirmwareTextBlock.Text =
            $"固件信息：{f.BiosVendor} {f.BiosVersion}（{f.BiosReleaseDate}） | " +
            $"模式：{f.FirmwareType} | 主板：{f.BoardVendor} {f.BoardModel} | " +
            $"整机：{f.SystemVendor} {f.SystemModel} | " +
            $"系统盘：磁盘 {_report.BootConfig.SystemDiskIndex?.ToString() ?? "?"}（{_report.BootConfig.PartitionStyle}）";

        ChecksGrid.ItemsSource = _report.Checks.Select(c => new CheckRow
        {
            CheckId = c.Id,
            Title = c.Title,
            CategoryText = c.Category == "manual" ? "人工核验" : "自动检测",
            Weight = c.Weight,
            StatusText = c.Status switch
            {
                CheckStatus.Pass => "通过",
                CheckStatus.Fail => "未通过",
                _ => "需人工核验"
            },
            Detail = c.Detail,
            Status = c.Status,
            IsManual = c.Category == "manual"
        }).ToList();

        var risks = DeviceSecurityScorer.BuildRemediations(_report.Checks);
        RiskTextBlock.Text = risks.Count > 0
            ? "整改建议（按影响排序）：\n  " + string.Join("\n  ", risks)
            : "全部检查项通过。";
    }

    private void OnMarkPassClick(object sender, RoutedEventArgs e) => MarkSelected(CheckStatus.Pass);
    private void OnMarkFailClick(object sender, RoutedEventArgs e) => MarkSelected(CheckStatus.Fail);

    private void MarkSelected(CheckStatus status)
    {
        if (ChecksGrid.SelectedItem is not CheckRow row)
        {
            MessageBox.Show("请先在检查项列表中选择一行", "人工核验",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (!row.IsManual)
        {
            MessageBox.Show($"「{row.Title}」是自动检测项，无需人工核验", "人工核验",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (string.IsNullOrWhiteSpace(AdminNameBox.Text))
        {
            MessageBox.Show("请填写核验管理员姓名", "人工核验",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            AdminNameBox.Focus();
            return;
        }

        if (_report is null)
        {
            MessageBox.Show("请先开始检测（需要固件指纹绑定核验记录）", "人工核验",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var save = _assessor.SaveVerification(
            _report.DeviceId,
            _report.Firmware,
            new[] { (row.CheckId, status, NoteBox.Text.Trim()) },
            AdminNameBox.Text.Trim());
        if (!save.IsSuccess)
        {
            MessageBox.Show(save.ErrorMessage, "保存核验失败",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        // 重新评估以刷新评分与核验状态（新指纹已随采集固定，刷新不破坏判定）
        _report = _assessor.Assess(_report.DeviceId);
        RenderReport();
        NoteBox.Clear();
    }

    private void OnExportClick(object sender, RoutedEventArgs e)
    {
        if (_report is null) return;

        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = "导出设备安全报告",
            Filter = "Markdown 报告 (*.md)|*.md",
            FileName = $"device_security_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}.md"
        };
        if (dialog.ShowDialog() != true) return;

        var outputDir = Path.GetDirectoryName(dialog.FileName)!;
        var result = ReportExporter.WriteFiles(_report, outputDir);
        if (result.IsSuccess)
        {
            MessageBox.Show(
                $"报告已导出：\n{result.Data.MarkdownPath}\n{result.Data.CsvPath}",
                "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            MessageBox.Show(result.ErrorMessage, "导出失败",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
