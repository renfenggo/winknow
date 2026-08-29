using System.Windows;

namespace Winknow.AdminUI;

/// <summary>
/// 维护模式入口对话框：收集密码+TOTP 或恢复码输入。
/// 仅收集输入，实际验证由 MainWindow 调用 MaintenanceSession 完成。
/// </summary>
public partial class MaintenanceEntryDialog : Window
{
    /// <summary>初始化维护入口对话框。</summary>
    public MaintenanceEntryDialog()
    {
        InitializeComponent();
    }

    /// <summary>用户输入的维护密码。</summary>
    public string Password => PasswordBox.Password;

    /// <summary>用户输入的 TOTP 码。</summary>
    public string Totp => TotpBox.Text.Trim();

    /// <summary>用户输入的恢复码（紧急通道）。</summary>
    public string RecoveryCode => RecoveryCodeBox.Text.Trim();

    /// <summary>超时分钟数。</summary>
    public int TimeoutMinutes { get; private set; } = 15;

    private void OnEnterClick(object sender, RoutedEventArgs e)
    {
        ErrorText.Text = string.Empty;

        var recovery = RecoveryCode;
        var hasRecovery = !string.IsNullOrWhiteSpace(recovery);
        var hasPassword = !string.IsNullOrWhiteSpace(PasswordBox.Password);
        var hasTotp = !string.IsNullOrWhiteSpace(Totp);

        if (!hasRecovery && !(hasPassword && hasTotp))
        {
            ErrorText.Text = "请填写密码+TOTP，或填写恢复码";
            return;
        }

        if (!int.TryParse(TimeoutBox.Text.Trim(), out var t) || t <= 0)
        {
            ErrorText.Text = "超时分钟数必须为正整数";
            return;
        }

        TimeoutMinutes = t;
        DialogResult = true;
    }
}
