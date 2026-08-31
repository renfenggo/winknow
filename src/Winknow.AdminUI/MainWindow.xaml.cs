using System.IO;
using System.ServiceProcess;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using Winknow.Core;
using Winknow.Logging;
using Winknow.Security;
using Winknow.Licensing;
using Microsoft.Extensions.Logging;

namespace Winknow.AdminUI;

/// <summary>
/// 管理控制台主窗口。
/// 提供 V7.0 第 6 周"维护模式入口"（0.5 天）：密码+TOTP/恢复码验证、倒计时、退出。
/// </summary>
public partial class MainWindow : Window
{
    private static readonly string ConfigDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Winknow", "maintain");
    private static readonly string ConfigPath = Path.Combine(ConfigDir, "maintain.json");
    private static readonly string RecoveryPath = Path.Combine(ConfigDir, "recovery-codes.json");
    private static readonly string AuditDbPath = Path.Combine(ConfigDir, "audit.db");

    private static readonly string[] ManagedServices = ["Winknow Control Service", "Winknow Guard Service"];

    private MaintenanceSession? _session;
    private readonly DispatcherTimer _countdownTimer;
    private readonly TeacherLicenseServer _licenseServer;
    private readonly ILoggerFactory _loggerFactory;

    /// <summary>初始化主窗口。</summary>
    public MainWindow()
    {
        InitializeComponent();

        _countdownTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _countdownTimer.Tick += OnCountdownTick;

        // 初始化授权服务器和日志
        _loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
        var licenseLogger = _loggerFactory.CreateLogger<Winknow.Licensing.TeacherLicenseServer>();
        _licenseServer = new TeacherLicenseServer(licenseLogger);

        // 初始化课堂总览页面
        var classroomLogger = _loggerFactory.CreateLogger<Winknow.AdminUI.ClassroomPage>();
        var classroomPage = new ClassroomPage(_licenseServer, classroomLogger);
        ClassroomTabItem.Content = classroomPage;
    }

    private void OnEnterMaintenanceClick(object sender, RoutedEventArgs e)
    {
        var config = LoadConfig();
        if (config is null)
        {
            MessageBox.Show("未初始化维护配置，请先以管理员运行: RecoveryTool maintain init",
                "维护模式", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var dialog = new MaintenanceEntryDialog { Owner = this };
        if (dialog.ShowDialog() != true) return;

        var audit = new MaintenanceAuditLog(AuditDbPath);
        var recoveryStore = new RecoveryCodeStore(RecoveryPath);
        var totpSecret = TotpGenerator.Base32Decode(config.TotpSecretBase32);

        _session?.Dispose();
        _session = new MaintenanceSession(new MaintenanceSessionOptions
        {
            PasswordHash = config.PasswordHash,
            TotpSecret = totpSecret,
            RecoveryCodes = recoveryStore,
            DefaultTimeoutMinutes = dialog.TimeoutMinutes,
            OnEnter = StopManagedServices,
            OnExit = isTimeout => Dispatcher.Invoke(() => OnMaintenanceExited(isTimeout)),
            OnAudit = (actor, op, rsn, detail) => audit.RecordEntry(actor, op, rsn, detail)
        });

        var result = !string.IsNullOrWhiteSpace(dialog.RecoveryCode)
            ? _session.EnterWithRecoveryCode(dialog.RecoveryCode, Environment.UserName, "ui")
            : _session.Enter(dialog.Password, dialog.Totp, Environment.UserName, "ui");

        if (!result.IsSuccess)
        {
            MessageBox.Show(result.ErrorMessage, "进入维护失败", MessageBoxButton.OK, MessageBoxImage.Error);
            _session.Dispose();
            _session = null;
            return;
        }

        EnterMaintenanceBtn.IsEnabled = false;
        ExitMaintenanceBtn.IsEnabled = true;
        _countdownTimer.Start();
        UpdateCountdown();
    }

    private void OnExitMaintenanceClick(object sender, RoutedEventArgs e)
    {
        if (_session is { IsActive: true })
        {
            _session.Exit(Environment.UserName, "ui-exit");
        }
        OnMaintenanceExited(isTimeout: false);
    }

    private void OnMaintenanceExited(bool isTimeout)
    {
        _countdownTimer.Stop();
        _session?.Dispose();
        _session = null;
        EnterMaintenanceBtn.IsEnabled = true;
        ExitMaintenanceBtn.IsEnabled = false;
        StatusText.Text = isTimeout ? "维护模式已超时，服务保护已自动恢复" : "维护模式已结束";
    }

    private void OnCountdownTick(object? sender, EventArgs e) => UpdateCountdown();

    private void UpdateCountdown()
    {
        if (_session is not null && _session.IsActive && _session.ExpiresAt is { } exp)
        {
            var remaining = exp - DateTimeOffset.UtcNow;
            if (remaining < TimeSpan.Zero) remaining = TimeSpan.Zero;
            StatusText.Text = $"维护中 — 剩余 {remaining:hh\\:mm\\:ss}";
        }
    }

    private static void StopManagedServices()
    {
        foreach (var svc in ManagedServices)
        {
            try
            {
                using var sc = new ServiceController(svc);
                if (sc.Status == ServiceControllerStatus.Running)
                {
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                }
            }
            catch (InvalidOperationException) { /* 服务未安装 */ }
            catch { /* 忽略，维护入口不应被服务异常阻塞 */ }
        }
    }

    private static MaintainConfig? LoadConfig()
    {
        if (!File.Exists(ConfigPath)) return null;
        var json = File.ReadAllText(ConfigPath);
        return JsonSerializer.Deserialize<MaintainConfig>(json);
    }
}

internal sealed class MaintainConfig
{
    public string PasswordHash { get; set; } = string.Empty;
    public string TotpSecretBase32 { get; set; } = string.Empty;
}
