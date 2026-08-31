using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Winknow.Licensing;
using Winknow.Core.Results;
using Winknow.Ipc;
using Microsoft.Extensions.Logging;

namespace Winknow.AdminUI;

/// <summary>
/// ClassroomPage.xaml 的交互逻辑
/// 课堂总览页面：设备名单+实时状态+远程解锁（双路解锁）。
/// </summary>
public partial class ClassroomPage : Page
{
    private readonly TeacherLicenseServer _licenseServer;
    private readonly ILogger<ClassroomPage>? _logger;
    private DeviceStatusInfo? _selectedDevice;

    /// <summary>
    /// 初始化 ClassroomPage 类的新实例。
    /// </summary>
    /// <param name="licenseServer">教师许可证服务器实例。</param>
    /// <param name="logger">可选的日志记录器。</param>
    public ClassroomPage(TeacherLicenseServer licenseServer, ILogger<ClassroomPage>? logger = null)
    {
        InitializeComponent();
        _licenseServer = licenseServer ?? throw new ArgumentNullException(nameof(licenseServer));
        _logger = logger;

        LoadDevices();
    }

    /// <summary>
    /// 加载设备列表。
    /// </summary>
    private void LoadDevices()
    {
        try
        {
            var devices = _licenseServer.GetAllDeviceStatus();

            // 转换为显示模型
            var deviceViewModels = devices.Select(d => new DeviceViewModel
            {
                DeviceId = d.DeviceId,
                StudentName = d.StudentName,
                Status = d.Status,
                StatusDisplay = GetStatusDisplay(d.Status),
                StatusColor = GetStatusColor(d.Status),
                LastSeen = d.LastSeen,
                LastSeenDisplay = FormatLastSeen(d.LastSeen),
                LockedAt = d.LockedAt,
                LockedAtDisplay = d.LockedAt.HasValue ? d.LockedAt.Value.ToString("yyyy-MM-dd HH:mm:ss") : "-"
            }).ToList();

            DevicesGrid.ItemsSource = deviceViewModels;
            UpdateStatistics(deviceViewModels);

            _logger?.LogInformation("Loaded {Count} devices into classroom overview", deviceViewModels.Count);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to load devices");
            MessageBox.Show($"加载设备列表失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    /// <summary>
    /// 刷新设备状态。
    /// </summary>
    private void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        LoadDevices();
        _logger?.LogInformation("Classroom overview refreshed by user");
    }

    /// <summary>
    /// 生成解锁码。
    /// </summary>
    private void GenerateCodeButton_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedDevice == null)
        {
            MessageBox.Show("请先选择一个设备", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            var result = _licenseServer.GenerateDynamicCode(_selectedDevice.DeviceId);

            if (result.IsSuccess)
            {
                var code = result.Data;
                var message = $"设备 {_selectedDevice.StudentName} ({_selectedDevice.DeviceId}) 的动态解锁码：\n\n{code}\n\n此码有效期为5分钟";

                MessageBoxResult dialogResult = MessageBox.Show(
                    message,
                    "动态解锁码",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);

                _logger?.LogInformation("Generated dynamic code for device {DeviceId}: {Code}", _selectedDevice.DeviceId, code);
            }
            else
            {
                MessageBox.Show($"生成解锁码失败：{result.ErrorMessage}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                _logger?.LogError("Failed to generate code for device {DeviceId}: {Error}", _selectedDevice.DeviceId, result.ErrorMessage);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to generate code for device {DeviceId}", _selectedDevice?.DeviceId);
            MessageBox.Show($"生成解锁码失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    /// <summary>
    /// 解锁设备。
    /// </summary>
    private void UnlockButton_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedDevice == null)
        {
            MessageBox.Show("请先选择一个设备", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var result = MessageBox.Show(
            $"确定要解锁设备 {_selectedDevice.StudentName} ({_selectedDevice.DeviceId}) 吗？",
            "确认解锁",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result == MessageBoxResult.Yes)
        {
            try
            {
                var unlockResult = _licenseServer.UnlockDevice(_selectedDevice.DeviceId);

                if (unlockResult.IsSuccess)
                {
                    MessageBox.Show("设备解锁成功", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    LoadDevices();
                    _logger?.LogInformation("Device {DeviceId} unlocked by admin", _selectedDevice.DeviceId);
                }
                else
                {
                    MessageBox.Show($"解锁失败：{unlockResult.ErrorMessage}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    _logger?.LogError("Failed to unlock device {DeviceId}: {Error}", _selectedDevice.DeviceId, unlockResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to unlock device {DeviceId}", _selectedDevice?.DeviceId);
                MessageBox.Show($"解锁失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    /// <summary>
    /// 锁定设备。
    /// </summary>
    private void LockButton_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedDevice == null)
        {
            MessageBox.Show("请先选择一个设备", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var result = MessageBox.Show(
            $"确定要锁定设备 {_selectedDevice.StudentName} ({_selectedDevice.DeviceId}) 吗？\n\n锁定后设备将显示锁屏遮罩，需要解锁码才能恢复。",
            "确认锁定",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
        {
            try
            {
                var lockResult = _licenseServer.LockDevice(_selectedDevice.DeviceId);

                if (lockResult.IsSuccess)
                {
                    MessageBox.Show("设备锁定成功", "成功", MessageBoxButton.OK, MessageBoxImage.Information);

                    // TODO 通过IPC通知SessionAgent显示锁屏遮罩
                    // SendLockOverlayCommand(_selectedDevice.DeviceId, "SHOW");

                    LoadDevices();
                    _logger?.LogInformation("Device {DeviceId} locked by admin", _selectedDevice.DeviceId);
                }
                else
                {
                    MessageBox.Show($"锁定失败：{lockResult.ErrorMessage}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    _logger?.LogError("Failed to lock device {DeviceId}: {Error}", _selectedDevice.DeviceId, lockResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to lock device {DeviceId}", _selectedDevice?.DeviceId);
                MessageBox.Show($"锁定失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    /// <summary>
    /// 更新统计信息。
    /// </summary>
    private void UpdateStatistics(List<DeviceViewModel> devices)
    {
        var onlineCount = devices.Count(d => d.Status == DeviceStatus.Online);
        var graceCount = devices.Count(d => d.Status == DeviceStatus.GracePeriod);
        var lockedCount = devices.Count(d => d.Status == DeviceStatus.Locked);

        OnlineCount.Text = onlineCount.ToString();
        GraceCount.Text = graceCount.ToString();
        LockedCount.Text = lockedCount.ToString();
    }

    /// <summary>
    /// 获取状态显示文本。
    /// </summary>
    private static string GetStatusDisplay(DeviceStatus status)
    {
        return status switch
        {
            DeviceStatus.Online => "在线",
            DeviceStatus.Locked => "锁定",
            _ => "未知"
        };
    }

    /// <summary>
    /// 获取状态颜色。
    /// </summary>
    private static Brush GetStatusColor(DeviceStatus status)
    {
        return status switch
        {
            DeviceStatus.Online => new SolidColorBrush(Color.FromRgb(76, 175, 80)),   // 绿色
            DeviceStatus.Locked => new SolidColorBrush(Color.FromRgb(244, 67, 54)),   // 红色
            _ => new SolidColorBrush(Color.FromRgb(158, 158, 158))                   // 灰色
        };
    }

    /// <summary>
    /// 格式化最后心跳时间。
    /// </summary>
    private static string FormatLastSeen(DateTime lastSeen)
    {
        var elapsed = DateTime.UtcNow - lastSeen;

        if (elapsed.TotalMinutes < 1)
            return "刚刚";

        if (elapsed.TotalMinutes < 60)
            return $"{(int)elapsed.TotalMinutes} 分钟前";

        if (elapsed.TotalHours < 24)
            return $"{(int)elapsed.TotalHours} 小时前";

        return lastSeen.ToString("yyyy-MM-dd HH:mm:ss");
    }

    /// <summary>
    /// 处理设备选择变化。
    /// </summary>
    private void DevicesGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        _selectedDevice = (DeviceStatusInfo)DevicesGrid.SelectedItem;
        UpdateButtonStates();
    }

    /// <summary>
    /// 更新按钮状态。
    /// </summary>
    private void UpdateButtonStates()
    {
        var hasSelection = _selectedDevice != null;
        var isLocked = _selectedDevice?.Status == DeviceStatus.Locked;

        GenerateCodeButton.IsEnabled = hasSelection;
        UnlockButton.IsEnabled = hasSelection && isLocked;
        LockButton.IsEnabled = hasSelection && !isLocked;
    }
}

/// <summary>
/// 设备视图模型。
/// </summary>
public sealed class DeviceViewModel
{
    /// <summary>
    /// 获取或设置设备 ID。
    /// </summary>
    public string DeviceId { get; set; } = string.Empty;
    
    /// <summary>
    /// 获取或设置学生姓名。
    /// </summary>
    public string StudentName { get; set; } = string.Empty;
    
    /// <summary>
    /// 获取或设置设备状态。
    /// </summary>
    public DeviceStatus Status { get; set; }
    
    /// <summary>
    /// 获取或设置状态显示文本。
    /// </summary>
    public string StatusDisplay { get; set; } = string.Empty;
    
    /// <summary>
    /// 获取或设置状态颜色。
    /// </summary>
    public Brush StatusColor { get; set; } = Brushes.Transparent;
    
    /// <summary>
    /// 获取或设置最后连接时间。
    /// </summary>
    public DateTime LastSeen { get; set; }
    
    /// <summary>
    /// 获取或设置最后连接时间的显示文本。
    /// </summary>
    public string LastSeenDisplay { get; set; } = string.Empty;
    
    /// <summary>
    /// 获取或设置锁定时间。
    /// </summary>
    public DateTime? LockedAt { get; set; }
    
    /// <summary>
    /// 获取或设置锁定时间的显示文本。
    /// </summary>
    public string LockedAtDisplay { get; set; } = string.Empty;
}