using System.Management;
using Microsoft.Extensions.Logging;

namespace Winknow.DeviceSecurity;

/// <summary>
/// 启动配置采集器（V7.0 第 11 周"启动配置采集：可读取的启动项和系统盘状态"）。
///
/// 采集内容：
/// - 系统盘与分区表风格：Win32_BootPartition → Win32_DiskPartition
///   （分区 Type 含 "GPT:" 前缀即 GPT 磁盘；GPT+UEFI 是 Secure Boot 的正确配套）；
/// - 启动分区清单（磁盘索引+类型描述摘要）；
/// - BCD 可读性：bcdedit /enum 尝试（需管理员；失败标记为不可读，不视为错误）。
///
/// 与人工核验的边界：BCD/BIOS 层面的 USB Boot、PXE、Boot Order 开关
/// 属固件设置，操作系统内不可可靠读取——一律走 ManualChecklist，
/// 本采集器的 BCD 能力仅作辅助证据，绝不替代人工结论。
/// </summary>
public sealed class BootConfigCollector
{
    private readonly ILogger? _logger;

    /// <summary>
    /// 构造启动配置采集器。
    /// </summary>
    /// <param name="logger">可选日志。</param>
    public BootConfigCollector(ILogger? logger = null) => _logger = logger;

    /// <summary>
    /// 采集系统盘与启动分区信息。
    /// </summary>
    public BootConfigInfo Collect()
    {
        var info = new BootConfigInfo { CollectedAt = DateTimeOffset.UtcNow.ToString("O") };
        try
        {
            // 启动分区（BootPartition=true）→ 所在磁盘
            using var bootSearcher = new ManagementObjectSearcher(
                "SELECT Antecedent, Dependent FROM Win32_BootPartition");
            using var bootResults = bootSearcher.Get();

            foreach (var boot in bootResults.Cast<ManagementObject>())
            {
                using var partition = (ManagementObject)boot["Antecedent"];
                var type = partition["Type"]?.ToString() ?? "Unknown";
                var diskIndex = Convert.ToInt32(partition["DiskIndex"]);
                var desc = $"{partition["DeviceID"]?.ToString()} ({type})";

                info.SystemDiskIndex ??= diskIndex;
                info.SystemPartitionType = type;
                info.Partitions.Add(desc);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "启动分区采集失败");
        }

        // 同盘全部分区：任一分区 Type 以 "GPT:" 开头 → GPT 磁盘
        if (info.SystemDiskIndex is int disk)
        {
            info.PartitionStyle = GetDiskPartitionStyle(disk);
        }

        info.BcdReadable = TryProbeBcdAccess();
        _logger?.LogInformation(
            "启动配置采集：磁盘 {Disk}，分区表 {Style}，BCD 可读: {Bcd}",
            info.SystemDiskIndex, info.PartitionStyle, info.BcdReadable);
        return info;
    }

    /// <summary>
    /// 判定磁盘分区表风格：GPT / MBR / Unknown。
    /// 纯逻辑（WMI 数据驱动），供单元测试直接验证判定规则。
    /// </summary>
    /// <param name="partitionTypes">该磁盘全部分区的 Type 描述。</param>
    public static string DeterminePartitionStyle(IEnumerable<string> partitionTypes)
    {
        foreach (var t in partitionTypes)
        {
            if (t.StartsWith("GPT:", StringComparison.OrdinalIgnoreCase))
            {
                return "GPT";
            }
        }
        // WMI 中 MBR 磁盘分区无 "GPT:" 前缀（如 "Installable File System"）；
        // 空列表（采集失败）保持 Unknown
        return partitionTypes.Any() ? "MBR" : "Unknown";
    }

    private string GetDiskPartitionStyle(int diskIndex)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT Type FROM Win32_DiskPartition WHERE DiskIndex = {diskIndex}");
            using var results = searcher.Get();
            var types = results.Cast<ManagementBaseObject>().Select(p => p["Type"]?.ToString() ?? string.Empty);
            return DeterminePartitionStyle(types);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "磁盘 {Disk} 分区表判定失败", diskIndex);
            return "Unknown";
        }
    }

    /// <summary>
    /// 探测 BCD 是否可读（bcdedit 需要管理员；不可读仅记录，不是错误——BCD 明细属人工核验范畴）。
    /// </summary>
    private bool? TryProbeBcdAccess()
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "bcdedit.exe",
                Arguments = "/enum {current}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var process = System.Diagnostics.Process.Start(psi);
            if (process is null) return null;
            process.WaitForExit(5000);
            return process.ExitCode == 0;
        }
        catch (Exception)
        {
            return null; // 无法判定（bcdedit 不存在/超时）——不猜
        }
    }
}
