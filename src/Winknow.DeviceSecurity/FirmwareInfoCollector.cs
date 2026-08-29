using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Winknow.Core;

namespace Winknow.DeviceSecurity;

/// <summary>
/// 固件信息采集器（V7.0 第 11 周"固件信息采集"）。
///
/// 采集内容：BIOS 厂商/版本/发布日期（Win32_BIOS）、主板厂商/型号/序列号
/// （Win32_BaseBoard）、整机厂商/型号（Win32_ComputerSystem）、固件类型
/// UEFI/Legacy（kernel32 GetFirmwareType，P/Invoke）。
///
/// 固件指纹：SHA256(BIOS版本 + 发布日期 + 主板序列号) 前 16 字节 Hex——
/// 供 <see cref="VerificationStore"/> 做"BIOS 更新/主板变化后核验记录失效"判定。
///
/// 容错语义：单项 WMI 查询失败不抛异常，字段保持 "Unknown"——
/// 采集器必须能在任意课堂设备上完成（Partial 优于 Crash）。
/// </summary>
public sealed class FirmwareInfoCollector
{
    private readonly ILogger? _logger;

    /// <summary>
    /// 构造固件信息采集器。
    /// </summary>
    /// <param name="logger">可选日志。</param>
    public FirmwareInfoCollector(ILogger? logger = null) => _logger = logger;

    /// <summary>
    /// 采集全部固件信息（WMI 三表 + GetFirmwareType）。
    /// </summary>
    public FirmwareInfo Collect()
    {
        var info = new FirmwareInfo { CollectedAt = DateTimeOffset.UtcNow.ToString("O") };

        FillFromWmi(info);
        info.FirmwareType = GetFirmwareType() switch
        {
            FirmwareType.Uefi => "UEFI",
            FirmwareType.Bios => "Legacy",
            _ => "Unknown"
        };

        _logger?.LogInformation(
            "固件信息采集完成：{Vendor} {Version} ({Type})", info.BiosVendor, info.BiosVersion, info.FirmwareType);
        return info;
    }

    /// <summary>
    /// 计算固件指纹（BIOS 更新或主板变化 → 指纹变化 → 核验记录失效）。
    /// </summary>
    public static string ComputeFingerprint(FirmwareInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);
        var raw = $"{info.BiosVersion}|{info.BiosReleaseDate}|{info.BoardSerial}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash, 0, 16).ToLowerInvariant();
    }

    private void FillFromWmi(FirmwareInfo info)
    {
        QueryFirst("SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS", mo =>
        {
            info.BiosVendor = mo["Manufacturer"]?.ToString() ?? "Unknown";
            info.BiosVersion = mo["SMBIOSBIOSVersion"]?.ToString() ?? "Unknown";
            info.BiosReleaseDate = mo["ReleaseDate"]?.ToString() ?? "Unknown";
        });

        QueryFirst("SELECT Manufacturer, Product, SerialNumber FROM Win32_BaseBoard", mo =>
        {
            info.BoardVendor = mo["Manufacturer"]?.ToString() ?? "Unknown";
            info.BoardModel = mo["Product"]?.ToString() ?? "Unknown";
            info.BoardSerial = mo["SerialNumber"]?.ToString() ?? "Unknown";
        });

        QueryFirst("SELECT Manufacturer, Model FROM Win32_ComputerSystem", mo =>
        {
            info.SystemVendor = mo["Manufacturer"]?.ToString() ?? "Unknown";
            info.SystemModel = mo["Model"]?.ToString() ?? "Unknown";
        });
    }

    private void QueryFirst(string query, Action<ManagementObject> fill)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(query);
            using var result = searcher.Get();
            var first = result.Cast<ManagementObject>().FirstOrDefault();
            if (first is not null)
            {
                using (first)
                {
                    fill(first);
                }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "WMI 查询失败: {Query}", query);
        }
    }

    /// <summary>
    /// 读取固件类型（UEFI/Bios）。API 不可用时返回 Unknown。
    /// </summary>
    public static FirmwareType GetFirmwareType()
    {
        try
        {
            // GetFirmwareType 自 Windows 8 起可用；失败（旧系统/权限）返回 0
            if (NativeMethods.GetFirmwareType(out var type) != 0)
            {
                return type switch
                {
                    2 => FirmwareType.Uefi,
                    1 => FirmwareType.Bios,
                    _ => FirmwareType.Unknown
                };
            }
            return FirmwareType.Unknown;
        }
        catch (Exception)
        {
            return FirmwareType.Unknown;
        }
    }

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint GetFirmwareType(out uint firmwareType);
    }
}

/// <summary>固件类型（GetFirmwareType 原始值映射）。</summary>
public enum FirmwareType
{
    /// <summary>未知（API 不可用或返回异常值）。</summary>
    Unknown = 0,

    /// <summary>传统 BIOS（Legacy/CSM）。</summary>
    Bios = 1,

    /// <summary>UEFI。</summary>
    Uefi = 2
}
