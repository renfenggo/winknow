namespace Winknow.DeviceSecurity;

/// <summary>
/// 单个 BIOS 设置项的菜单路径（品牌差异表原子）。
/// </summary>
public sealed class BiosSettingPath
{
    /// <summary>设置项 Id（与第 11 周检查项 Id 对齐：bios-password/usb-boot/pxe-boot/boot-order/boot-menu/secure-boot/uefi-mode）。</summary>
    public required string CheckId { get; init; }

    /// <summary>菜单路径（该品牌 BIOS 内的导航路径）。</summary>
    public required string Path { get; init; }

    /// <summary>品牌特定注意事项。</summary>
    public string Note { get; init; } = string.Empty;
}

/// <summary>
/// 品牌 BIOS 档案（V7.0 第 12 周"品牌差异表"代码化）。
/// </summary>
public sealed class BiosVendorProfile
{
    /// <summary>档案键（lenovo/dell/hp/asus/generic）。</summary>
    public required string Key { get; init; }

    /// <summary>品牌显示名。</summary>
    public required string DisplayName { get; init; }

    /// <summary>进入 BIOS 的热键。</summary>
    public required string BiosHotKey { get; init; }

    /// <summary>一次性启动菜单热键（空串表示该品牌无独立热键或需在 BIOS 内启用）。</summary>
    public string BootMenuHotKey { get; init; } = string.Empty;

    /// <summary>厂商匹配模式（对 WMI BIOS/整机厂商串做不区分大小写的包含匹配）。</summary>
    public required IReadOnlyList<string> MatchPatterns { get; init; }

    /// <summary>六项设置的品牌菜单路径。</summary>
    public required IReadOnlyList<BiosSettingPath> SettingPaths { get; init; }

    /// <summary>品牌差异备注（无法自动化项说明）。</summary>
    public string Notes { get; init; } = string.Empty;
}

/// <summary>
/// 多品牌 BIOS/UEFI 兼容矩阵（V7.0 第 12 周核心交付的代码面）。
///
/// 覆盖：联想（ThinkCentre/启天/ThinkPad 教学线）、戴尔（OptiPlex）、
/// 惠普（ProDesk/EliteDesk）、华硕（商用台式/主板），另含 generic 兜底档案。
/// 数据来源：各厂商公开 BIOS 手册路径整理（差异表文档含版本说明）。
///
/// 联动：DeviceSecurityAssessor 评估时按固件厂商自动匹配档案，
/// 报告与 AdminUI 展示当前机型的设置路径——管理员核验时
/// 直接按指引操作（第 11 周五项人工核验 × 第 12 周品牌路径）。
/// </summary>
public static class BiosCompatibilityMatrix
{
    /// <summary>全部品牌档案（含 generic）。</summary>
    public static readonly IReadOnlyList<BiosVendorProfile> Profiles = new List<BiosVendorProfile>
    {
        new()
        {
            Key = "lenovo", DisplayName = "联想（Lenovo/ThinkCentre/启天）", BiosHotKey = "F1", BootMenuHotKey = "F12",
            MatchPatterns = new[] { "lenovo", "联想" },
            SettingPaths = new List<BiosSettingPath>
            {
                new() { CheckId = "bios-password", Path = "Security → Administrator Password", Note = "学生机建议同时设置 Power-On Password 按需" },
                new() { CheckId = "usb-boot", Path = "Startup → USB Boot → Disabled", Note = "部分机型在 Restart → Setup Utility 下" },
                new() { CheckId = "pxe-boot", Path = "Startup → Network Boot → Disabled（或改 Legacy 只保留 HDD）" },
                new() { CheckId = "boot-order", Path = "Startup → Boot：将内部 HDD/SSD 调至首位（Excluded 列表移除外设）" },
                new() { CheckId = "boot-menu", Path = "Startup → Boot Menu → Disabled（F12 菜单关闭）" },
                new() { CheckId = "secure-boot", Path = "Security → Secure Boot → Enabled", Note = "需先切换 UEFI 模式" }
            },
            Notes = "教学机型常见 F1 进 BIOS / F12 启动菜单；部分启天机型 BIOS 精简，路径以随机手册为准"
        },
        new()
        {
            Key = "dell", DisplayName = "戴尔（Dell OptiPlex）", BiosHotKey = "F2", BootMenuHotKey = "F12",
            MatchPatterns = new[] { "dell" },
            SettingPaths = new List<BiosSettingPath>
            {
                new() { CheckId = "bios-password", Path = "Security → System Password / Setup Password", Note = "Setup Password 才限制 BIOS 修改，两者都建议设置" },
                new() { CheckId = "usb-boot", Path = "Boot Configuration → Secure Boot → 未启用项；Storage/USB 在 Boot Sequence 关闭" },
                new() { CheckId = "pxe-boot", Path = "Boot Configuration → Boot Sequence 取消勾选 Onboard NIC/PXE" },
                new() { CheckId = "boot-order", Path = "Boot Configuration → Boot Sequence：仅勾选内部硬盘" },
                new() { CheckId = "boot-menu", Path = "Boot Configuration → Boot Sequence（One Time Boot 由 F12 触发，可在 BIOS 关闭）" },
                new() { CheckId = "secure-boot", Path = "Secure Boot → Secure Boot Enable → Enabled" }
            },
            Notes = "OptiPlex 新版 BIOS 为分页布局（与旧版树形不同）；BIOS 更新后个别设置项会复位，更新后必须复检"
        },
        new()
        {
            Key = "hp", DisplayName = "惠普（HP ProDesk/EliteDesk）", BiosHotKey = "F10", BootMenuHotKey = "F9",
            MatchPatterns = new[] { "hp", "hewlett" },
            SettingPaths = new List<BiosSettingPath>
            {
                new() { CheckId = "bios-password", Path = "Security → Administrator Password", Note = "HP 需同时注意 Power-On Password 联动选项" },
                new() { CheckId = "usb-boot", Path = "Advanced → Boot Options → 取消 USB Storage Boot（部分机型在 Storage 菜单）" },
                new() { CheckId = "pxe-boot", Path = "Advanced → Boot Options → 取消 Network (PXE) Boot" },
                new() { CheckId = "boot-order", Path = "Advanced → Boot Order → Internal CD/DVD ROM Drive 与 Notebook Hard Drive 置顶（UEFI 顺序分开调）" },
                new() { CheckId = "boot-menu", Path = "Advanced → Boot Options → 取消 One-Time Boot Menu（F9）" },
                new() { CheckId = "secure-boot", Path = "Advanced → Secure Boot Configuration → Secure Boot → Enable" }
            },
            Notes = "Legacy/UEFI 双启动顺序独立维护，两列都要核验；BIOS 密码遗忘需主板跳线清除（保留处置流程）"
        },
        new()
        {
            Key = "asus", DisplayName = "华硕（ASUS 商用台式/主板）", BiosHotKey = "F2 或 Del", BootMenuHotKey = "F8",
            MatchPatterns = new[] { "asus", "华硕" },
            SettingPaths = new List<BiosSettingPath>
            {
                new() { CheckId = "bios-password", Path = "Advanced Mode（F7）→ Security → Administrator Password" },
                new() { CheckId = "usb-boot", Path = "Advanced Mode → Boot → Boot Configuration → Fast Boot 关闭项下 USB Boot 控制", Note = "EZ Mode 无此项，需进 Advanced Mode" },
                new() { CheckId = "pxe-boot", Path = "Advanced Mode → Boot → Network Stack Configuration → 关闭 Network Stack/PXE" },
                new() { CheckId = "boot-order", Path = "Advanced Mode → Boot → Boot Option Priorities → Boot Option #1 为内置盘" },
                new() { CheckId = "boot-menu", Path = "Advanced Mode → Boot → Boot Configuration → Boot Menu（F8）按机型支持情况", Note = "零售主板无统一开关，以 Boot Option Priorities 排除为主" },
                new() { CheckId = "secure-boot", Path = "Advanced Mode → Boot → Secure Boot → OS Type=Windows UEFI（Enabled）" }
            },
            Notes = "零售主板 BIOS 差异大（不同 chipset 菜单不同）；F8 启动菜单关闭项部分机型缺失，靠 Boot Order 排除兜底"
        },
        new()
        {
            Key = "generic", DisplayName = "通用机型（未识别品牌）", BiosHotKey = "F2/F10/Del（依机型）", BootMenuHotKey = "F12/F9/F8（依机型）",
            MatchPatterns = Array.Empty<string>(),
            SettingPaths = new List<BiosSettingPath>
            {
                new() { CheckId = "bios-password", Path = "Security/Administrator 菜单（通用路径）" },
                new() { CheckId = "usb-boot", Path = "Boot/Startup 菜单中 USB Storage/USB Boot 项" },
                new() { CheckId = "pxe-boot", Path = "Boot/Network 菜单中 PXE/Network Boot 项" },
                new() { CheckId = "boot-order", Path = "Boot/Startup → Boot Order/Boot Sequence" },
                new() { CheckId = "boot-menu", Path = "Boot 菜单中 One-Time/Boot Menu 项" },
                new() { CheckId = "secure-boot", Path = "Security/Boot 菜单中 Secure Boot 项" }
            },
            Notes = "未匹配品牌时使用：按机型手册定位同名设置；核验完成后请在备注中登记机型与实际路径，反哺本矩阵"
        }
    };

    /// <summary>
    /// 按固件厂商/整机厂商匹配品牌档案（先专后通：具体品牌优先，未匹配回落 generic）。
    /// </summary>
    /// <param name="biosVendor">Win32_BIOS.Manufacturer。</param>
    /// <param name="systemVendor">Win32_ComputerSystem.Manufacturer（部分厂商 BIOS 由 AMI/Insyde 代工，需整机厂商兜底）。</param>
    public static BiosVendorProfile Match(string biosVendor, string systemVendor)
    {
        var specific = Profiles.FirstOrDefault(p =>
            p.MatchPatterns.Count > 0 &&
            (Contains(biosVendor, p) || Contains(systemVendor, p)));
        return specific ?? Profiles.First(p => p.Key == "generic");

        static bool Contains(string vendor, BiosVendorProfile p) =>
            !string.IsNullOrWhiteSpace(vendor) &&
            p.MatchPatterns.Any(m => vendor.Contains(m, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// 取档案中某检查项的设置路径；未知 CheckId 返回 null。
    /// </summary>
    public static BiosSettingPath? FindPath(BiosVendorProfile profile, string checkId) =>
        profile.SettingPaths.FirstOrDefault(s => string.Equals(s.CheckId, checkId, StringComparison.OrdinalIgnoreCase));
}
