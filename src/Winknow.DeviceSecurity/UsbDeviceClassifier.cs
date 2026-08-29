namespace Winknow.DeviceSecurity;

/// <summary>
/// USB 设备分类器（V7.0 第 12 周"USB 设备矩阵"代码化）。
///
/// 依据 USB 类码（bInterfaceClass，USB-IF 分配）将设备归类，
/// 并映射 V7.0 管控策略：
/// - Mass Storage（0x08：U 盘、移动硬盘、部分读卡器）→ 受 <see cref="UsbStorageController"/> 管控（禁用后不可作普通存储）；
/// - HID（0x03：键盘、鼠标、数位板）→ **恒放行**（教学必需，验收"键盘和鼠标正常"）；
/// - 摄像头/音频/打印机/网络等 → 放行（教学外设，非存储威胁面）；
/// - Hub（0x09）→ 放行（仅扩展拓扑，无数据面）；
/// - 未知/厂商自定义（0xFF）→ 放行但可审计（默认非存储——存储判定必须明确，防误伤教学设备）。
///
/// 与 <see cref="UsbStorageController"/> 的关系：该控制器写 USBSTOR 驱动 Start=4，
/// 仅影响大容量存储类驱动栈；HID/摄像头走独立驱动类，不受影响——
/// 本分类器的 <see cref="ShouldBeBlocked"/> 与之形成同一策略的两面（意图与手段）。
/// </summary>
public static class UsbDeviceClassifier
{
    /// <summary>USB 设备类别（按 USB-IF 类码归纳）。</summary>
    public enum UsbDeviceKind
    {
        /// <summary>大容量存储（U 盘/移动硬盘/读卡器）：0x08。</summary>
        MassStorage,

        /// <summary>HID 人机接口（键盘/鼠标/数位板）：0x03。</summary>
        HumanInterface,

        /// <summary>摄像头/视频：0x0E。</summary>
        Camera,

        /// <summary>音频：0x01。</summary>
        Audio,

        /// <summary>打印机：0x07。</summary>
        Printer,

        /// <summary>通信/网络（CDC/网卡）：0x02。</summary>
        Network,

        /// <summary>集线器：0x09。</summary>
        Hub,

        /// <summary>厂商自定义：0xFF。</summary>
        VendorSpecific,

        /// <summary>未识别。</summary>
        Unknown
    }

    /// <summary>
    /// 按 USB 类码归类设备。
    /// </summary>
    /// <param name="usbClassCode">bInterfaceClass（如 Win32_USBHub pnp 类或描述符类码）。</param>
    public static UsbDeviceKind Classify(byte usbClassCode) => usbClassCode switch
    {
        0x08 => UsbDeviceKind.MassStorage,
        0x03 => UsbDeviceKind.HumanInterface,
        0x0E => UsbDeviceKind.Camera,
        0x01 => UsbDeviceKind.Audio,
        0x07 => UsbDeviceKind.Printer,
        0x02 => UsbDeviceKind.Network,
        0x09 => UsbDeviceKind.Hub,
        0xFF => UsbDeviceKind.VendorSpecific,
        _ => UsbDeviceKind.Unknown
    };

    /// <summary>
    /// V7.0 管控策略：仅大容量存储受禁；其余（含未知）放行。
    /// 未知设备放行的理由：存储类判定必须明确匹配（0x08/USBSTOR），
    /// 逐类禁用教学外设（键鼠/摄像头）反而破坏课堂可用性——
    /// 潜在风险由进程管控与审计兜底（威胁模型 A2 及以下）。
    /// </summary>
    public static bool ShouldBeBlocked(UsbDeviceKind kind) => kind == UsbDeviceKind.MassStorage;

    /// <summary>
    /// 判定设备是否为 USB 大容量存储（U 盘与移动硬盘同为 0x08 类——
    /// 验收"U 盘和移动硬盘不能在 Windows 中作为普通存储使用"的统一判定入口）。
    /// </summary>
    public static bool IsMassStorage(byte usbClassCode) => Classify(usbClassCode) == UsbDeviceKind.MassStorage;

    /// <summary>类别中文名（矩阵文档与审计展示）。</summary>
    public static string KindText(UsbDeviceKind kind) => kind switch
    {
        UsbDeviceKind.MassStorage => "大容量存储（U 盘/移动硬盘）",
        UsbDeviceKind.HumanInterface => "HID（键盘/鼠标）",
        UsbDeviceKind.Camera => "摄像头",
        UsbDeviceKind.Audio => "音频设备",
        UsbDeviceKind.Printer => "打印机",
        UsbDeviceKind.Network => "通信/网络设备",
        UsbDeviceKind.Hub => "集线器",
        UsbDeviceKind.VendorSpecific => "厂商自定义设备",
        _ => "未识别设备"
    };

    /// <summary>
    /// 设备矩阵预期行为描述（教学用表格同源数据）。
    /// </summary>
    public static (string Kind, string ExpectedBehavior) MatrixRow(byte usbClassCode)
    {
        var kind = Classify(usbClassCode);
        var expected = ShouldBeBlocked(kind)
            ? "禁用后不可作为普通存储使用（USBSTOR 驱动禁用）"
            : "正常使用（不受 USB 存储管控影响）";
        return (KindText(kind), expected);
    }
}
