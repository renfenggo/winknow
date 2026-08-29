using Winknow.DeviceSecurity;

namespace Winknow.DeviceSecurity.Tests;

/// <summary>
/// USB 设备分类器测试（第 12 周验收：
/// U 盘/移动硬盘禁用、键盘鼠标正常、设备矩阵规则）。
/// </summary>
public sealed class UsbDeviceClassifierTests
{
    [Theory]
    [InlineData(0x08)] // U 盘 / 移动硬盘 / 读卡器
    public void MassStorage_ShouldBeBlocked(byte classCode)
    {
        // 验收：U 盘和移动硬盘不能在 Windows 中作为普通存储使用
        Assert.Equal(UsbDeviceClassifier.UsbDeviceKind.MassStorage,
            UsbDeviceClassifier.Classify(classCode));
        Assert.True(UsbDeviceClassifier.ShouldBeBlocked(UsbDeviceClassifier.Classify(classCode)));
        Assert.True(UsbDeviceClassifier.IsMassStorage(classCode));
    }

    [Theory]
    [InlineData(0x03)] // HID：键盘 / 鼠标 / 数位板
    [InlineData(0x0E)] // 摄像头
    [InlineData(0x01)] // 音频（USB 耳机/声卡）
    [InlineData(0x07)] // 打印机
    [InlineData(0x02)] // CDC（USB 网卡等）
    [InlineData(0x09)] // Hub（扩展坞拓扑）
    [InlineData(0xFF)] // 厂商自定义（部分编程器/开发板）
    [InlineData(0x00)] // 未识别
    public void TeachingPeripherals_NeverBlocked(byte classCode)
    {
        // 验收：键盘和鼠标正常——教学外设不受 USB 存储管控影响
        var kind = UsbDeviceClassifier.Classify(classCode);
        Assert.False(UsbDeviceClassifier.ShouldBeBlocked(kind));
        Assert.False(UsbDeviceClassifier.IsMassStorage(classCode));
    }

    [Fact]
    public void KeyboardAndMouse_AreHid()
    {
        Assert.Equal(UsbDeviceClassifier.UsbDeviceKind.HumanInterface, UsbDeviceClassifier.Classify(0x03));
    }

    [Fact]
    public void KindText_CoversAllKinds()
    {
        foreach (var kind in Enum.GetValues<UsbDeviceClassifier.UsbDeviceKind>())
        {
            var text = UsbDeviceClassifier.KindText(kind);
            Assert.False(string.IsNullOrEmpty(text));
        }
        // 键鼠类别文案明确含"键盘"，避免矩阵表歧义
        Assert.Contains("键盘", UsbDeviceClassifier.KindText(UsbDeviceClassifier.UsbDeviceKind.HumanInterface));
    }

    [Fact]
    public void MatrixRow_StorageBlocked_OthersUsable()
    {
        var (storageKind, storageBehavior) = UsbDeviceClassifier.MatrixRow(0x08);
        Assert.Contains("大容量存储", storageKind);
        Assert.Contains("不可作为普通存储", storageBehavior);

        var (hidKind, hidBehavior) = UsbDeviceClassifier.MatrixRow(0x03);
        Assert.Contains("HID", hidKind);
        Assert.Contains("正常使用", hidBehavior);
    }
}

/// <summary>
/// 品牌 BIOS 兼容矩阵测试（第 12 周验收：至少 3 类设备覆盖 + 差异说明）。
/// </summary>
public sealed class BiosCompatibilityMatrixTests
{
    [Theory]
    [InlineData("LENOVO", "Lenovo", "lenovo")]
    [InlineData("American Megatrends Inc.", "Dell Inc.", "dell")]       // BIOS 代工（AMI）→ 整机厂商兜底
    [InlineData("InsydeH2O", "HP", "hp")]
    [InlineData("American Megatrends Inc.", "ASUSTeK COMPUTER INC.", "asus")]
    [InlineData("Unknown BIOS Co.", "某组装机", "generic")]              // 未匹配 → generic
    [InlineData("", "", "generic")]
    public void Match_ByBiosOrSystemVendor(string biosVendor, string systemVendor, string expectedKey)
    {
        var profile = BiosCompatibilityMatrix.Match(biosVendor, systemVendor);
        Assert.Equal(expectedKey, profile.Key);
    }

    [Fact]
    public void Profiles_AtLeastThreeBrandsPlusGeneric()
    {
        // 验收：至少 3 类设备——4 品牌 + generic 兜底
        var keys = BiosCompatibilityMatrix.Profiles.Select(p => p.Key).ToList();
        Assert.Contains("generic", keys);
        Assert.True(BiosCompatibilityMatrix.Profiles.Count(p => p.Key != "generic") >= 3);
    }

    [Fact]
    public void EveryProfile_CoversAllManualChecksAndSecureBoot()
    {
        var requiredIds = new[]
        {
            "bios-password", "usb-boot", "pxe-boot", "boot-order", "boot-menu", "secure-boot"
        };
        foreach (var profile in BiosCompatibilityMatrix.Profiles)
        {
            foreach (var id in requiredIds)
            {
                var path = BiosCompatibilityMatrix.FindPath(profile, id);
                Assert.NotNull(path);
                Assert.False(string.IsNullOrWhiteSpace(path!.Path));
            }
            Assert.False(string.IsNullOrEmpty(profile.DisplayName));
            Assert.False(string.IsNullOrEmpty(profile.BiosHotKey));
            Assert.False(string.IsNullOrEmpty(profile.Notes)); // 差异说明必填
        }
    }

    [Fact]
    public void FindPath_UnknownCheckId_ReturnsNull()
    {
        var profile = BiosCompatibilityMatrix.Match("LENOVO", "Lenovo");
        Assert.Null(BiosCompatibilityMatrix.FindPath(profile!, "ghost-check"));
    }

    [Fact]
    public void Report_Integration_VendorGuidanceInMarkdown()
    {
        var report = new DeviceSecurityReport
        {
            Firmware = new FirmwareInfo { BiosVendor = "LENOVO", SystemVendor = "Lenovo" },
            Checks = new List<CheckItem>
            {
                new() { Id = "usb-boot", Title = "USB 外部启动已禁用", Category = "manual", Weight = 15 }
            }
        };

        var md = ReportExporter.ToMarkdown(report);
        Assert.Contains("品牌 BIOS 设置指引", md);
        Assert.Contains("联想", md);
        Assert.Contains("F1", md);                       // 联想 BIOS 热键
        Assert.Contains("Startup → USB Boot", md);        // 品牌路径进入报告
    }
}
