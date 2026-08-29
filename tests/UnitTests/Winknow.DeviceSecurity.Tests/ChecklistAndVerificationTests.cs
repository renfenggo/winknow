using Winknow.DeviceSecurity;

namespace Winknow.DeviceSecurity.Tests;

/// <summary>
/// 人工核验表 + 核验记录 + 变化失效机制测试。
/// </summary>
public sealed class ChecklistAndVerificationTests : IDisposable
{
    private readonly string _tempDir =
        Path.Combine(Path.GetTempPath(), $"winknow_w11_{Guid.NewGuid():N}");

    public ChecklistAndVerificationTests() => Directory.CreateDirectory(_tempDir);

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch (IOException) { }
    }

    // ───────────────────────── ManualChecklist ─────────────────────────

    [Fact]
    public void Checklist_DefaultsToPending_NeverPass()
    {
        // 验收：无法自动检测的项目显示"需人工核验"，不显示为通过
        var checklist = new ManualChecklist(_tempDir);
        var results = checklist.CurrentResults;

        Assert.Equal(5, results.Count);
        Assert.All(results, r => Assert.Equal(CheckStatus.Pending, r.Status));
        Assert.False(checklist.AllVerified);
    }

    [Fact]
    public void Checklist_SetResult_PersistsAcrossInstances()
    {
        var checklist = new ManualChecklist(_tempDir);
        checklist.SetResult("usb-boot", CheckStatus.Pass, "zhangsan", "BIOS 中已确认 Disabled");

        // 新实例从磁盘加载
        var reloaded = new ManualChecklist(_tempDir);
        var usb = reloaded.CurrentResults.Single(r => r.CheckId == "usb-boot");
        Assert.Equal(CheckStatus.Pass, usb.Status);
        Assert.Equal("zhangsan", usb.VerifiedBy);
        Assert.Contains("Disabled", usb.Note);
    }

    [Fact]
    public void Checklist_RejectsPendingAndUnknownIds()
    {
        var checklist = new ManualChecklist(_tempDir);

        Assert.Throws<ArgumentException>(() =>
            checklist.SetResult("usb-boot", CheckStatus.Pending, "admin"));
        Assert.Throws<ArgumentException>(() =>
            checklist.SetResult("ghost-item", CheckStatus.Pass, "admin"));
        Assert.Throws<ArgumentException>(() =>
            checklist.SetResult("usb-boot", CheckStatus.Pass, "")); // 管理员必填
    }

    [Fact]
    public void Checklist_Reset_ReturnsAllToPending()
    {
        var checklist = new ManualChecklist(_tempDir);
        checklist.SetResult("bios-password", CheckStatus.Fail, "admin");
        checklist.Reset();

        Assert.All(checklist.CurrentResults, r => Assert.Equal(CheckStatus.Pending, r.Status));
        // 持久化同样复位
        Assert.All(new ManualChecklist(_tempDir).CurrentResults,
            r => Assert.Equal(CheckStatus.Pending, r.Status));
    }

    // ───────────────────────── 固件指纹 ─────────────────────────

    [Fact]
    public void Fingerprint_StableForSameFirmware()
    {
        var fw = new FirmwareInfo
        {
            BiosVersion = "1.2.3", BiosReleaseDate = "20250101000000.000000+000", BoardSerial = "MB-001"
        };
        Assert.Equal(
            FirmwareInfoCollector.ComputeFingerprint(fw),
            FirmwareInfoCollector.ComputeFingerprint(new FirmwareInfo
            {
                BiosVersion = "1.2.3", BiosReleaseDate = "20250101000000.000000+000", BoardSerial = "MB-001"
            }));
    }

    [Theory]
    [InlineData("9.9.9", "20250101000000.000000+000", "MB-001")]   // BIOS 升级
    [InlineData("1.2.3", "20260601000000.000000+000", "MB-001")]   // 日期变化
    [InlineData("1.2.3", "20250101000000.000000+000", "MB-OTHER")] // 主板更换
    public void Fingerprint_Changes_WhenFirmwareChanges(
        string version, string date, string serial)
    {
        var original = FirmwareInfoCollector.ComputeFingerprint(new FirmwareInfo
        {
            BiosVersion = "1.2.3", BiosReleaseDate = "20250101000000.000000+000", BoardSerial = "MB-001"
        });
        var changed = FirmwareInfoCollector.ComputeFingerprint(new FirmwareInfo
        {
            BiosVersion = version, BiosReleaseDate = date, BoardSerial = serial
        });

        Assert.NotEqual(original, changed);
    }

    [Fact]
    public void Fingerprint_Format_32HexChars()
    {
        var fp = FirmwareInfoCollector.ComputeFingerprint(new FirmwareInfo());
        Assert.Equal(32, fp.Length);
        Assert.Matches("^[0-9a-f]+$", fp);
    }

    // ───────────────────────── VerificationStore ─────────────────────────

    [Fact]
    public void Verification_SaveLoad_RoundTrip()
    {
        var store = new VerificationStore(_tempDir);
        var save = store.Save(new VerificationRecord
        {
            DeviceId = "DEV-1",
            FirmwareFingerprint = "aa11223344556677889900aabbccddeeff",
            FirmwareVersion = "1.2.3",
            AdminName = "zhangsan",
            VerifiedAt = "2026-08-29T10:00:00Z",
            Notes = "机房 301 全部核验"
        });

        Assert.True(save.IsSuccess, save.ErrorMessage);
        var loaded = store.Load();
        Assert.NotNull(loaded);
        Assert.Equal("DEV-1", loaded!.DeviceId);
        Assert.Equal("zhangsan", loaded.AdminName);
        Assert.Equal("1.2.3", loaded.FirmwareVersion);
    }

    [Fact]
    public void Verification_IsCurrent_NoRecord_ReturnsNull()
    {
        var store = new VerificationStore(Path.Combine(_tempDir, "empty"));
        Assert.Null(store.IsCurrent("any"));
    }

    [Fact]
    public void Verification_MatchingFingerprint_Current()
    {
        var store = new VerificationStore(_tempDir);
        var fp = FirmwareInfoCollector.ComputeFingerprint(new FirmwareInfo
        {
            BiosVersion = "1.0", BiosReleaseDate = "d", BoardSerial = "S1"
        });
        store.Save(new VerificationRecord { FirmwareFingerprint = fp, AdminName = "a" });

        Assert.True(store.IsCurrent(fp));
    }

    [Fact]
    public void Verification_BiosUpdate_InvalidatesRecord_AndResetsChecklist()
    {
        // 验收：BIOS 更新后旧核验记录自动失效
        var store = new VerificationStore(_tempDir);
        var checklist = new ManualChecklist(_tempDir);
        checklist.SetResult("bios-password", CheckStatus.Pass, "admin");
        checklist.SetResult("usb-boot", CheckStatus.Pass, "admin");

        var oldFp = FirmwareInfoCollector.ComputeFingerprint(new FirmwareInfo
        {
            BiosVersion = "1.0", BiosReleaseDate = "d", BoardSerial = "S1"
        });
        store.Save(new VerificationRecord { FirmwareFingerprint = oldFp, AdminName = "admin" });

        // BIOS 更新：版本 1.0 → 2.0
        var newFp = FirmwareInfoCollector.ComputeFingerprint(new FirmwareInfo
        {
            BiosVersion = "2.0", BiosReleaseDate = "d", BoardSerial = "S1"
        });

        var (isValid, detail) = store.ValidateAndExpire(newFp, checklist);

        Assert.False(isValid);
        Assert.Contains("失效", detail);
        Assert.Null(store.Load());                                    // 记录已清除
        Assert.All(checklist.CurrentResults,                          // 核验表已重置
            r => Assert.Equal(CheckStatus.Pending, r.Status));
        Assert.False(checklist.AllVerified);
    }

    [Fact]
    public void Verification_MatchingFingerprint_KeepsChecklist()
    {
        var store = new VerificationStore(_tempDir);
        var checklist = new ManualChecklist(_tempDir);
        checklist.SetResult("bios-password", CheckStatus.Pass, "admin");

        var fp = FirmwareInfoCollector.ComputeFingerprint(new FirmwareInfo
        {
            BiosVersion = "1.0", BiosReleaseDate = "d", BoardSerial = "S1"
        });
        store.Save(new VerificationRecord { FirmwareFingerprint = fp, AdminName = "admin" });

        var (isValid, _) = store.ValidateAndExpire(fp, checklist);
        Assert.True(isValid);
        Assert.Equal(CheckStatus.Pass,
            checklist.CurrentResults.Single(r => r.CheckId == "bios-password").Status);
    }
}
