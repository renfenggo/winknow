using Winknow.TrustedUpdater;

namespace Winknow.Guard.Tests;

/// <summary>
/// 第 10 周可信恢复库与自动修复测试。
/// 目录布局（每个测试独立临时根）：
///   deploy/Current   —— 运行版本
///   deploy/Previous  —— 上一版本（回滚源）
///   deploy/Recovery  —— 可信副本 + manifest.json
/// </summary>
public sealed class RecoveryAndRepairTests : IDisposable
{
    private readonly string _root =
        Path.Combine(Path.GetTempPath(), $"winknow_repair_{Guid.NewGuid():N}");

    public RecoveryAndRepairTests()
    {
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, true); } catch (IOException) { }
    }

    private DeploymentSlots CreateSlots() => new(Path.Combine(_root, "deploy"));

    /// <summary>创建测试部署：Current 含两个文件。</summary>
    private (DeploymentSlots slots, RecoveryVault vault) DeployCurrent(params string[] files)
    {
        var slots = CreateSlots();
        foreach (var f in files)
        {
            var path = Path.Combine(slots.CurrentDir, f);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, $"content-of-{f}");
        }
        var vault = new RecoveryVault(Path.Combine(_root, "deploy"));
        return (slots, vault);
    }

    // ───────────────────────── RecoveryVault ─────────────────────────

    [Fact]
    public void Vault_Snapshot_CreatesManifestWithHashes()
    {
        var (slots, vault) = DeployCurrent("Winknow.ControlService.exe", "policy.json");
        var snap = vault.SnapshotFrom(slots.CurrentDir, "7.0.0");

        Assert.True(snap.IsSuccess, snap.ErrorMessage);
        Assert.True(File.Exists(vault.ManifestPath));

        var manifest = vault.GetManifest();
        Assert.NotNull(manifest);
        Assert.Equal("7.0.0", manifest!.Version);
        Assert.Equal(2, manifest.Files.Count);
        Assert.All(manifest.Files, f => Assert.Equal(64, f.Sha256.Length));
        Assert.True(vault.IsReady());
    }

    [Fact]
    public void Vault_Snapshot_MissingSource_Fails()
    {
        var vault = new RecoveryVault(Path.Combine(_root, "deploy"));
        var result = vault.SnapshotFrom(Path.Combine(_root, "no_such_dir"), "1.0");
        Assert.False(result.IsSuccess);
    }

    [Fact]
    public void Vault_Verify_DetectsTamperedFile()
    {
        var (slots, vault) = DeployCurrent("a.dll", "b.dll");
        vault.SnapshotFrom(slots.CurrentDir, "7.0.0");

        // 篡改一个文件
        File.WriteAllText(Path.Combine(slots.CurrentDir, "a.dll"), "tampered!");

        var report = vault.VerifyAgainstManifest(slots.CurrentDir);
        Assert.False(report.IsHealthy);
        Assert.Single(report.Corrupted);
        Assert.Equal("a.dll", report.Corrupted[0].Path);
    }

    [Fact]
    public void Vault_Verify_DetectsMissingFile()
    {
        var (slots, vault) = DeployCurrent("a.dll", "b.dll");
        vault.SnapshotFrom(slots.CurrentDir, "7.0.0");

        File.Delete(Path.Combine(slots.CurrentDir, "b.dll"));

        var report = vault.VerifyAgainstManifest(slots.CurrentDir);
        Assert.False(report.IsHealthy);
        Assert.Single(report.Missing);
        Assert.Equal("b.dll", report.Missing[0]);
    }

    [Fact]
    public void Vault_RestoreFile_RepairsCorruption()
    {
        var (slots, vault) = DeployCurrent("a.dll");
        vault.SnapshotFrom(slots.CurrentDir, "7.0.0");
        var original = File.ReadAllText(Path.Combine(slots.CurrentDir, "a.dll"));

        File.WriteAllText(Path.Combine(slots.CurrentDir, "a.dll"), "corrupted");
        var restore = vault.RestoreFile("a.dll", slots.CurrentDir);

        Assert.True(restore.IsSuccess, restore.ErrorMessage);
        Assert.Equal(original, File.ReadAllText(Path.Combine(slots.CurrentDir, "a.dll")));
        Assert.True(vault.VerifyAgainstManifest(slots.CurrentDir).IsHealthy);
    }

    [Fact]
    public void Vault_RestoreFile_FailsWhenNotInVault()
    {
        var vault = new RecoveryVault(Path.Combine(_root, "deploy"));
        var result = vault.RestoreFile("ghost.dll", _root);
        Assert.False(result.IsSuccess);
    }

    [Fact]
    public void Vault_IsReady_FalseWithoutSnapshot()
    {
        var vault = new RecoveryVault(Path.Combine(_root, "deploy"));
        Assert.False(vault.IsReady());
        Assert.Null(vault.GetManifest());
    }

    // ───────────────────────── AutoRepairService ─────────────────────────

    [Fact]
    public void Repair_HealthyCurrent_NoAction()
    {
        var (slots, vault) = DeployCurrent("a.dll");
        vault.SnapshotFrom(slots.CurrentDir, "7.0.0");

        var repair = new AutoRepairService(slots, vault);
        var result = repair.CheckAndRepair();

        Assert.True(result.Success);
        Assert.Equal(AutoRepairService.RepairStrategy.None, result.Strategy);
    }

    [Fact]
    public void Repair_CorruptedFile_RestoredFromVault()
    {
        var (slots, vault) = DeployCurrent("Winknow.ControlService.exe", "policy.json");
        vault.SnapshotFrom(slots.CurrentDir, "7.0.0");
        var good = File.ReadAllText(Path.Combine(slots.CurrentDir, "policy.json"));

        // 篡改 + 缺失双损伤
        File.WriteAllText(Path.Combine(slots.CurrentDir, "policy.json"), "被篡改的策略");
        File.Delete(Path.Combine(slots.CurrentDir, "Winknow.ControlService.exe"));

        var result = new AutoRepairService(slots, vault).CheckAndRepair();

        Assert.True(result.Success, result.Detail);
        Assert.Equal(AutoRepairService.RepairStrategy.VaultFileRestore, result.Strategy);
        Assert.Equal(2, result.RepairedFiles);
        Assert.Equal(good, File.ReadAllText(Path.Combine(slots.CurrentDir, "policy.json")));
        Assert.True(vault.VerifyAgainstManifest(slots.CurrentDir).IsHealthy);
    }

    [Fact]
    public void Repair_NoVault_RollbacksToPrevious()
    {
        var slots = CreateSlots();

        // Previous 有完好版本，Current 为空且无 Recovery 清单
        File.WriteAllText(Path.Combine(slots.PreviousDir, "Winknow.ControlService.exe"), "old-good");
        var vault = new RecoveryVault(Path.Combine(_root, "deploy"));

        var result = new AutoRepairService(slots, vault).CheckAndRepair();

        Assert.True(result.Success, result.Detail);
        Assert.Equal(AutoRepairService.RepairStrategy.PreviousRollback, result.Strategy);
        Assert.True(File.Exists(Path.Combine(slots.CurrentDir, "Winknow.ControlService.exe")));
    }

    [Fact]
    public void Repair_AllSourcesMissing_FailsWithoutDeescalation()
    {
        // 验收"恢复失败时不自动全部放行"的前半段：
        // Vault 与 Previous 均不可用 → 修复必须失败（调用方据此保持降级）
        var slots = CreateSlots();
        var vault = new RecoveryVault(Path.Combine(_root, "deploy"));

        var result = new AutoRepairService(slots, vault).CheckAndRepair();

        Assert.False(result.Success);
        Assert.NotNull(result.Detail);
        Assert.Contains("不放行", result.Detail);
    }

    [Fact]
    public void Repair_RefreshSnapshot_UpdatesManifestVersion()
    {
        var (slots, vault) = DeployCurrent("a.dll");
        var repair = new AutoRepairService(slots, vault);

        var refresh = repair.RefreshSnapshot("7.1.0");
        Assert.True(refresh.IsSuccess, refresh.ErrorMessage);
        Assert.Equal("7.1.0", vault.GetManifest()!.Version);
    }
}
