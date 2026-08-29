using System.IO;
using System.Security.Cryptography;
using Winknow.Core.Results;
using Winknow.TrustedUpdater;

namespace Winknow.TrustedUpdater.Tests;

/// <summary>
/// 第 7 周"更新编排器 + 自动回滚"端到端测试。
/// 覆盖验收项：
/// - "TrustedUpdater 验证签名、产品标识、目标版本和文件 Hash"
/// - "更新过程不会触发双进程互相拉起"（Stop 在切换前，Start 在切换后）
/// - "更新中断后自动回滚"（健康检查失败 → Previous→Current）
/// - "更新包签名验证失败时拒绝安装"
/// </summary>
public class UpdateOrchestratorTests : IDisposable
{
    private readonly string _root = TestUpdatablePackage.NewDeployRoot();
    private readonly List<string> _events = new();

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, true);
    }

    [Fact]
    public void Apply_ValidPackage_StopBeforeStartAfter_RunsNewVersion()
    {
        var (priv, pub) = TestUpdatablePackage.NewRsaKeyPair();
        var (fc, fh) = TestUpdatablePackage.NewFile("v7.0.1-bin");
        var manifest = TestUpdatablePackage.BuildSignedManifest(priv, version: "7.0.1",
            files: new List<FileEntry> { new() { RelativePath = "bin.txt", Sha256 = fh } });
        var package = TestUpdatablePackage.WritePackage(
            Path.Combine(_root, "..", $"v7.0.1.wku"), manifest,
            new[] { ("bin.txt", fc) });

        var orchestrator = new UpdateOrchestrator(NewOptions(pub, stop: () => _events.Add("stop"), start: () => _events.Add("start"),
            checkService: () => Result.Success()));

        var r = orchestrator.Apply(package);
        Assert.True(r.IsSuccess);
        // 防双进程：必须先 stop 再 start
        Assert.Equal(new[] { "stop", "start" }, _events.ToArray());
        Assert.Equal("7.0.1", new DeploymentSlots(_root).GetCurrentVersion());
    }

    [Fact]
    public void Apply_WrongPublicKey_RejectsAndRestartsOldService()
    {
        var (priv, _) = TestUpdatablePackage.NewRsaKeyPair();
        var (_, otherPub) = TestUpdatablePackage.NewRsaKeyPair();
        var (fc, fh) = TestUpdatablePackage.NewFile();
        var manifest = TestUpdatablePackage.BuildSignedManifest(priv, version: "7.0.1",
            files: new List<FileEntry> { new() { RelativePath = "bin.txt", Sha256 = fh } });
        var package = TestUpdatablePackage.WritePackage(
            Path.Combine(_root, "..", $"bad.wku"), manifest,
            new[] { ("bin.txt", fc) });

        var orchestrator = new UpdateOrchestrator(NewOptions(otherPub,
            stop: () => _events.Add("stop"), start: () => _events.Add("start")));

        var r = orchestrator.Apply(package);
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.SignatureInvalid, r.ErrorCode);
        // 失败时仍要重启旧服务（避免系统瘫痪）
        Assert.Contains("start", _events);
        // Current 仍是空（之前未安装）
        Assert.Null(new DeploymentSlots(_root).GetCurrentVersion());
    }

    [Fact]
    public void Apply_ProductMismatch_Rejects()
    {
        var (priv, pub) = TestUpdatablePackage.NewRsaKeyPair();
        var (fc, fh) = TestUpdatablePackage.NewFile();
        var manifest = TestUpdatablePackage.BuildSignedManifest(priv, version: "7.0.1",
            productId: "Other.Product",
            files: new List<FileEntry> { new() { RelativePath = "bin.txt", Sha256 = fh } });
        var package = TestUpdatablePackage.WritePackage(
            Path.Combine(_root, "..", $"other.wku"), manifest,
            new[] { ("bin.txt", fc) });

        var orchestrator = new UpdateOrchestrator(NewOptions(pub));

        var r = orchestrator.Apply(package);
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.InvalidArgument, r.ErrorCode);
    }

    [Fact]
    public void Apply_HashMismatch_RejectsWithHashMismatch()
    {
        var (priv, pub) = TestUpdatablePackage.NewRsaKeyPair();
        var manifest = TestUpdatablePackage.BuildSignedManifest(priv, version: "7.0.1",
            files: new List<FileEntry> { new() { RelativePath = "bin.txt", Sha256 = "00" } });
        var package = TestUpdatablePackage.WritePackage(
            Path.Combine(_root, "..", $"hash.wku"), manifest,
            new[] { ("bin.txt", "real-content-not-matching-hash") });

        var orchestrator = new UpdateOrchestrator(NewOptions(pub));

        var r = orchestrator.Apply(package);
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.HashMismatch, r.ErrorCode);
    }

    [Fact]
    public void Apply_Downgrade_RejectsWithVersionBlocked()
    {
        var (priv, pub) = TestUpdatablePackage.NewRsaKeyPair();

        // 先装 v7.0.1
        var (fc1, fh1) = TestUpdatablePackage.NewFile("v1");
        var m1 = TestUpdatablePackage.BuildSignedManifest(priv, version: "7.0.1",
            files: new List<FileEntry> { new() { RelativePath = "bin.txt", Sha256 = fh1 } });
        var p1 = TestUpdatablePackage.WritePackage(
            Path.Combine(_root, "..", $"v1.wku"), m1, new[] { ("bin.txt", fc1) });
        var orchestrator = new UpdateOrchestrator(NewOptions(pub,
            checkService: () => Result.Success()));
        Assert.True(orchestrator.Apply(p1).IsSuccess);

        // 试图降级到 v7.0.0
        var (fc0, fh0) = TestUpdatablePackage.NewFile("v0");
        var m0 = TestUpdatablePackage.BuildSignedManifest(priv, version: "7.0.0",
            files: new List<FileEntry> { new() { RelativePath = "bin.txt", Sha256 = fh0 } });
        var p0 = TestUpdatablePackage.WritePackage(
            Path.Combine(_root, "..", $"v0.wku"), m0, new[] { ("bin.txt", fc0) });
        var r = orchestrator.Apply(p0);
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.VersionBlocked, r.ErrorCode);
        // 当前版本保持 v7.0.1（未被覆盖）
        Assert.Equal("7.0.1", new DeploymentSlots(_root).GetCurrentVersion());
    }

    [Fact]
    public void Apply_HealthCheckFails_AutoRollbacksToPrevious()
    {
        var (priv, pub) = TestUpdatablePackage.NewRsaKeyPair();

        // v7.0.1 健康，安装成功
        var (fc1, fh1) = TestUpdatablePackage.NewFile("v1");
        var m1 = TestUpdatablePackage.BuildSignedManifest(priv, version: "7.0.1",
            files: new List<FileEntry> { new() { RelativePath = "bin.txt", Sha256 = fh1 } });
        var p1 = TestUpdatablePackage.WritePackage(
            Path.Combine(_root, "..", $"v1.wku"), m1, new[] { ("bin.txt", fc1) });
        var orchestrator1 = new UpdateOrchestrator(NewOptions(pub,
            checkService: () => Result.Success()));
        Assert.True(orchestrator1.Apply(p1).IsSuccess);

        // v7.0.2 健康检查失败 → 自动回滚到 v7.0.1
        var (fc2, fh2) = TestUpdatablePackage.NewFile("v2");
        var m2 = TestUpdatablePackage.BuildSignedManifest(priv, version: "7.0.2",
            files: new List<FileEntry> { new() { RelativePath = "bin.txt", Sha256 = fh2 } });
        var p2 = TestUpdatablePackage.WritePackage(
            Path.Combine(_root, "..", $"v2.wku"), m2, new[] { ("bin.txt", fc2) });
        var orchestrator2 = new UpdateOrchestrator(NewOptions(pub,
            checkService: () => Result.Failure(ErrorCode.ExternalError, "v7.0.2 启动失败")));

        var r = orchestrator2.Apply(p2);
        Assert.False(r.IsSuccess);
        // 验收：自动回滚到 Previous（v7.0.1）
        Assert.Equal("7.0.1", new DeploymentSlots(_root).GetCurrentVersion());
        // 验收：错误信息包含健康检查失败的说明
        Assert.Contains("自动回滚", r.ErrorMessage);
    }

    [Fact]
    public void Apply_HappyPath_HealthCheckPasses_DoesNotRollback()
    {
        var (priv, pub) = TestUpdatablePackage.NewRsaKeyPair();
        var (fc, fh) = TestUpdatablePackage.NewFile();
        var m = TestUpdatablePackage.BuildSignedManifest(priv, version: "7.0.1",
            files: new List<FileEntry> { new() { RelativePath = "bin.txt", Sha256 = fh } });
        var package = TestUpdatablePackage.WritePackage(
            Path.Combine(_root, "..", $"ok.wku"), m, new[] { ("bin.txt", fc) });
        var orchestrator = new UpdateOrchestrator(NewOptions(pub,
            checkService: () => Result.Success(),
            checkAgent: () => Result.Success(),
            checkPolicy: () => Result.Success()));

        var r = orchestrator.Apply(package);
        Assert.True(r.IsSuccess);
        Assert.Equal("7.0.1", new DeploymentSlots(_root).GetCurrentVersion());
    }

    [Fact]
    public void GetStatus_WhenNoCurrent_ReturnsNullVersionAndNoRollback()
    {
        var orchestrator = new UpdateOrchestrator(NewOptions(RSA.Create(2048)));
        var s = orchestrator.GetStatus();
        Assert.Null(s.CurrentVersion);
        Assert.False(s.CanRollback);
    }

    [Fact]
    public void GetStatus_AfterPromote_ReportsVersionAndRollbackAvailability()
    {
        var (priv, pub) = TestUpdatablePackage.NewRsaKeyPair();
        var (fc, fh) = TestUpdatablePackage.NewFile();
        var m = TestUpdatablePackage.BuildSignedManifest(priv, version: "7.0.1",
            files: new List<FileEntry> { new() { RelativePath = "bin.txt", Sha256 = fh } });
        var package = TestUpdatablePackage.WritePackage(
            Path.Combine(_root, "..", $"ok.wku"), m, new[] { ("bin.txt", fc) });

        var orchestrator = new UpdateOrchestrator(NewOptions(pub,
            checkService: () => Result.Success()));
        Assert.True(orchestrator.Apply(package).IsSuccess);
        Assert.Equal("7.0.1", orchestrator.GetStatus().CurrentVersion);
        Assert.False(orchestrator.GetStatus().CanRollback);
    }

    [Fact]
    public void ManualRollback_AfterTwoPromotes_RestoresPreviousVersion()
    {
        var (priv, pub) = TestUpdatablePackage.NewRsaKeyPair();

        // v1
        var (fc1, fh1) = TestUpdatablePackage.NewFile("v1");
        var m1 = TestUpdatablePackage.BuildSignedManifest(priv, version: "7.0.1",
            files: new List<FileEntry> { new() { RelativePath = "bin.txt", Sha256 = fh1 } });
        var p1 = TestUpdatablePackage.WritePackage(
            Path.Combine(_root, "..", $"v1.wku"), m1, new[] { ("bin.txt", fc1) });
        var orch = new UpdateOrchestrator(NewOptions(pub, checkService: () => Result.Success()));
        Assert.True(orch.Apply(p1).IsSuccess);

        // v2
        var (fc2, fh2) = TestUpdatablePackage.NewFile("v2");
        var m2 = TestUpdatablePackage.BuildSignedManifest(priv, version: "7.0.2",
            files: new List<FileEntry> { new() { RelativePath = "bin.txt", Sha256 = fh2 } });
        var p2 = TestUpdatablePackage.WritePackage(
            Path.Combine(_root, "..", $"v2.wku"), m2, new[] { ("bin.txt", fc2) });
        Assert.True(orch.Apply(p2).IsSuccess);

        // 手动回滚
        var rollback = new UpdateOrchestrator(NewOptions(pub,
            stop: () => _events.Add("stop"), start: () => _events.Add("start"))).Rollback();
        Assert.True(rollback.IsSuccess);
        Assert.Equal("7.0.1", new DeploymentSlots(_root).GetCurrentVersion());
    }

    [Fact]
    public void ManualRollback_NoPrevious_Fails()
    {
        var orch = new UpdateOrchestrator(NewOptions(RSA.Create(2048)));
        var r = orch.Rollback();
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.PathNotFound, r.ErrorCode);
    }

    private UpdateOptions NewOptions(
        RSA publicKey,
        Action? stop = null,
        Action? start = null,
        Func<Result>? checkService = null,
        Func<Result>? checkAgent = null,
        Func<Result>? checkPolicy = null) =>
        new()
        {
            DeployRoot = _root,
            ExpectedProductId = TestUpdatablePackage.ProductId,
            PublicKey = publicKey,
            StopServices = stop,
            StartServices = start,
            CheckServiceHealth = checkService,
            CheckAgentHealth = checkAgent,
            CheckPolicyHealth