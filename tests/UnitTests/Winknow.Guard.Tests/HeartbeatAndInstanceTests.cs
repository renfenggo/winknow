using Winknow.Core;
using Winknow.Ipc;
using Winknow.Security;

namespace Winknow.Guard.Tests;

/// <summary>
/// 第 10 周心跳租约与单实例守卫测试。
/// </summary>
public sealed class HeartbeatAndInstanceTests : IDisposable
{
    private readonly string _tempDir =
        Path.Combine(Path.GetTempPath(), $"winknow_w10_{Guid.NewGuid():N}");

    public HeartbeatAndInstanceTests()
    {
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch (IOException) { }
    }

    // ───────────────────────── HeartbeatLease ─────────────────────────

    [Fact]
    public void Lease_WriteThenCheck_IsAlive()
    {
        var now = DateTimeOffset.UtcNow;
        var lease = new HeartbeatLease(_tempDir, clock: () => now);

        var write = lease.Write(1234, ServiceNames.ControlService, "7.0.0");
        Assert.True(write.IsSuccess, write.ErrorMessage);

        var status = lease.Check();
        Assert.True(status.IsAlive);
        Assert.True(status.HasLease);
        Assert.False(status.IsExpired);
        Assert.Equal(1234, status.Lease!.Pid);
        Assert.Equal("7.0.0", status.Lease.Version);
    }

    [Fact]
    public void Lease_Expired_AfterTimeout()
    {
        var now = DateTimeOffset.UtcNow;
        var lease = new HeartbeatLease(
            _tempDir, leaseTimeout: TimeSpan.FromSeconds(15), clock: () => now);

        lease.Write(1234, "svc", "1.0");

        // 时间前进 16 秒：租约过期（真实活性判定由 GuardService 周期执行）
        now = now.AddSeconds(16);
        var status = lease.Check();

        Assert.True(status.IsExpired);
        Assert.False(status.IsAlive);
        Assert.Equal(16, Math.Round(status.AgeSeconds));
    }

    [Fact]
    public void Lease_NoFile_TreatedAsDead()
    {
        var lease = new HeartbeatLease(Path.Combine(_tempDir, "nonexistent"));
        var status = lease.Check();

        Assert.False(status.IsAlive);
        Assert.True(status.IsExpired);
        Assert.Null(status.Lease);
    }

    [Fact]
    public void Lease_CorruptedJson_TreatedAsDead()
    {
        var dir = Path.Combine(_tempDir, "corrupt");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "control_heartbeat.json"), "{ 不是合法 JSON");

        var lease = new HeartbeatLease(dir);
        var status = lease.Check();

        // fail-safe：损坏按死亡处理（宁可误判死亡触发守护，不可误判存活）
        Assert.False(status.IsAlive);
    }

    [Fact]
    public void Lease_Clear_RemovesFile()
    {
        var lease = new HeartbeatLease(_tempDir);
        lease.Write(42, "svc", "1.0");
        Assert.True(File.Exists(lease.LeaseFilePath));

        lease.Clear();
        Assert.False(File.Exists(lease.LeaseFilePath));
        Assert.False(lease.Check().IsAlive);
    }

    [Fact]
    public void Lease_WriteFailure_ReturnsFailure()
    {
        // 用一个非法路径触发写失败
        var lease = new HeartbeatLease(_tempDir);
        var field = typeof(HeartbeatLease).GetField("_leaseFilePath",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        field!.SetValue(lease, "Z:\\invalid\\path\\heartbeat.json");

        var result = lease.Write(1, "svc", "1.0");
        Assert.False(result.IsSuccess);
    }

    // ───────────────────────── SingleInstanceGuard ─────────────────────────

    [Fact]
    public void Instance_FirstGuard_Acquires()
    {
        using var guard1 = new SingleInstanceGuard(
            $@"Global\Winknow_Test_{Guid.NewGuid():N}", _tempDir);
        Assert.True(guard1.IsAcquired);

        // owner 文件已写入本进程身份
        var owner = guard1.ReadOwner();
        Assert.NotNull(owner);
        Assert.Equal(Environment.ProcessId, owner!.Pid);
        Assert.NotEmpty(owner.ExePath);
    }

    [Fact]
    public void Instance_SecondGuardWithSameMutex_Rejected()
    {
        var mutexName = $@"Global\Winknow_Test_{Guid.NewGuid():N}";
        using var guard1 = new SingleInstanceGuard(mutexName, _tempDir);
        Assert.True(guard1.IsAcquired);

        using var guard2 = new SingleInstanceGuard(mutexName, _tempDir);
        Assert.False(guard2.IsAcquired); // 双实例防线：后启动者拿不到锁
    }

    [Fact]
    public void Instance_AfterDispose_MutexReleased()
    {
        var mutexName = $@"Global\Winknow_Test_{Guid.NewGuid():N}";

        using (var guard1 = new SingleInstanceGuard(mutexName, _tempDir))
        {
            Assert.True(guard1.IsAcquired);
        }

        using var guard2 = new SingleInstanceGuard(mutexName, _tempDir);
        Assert.True(guard2.IsAcquired); // 旧实例退出后新实例可获锁（更新切换场景）
    }

    [Fact]
    public void Instance_ReadOwner_NullWhenNoFile()
    {
        var mutexName = $@"Global\Winknow_Test_{Guid.NewGuid():N}";
        using var holder = new SingleInstanceGuard(mutexName, _tempDir); // 占锁并写 owner

        // 后启动者未获锁且其 owner 目录为空 → 读不到身份（Mutex 状态才是仲裁依据）
        using var challenger = new SingleInstanceGuard(mutexName, Path.Combine(_tempDir, "empty"));
        Assert.False(challenger.IsAcquired);
        Assert.Null(challenger.ReadOwner());

        // 锁持有者读自己写入的身份
        Assert.NotNull(holder.ReadOwner());
    }

    [Fact]
    public void Instance_IsOwnerAlive_FalseForDeadPid()
    {
        // PID 上界之外必不存在（GetProcessById 抛 ArgumentException → false）
        Assert.False(SingleInstanceGuard.IsOwnerAlive(new SingleInstanceGuard.OwnerInfo
        {
            Pid = int.MaxValue - 1,
            ExePath = "C:\\x.exe",
            StartedAt = DateTimeOffset.UtcNow.ToString("O")
        }));
        Assert.False(SingleInstanceGuard.IsOwnerAlive(null));
    }
}
