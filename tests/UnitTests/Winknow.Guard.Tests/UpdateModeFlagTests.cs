using Winknow.TrustedUpdater;

namespace Winknow.Guard.Tests;

/// <summary>
/// 第 10 周更新模式标志测试（防守护与更新交叉拉起）。
/// </summary>
public sealed class UpdateModeFlagTests : IDisposable
{
    private readonly string _tempDir =
        Path.Combine(Path.GetTempPath(), $"winknow_umf_{Guid.NewGuid():N}");

    public UpdateModeFlagTests()
    {
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch (IOException) { }
    }

    [Fact]
    public void Flag_TryEnter_SucceedsWhenIdle()
    {
        Assert.True(UpdateModeFlag.TryEnter(_tempDir));
        Assert.True(UpdateModeFlag.IsUpdateInProgress(_tempDir));
    }

    [Fact]
    public void Flag_TryEnter_RejectsConcurrentUpdate()
    {
        Assert.True(UpdateModeFlag.TryEnter(_tempDir));
        Assert.False(UpdateModeFlag.TryEnter(_tempDir)); // 第二个更新器被拒
    }

    [Fact]
    public void Flag_Exit_AllowsReentry()
    {
        UpdateModeFlag.TryEnter(_tempDir);
        UpdateModeFlag.Exit(_tempDir);

        Assert.False(UpdateModeFlag.IsUpdateInProgress(_tempDir));
        Assert.True(UpdateModeFlag.TryEnter(_tempDir));
    }

    [Fact]
    public void Flag_Exit_IsIdempotent()
    {
        UpdateModeFlag.Exit(_tempDir); // 未进入时退出：无异常
        UpdateModeFlag.Exit(_tempDir);
    }

    [Fact]
    public void Flag_StaleFlag_IgnoredByGuard()
    {
        // 更新器中途崩溃遗留陈旧标志：超过新鲜期后守护恢复干预
        var flagPath = Path.Combine(_tempDir, "update_mode.flag");
        File.WriteAllText(flagPath, DateTimeOffset.UtcNow.AddMinutes(-15).ToString("O"));

        Assert.False(UpdateModeFlag.IsUpdateInProgress(_tempDir));
        Assert.True(UpdateModeFlag.TryEnter(_tempDir)); // 陈旧标志可被覆盖
    }
}
