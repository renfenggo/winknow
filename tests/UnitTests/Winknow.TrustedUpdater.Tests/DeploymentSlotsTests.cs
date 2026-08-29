using System.IO;
using Winknow.Core.Results;
using Winknow.TrustedUpdater;

namespace Winknow.TrustedUpdater.Tests;

/// <summary>
/// 第 7 周"A/B 部署槽位"测试。
/// 覆盖验收项：
/// - "A/B 目录 Current、Previous、Staging 切换"
/// - "更新中断后自动回滚"（Previous 始终保留上一可用版本）
/// </summary>
public class DeploymentSlotsTests : IDisposable
{
    private readonly string _root = TestUpdatablePackage.NewDeployRoot();

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, true);
    }

    [Fact]
    public void Constructor_CreatesAllThreeDirectories()
    {
        var slots = new DeploymentSlots(_root);
        Assert.True(Directory.Exists(slots.CurrentDir));
        Assert.True(Directory.Exists(slots.PreviousDir));
        Assert.True(Directory.Exists(slots.StagingDir));
    }

    [Fact]
    public void GetCurrentVersion_WhenEmpty_ReturnsNull()
    {
        var slots = new DeploymentSlots(_root);
        Assert.Null(slots.GetCurrentVersion());
    }

    [Fact]
    public void Promote_EmptyStaging_ReturnsPathNotFound()
    {
        var slots = new DeploymentSlots(_root);
        var r = slots.Promote("7.0.1", "2026-08-29T00:00:00Z");
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.PathNotFound, r.ErrorCode);
    }

    [Fact]
    public void Promote_FilledStaging_Succeeds_AndMovesToCurrent()
    {
        var slots = new DeploymentSlots(_root);
        SeedStaging(slots.StagingDir, "new-bin.dll");

        var r = slots.Promote("7.0.1", "2026-08-29T00:00:00Z");
        Assert.True(r.IsSuccess);

        Assert.False(Directory.Exists(slots.StagingDir) && Directory.EnumerateFileSystemEntries(slots.StagingDir).Any());
        Assert.True(File.Exists(Path.Combine(slots.CurrentDir, "new-bin.dll")));
        Assert.Equal("7.0.1", slots.GetCurrentVersion());
    }

    [Fact]
    public void Promote_Twice_PreservesPreviousVersion()
    {
        var slots = new DeploymentSlots(_root);

        // 第一次：Staging v7.0.1 → Current
        SeedStaging(slots.StagingDir, "v7.0.1.dll");
        slots.Promote("7.0.1", "t1");
        Assert.Equal("7.0.1", slots.GetCurrentVersion());

        // 第二次：Staging v7.0.2 → Current，原 Current → Previous
        SeedStaging(slots.StagingDir, "v7.0.2.dll");
        slots.Promote("7.0.2", "t2");
        Assert.Equal("7.0.2", slots.GetCurrentVersion());
        Assert.True(File.Exists(Path.Combine(slots.PreviousDir, "v7.0.1.dll")));
    }

    [Fact]
    public void Rollback_WhenPreviousEmpty_ReturnsPathNotFound()
    {
        var slots = new DeploymentSlots(_root);
        var r = slots.Rollback();
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.PathNotFound, r.ErrorCode);
    }

    [Fact]
    public void Rollback_AfterPromote_RestoresPreviousAsCurrent()
    {
        var slots = new DeploymentSlots(_root);

        // v7.0.1 安装为 Current
        SeedStaging(slots.StagingDir, "v7.0.1.dll");
        slots.Promote("7.0.1", "t1");

        // v7.0.2 安装并作为 Current，v7.0.1 → Previous
        SeedStaging(slots.StagingDir, "v7.0.2.dll");
        slots.Promote("7.0.2", "t2");
        Assert.Equal("7.0.2", slots.GetCurrentVersion());

        // 回滚：Previous(v7.0.1) → Current
        var r = slots.Rollback();
        Assert.True(r.IsSuccess);
        Assert.Equal("7.0.1", slots.GetCurrentVersion());
        Assert.True(File.Exists(Path.Combine(slots.CurrentDir, "v7.0.1.dll")));
    }

    [Fact]
    public void ClearStaging_RemovesAllStagingContents()
    {
        var slots = new DeploymentSlots(_root);
        SeedStaging(slots.StagingDir, "a.txt", "b.txt");
        slots.ClearStaging();
        Assert.Empty(Directory.EnumerateFileSystemEntries(slots.StagingDir));
    }

    private static void SeedStaging(string stagingDir, params string[] fileNames)
    {
        Directory.CreateDirectory(stagingDir);
        foreach (var name in fileNames)
        {
            File.WriteAllText(Path.Combine(stagingDir, name), "content-" + name);
        }
    }
}
