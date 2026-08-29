using Winknow.Core.Results;
using Winknow.TrustedUpdater;

namespace Winknow.TrustedUpdater.Tests;

/// <summary>
/// 第 7 周"版本守卫"测试。
/// 覆盖验收项：
/// - "防降级保护（拒绝降级到已知不安全版本）"
/// - "版本兼容校验（主服务、守护服务、Agent 版本一致性）"
/// </summary>
public class VersionGuardTests
{
    [Theory]
    [InlineData("7.0.0", "7.0.0", 0)]
    [InlineData("7.0.0", "7.0.1", -1)]
    [InlineData("7.0.1", "7.0.0", 1)]
    [InlineData("7.0.0.1", "7.0.0.2", -1)]
    [InlineData("7.0.1", "7.0.0.1", 1)]
    public void CompareVersions_StandardVersioning(string a, string b, int expected)
    {
        var actual = VersionGuard.CompareVersions(a, b);
        Assert.Equal(expected, Math.Sign(actual));
    }

    [Fact]
    public void CheckUpgrade_Upgrade_Succeeds()
    {
        var m = BuildManifest(version: "7.0.1");
        var r = VersionGuard.CheckUpgrade("7.0.0", m);
        Assert.True(r.IsSuccess);
    }

    [Fact]
    public void CheckUpgrade_SameVersion_Succeeds()
    {
        var m = BuildManifest(version: "7.0.1");
        var r = VersionGuard.CheckUpgrade("7.0.1", m);
        Assert.True(r.IsSuccess);
    }

    [Fact]
    public void CheckUpgrade_Downgrade_ReturnsVersionBlocked()
    {
        var m = BuildManifest(version: "7.0.0");
        var r = VersionGuard.CheckUpgrade("7.0.1", m);
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.VersionBlocked, r.ErrorCode);
    }

    [Fact]
    public void CheckUpgrade_HitRollbackBlacklist_ReturnsVersionBlocked()
    {
        var m = BuildManifest(version: "7.0.5", rollbackBlacklist: new List<string> { "7.0.5" });
        var r = VersionGuard.CheckUpgrade("7.0.4", m);
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.VersionBlocked, r.ErrorCode);
    }

    [Fact]
    public void CheckUpgrade_BlacklistedVersionStillBlocked_EvenIfEqual()
    {
        var m = BuildManifest(version: "7.0.5", rollbackBlacklist: new List<string> { "7.0.5" });
        var r = VersionGuard.CheckUpgrade("7.0.5", m);
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.VersionBlocked, r.ErrorCode);
    }

    [Fact]
    public void CheckCompatibility_CurrentTooOld_ReturnsInvalidArgument()
    {
        var m = BuildManifest(version: "7.0.2", minCompatibleVersion: "7.0.1");
        var r = VersionGuard.CheckCompatibility("7.0.0", m);
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.InvalidArgument, r.ErrorCode);
    }

    [Fact]
    public void CheckCompatibility_CurrentMeetsMin_Succeeds()
    {
        var m = BuildManifest(version: "7.0.2", minCompatibleVersion: "7.0.0");
        var r = VersionGuard.CheckCompatibility("7.0.1", m);
        Assert.True(r.IsSuccess);
    }

    [Fact]
    public void CheckCompatibility_ComponentVersionMismatch_ReturnsInvalidArgument()
    {
        var m = BuildManifest(version: "7.0.2",
            components: new Dictionary<string, string>
            {
                ["ControlService"] = "7.0.2",
                ["GuardService"] = "7.0.1",   // 不一致
                ["SessionAgent"] = "7.0.2"
            });
        var r = VersionGuard.CheckCompatibility("7.0.1", m);
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.InvalidArgument, r.ErrorCode);
    }

    [Fact]
    public void CheckCompatibility_ComponentVersionConsistent_Succeeds()
    {
        var m = BuildManifest(version: "7.0.2",
            components: new Dictionary<string, string>
            {
                ["ControlService"] = "7.0.2",
                ["GuardService"] = "7.0.2",
                ["SessionAgent"] = "7.0.2"
            });
        var r = VersionGuard.CheckCompatibility("7.0.1", m);
        Assert.True(r.IsSuccess);
    }

    private static UpdateManifest BuildManifest(
        string version = "7.0.1",
        string minCompatibleVersion = "7.0.0",
        List<string>? rollbackBlacklist = null,
        Dictionary<string, string>? components = null) =>
        new()
        {
            ProductId = TestUpdatablePackage.ProductId,
            Version = version,
            MinCompatibleVersion = minCompatibleVersion,
            RollbackBlacklist = rollbackBlacklist ?? new List<string>(),
            Components = components ?? new Dictionary<string, string>
            {
                ["ControlService"] = version,
                ["GuardService"] = version,
                ["SessionAgent"] = version
            },
            Files = new List<FileEntry>(),
            BuildTime = "2026-08-29T00:00:00Z"
        };
}
