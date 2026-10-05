using System.Text.RegularExpressions;

namespace Winknow.Core.Tests;

public sealed class DeviceIdTests
{
    [Fact]
    public void Generate_CurrentMachine_ShouldReturnSixteenHexCharacters()
    {
        var deviceId = DeviceId.Generate();

        Assert.Matches(new Regex("^[0-9A-F]{16}$", RegexOptions.CultureInvariant), deviceId);
    }

    [Fact]
    public void Generate_CalledTwice_ShouldReturnStableValue()
    {
        var first = DeviceId.Generate();
        var second = DeviceId.Generate();

        Assert.Equal(first, second);
    }
}

public sealed class ProductPathsTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "winknow-paths-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public void ConstructedWithTestRoot_UsesTheFrozenProductLayout()
    {
        var paths = new ProductPaths(_root);

        Assert.Equal(Path.Combine(_root, "deploy", "Current"), paths.CurrentDeployment);
        Assert.Equal(Path.Combine(_root, "policies", "active_policy.json"), paths.ActivePolicy);
        Assert.Equal(Path.Combine(_root, "deploy", "publickey.pem"), paths.PublicKey);
    }

    [Fact]
    public void EnsureDirectories_CreatesOnlyProductDirectories()
    {
        var paths = new ProductPaths(_root);
        paths.EnsureDirectories();

        Assert.True(Directory.Exists(paths.DeployRoot));
        Assert.True(Directory.Exists(paths.Policies));
        Assert.True(Directory.Exists(paths.Maintenance));
        Assert.True(Directory.Exists(paths.Logs));
        Assert.True(Directory.Exists(paths.Keys));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, true);
    }
}
