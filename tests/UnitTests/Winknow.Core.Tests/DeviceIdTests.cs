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
