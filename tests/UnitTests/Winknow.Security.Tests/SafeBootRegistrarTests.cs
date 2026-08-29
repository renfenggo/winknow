using Winknow.Core.Results;
using Winknow.Security;

namespace Winknow.Security.Tests;

/// <summary>
/// SafeBootRegistrar 单元测试。
///
/// 仅覆盖输入验证与状态查询路径（环境无关，CI 友好）。
/// 真实注册表写入需管理员权限，由集成测试在授权环境验证。
/// </summary>
public sealed class SafeBootRegistrarTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Register_EmptyServiceName_ReturnsInvalidArgument(string? name)
    {
        var result = SafeBootRegistrar.Register(name!, "desc");

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.InvalidArgument, result.ErrorCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Unregister_EmptyServiceName_ReturnsInvalidArgument(string? name)
    {
        var result = SafeBootRegistrar.Unregister(name!);

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.InvalidArgument, result.ErrorCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void IsRegistered_EmptyServiceName_ReturnsFalse(string? name)
    {
        Assert.False(SafeBootRegistrar.IsRegistered(name!));
    }

    [Fact]
    public void IsRegistered_UnknownService_ReturnsFalse()
    {
        // 未注册的虚构服务名必然不在 SafeBoot 白名单
        Assert.False(SafeBootRegistrar.IsRegistered("Winknow.NonExistent.TestService.0001"));
    }
}
