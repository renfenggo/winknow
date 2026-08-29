using Winknow.Core.Results;
using Winknow.Security;

namespace Winknow.Security.Tests;

/// <summary>
/// ServiceSecurity / ServiceRecovery / ProcessSecurity 输入验证测试。
///
/// 仅覆盖参数校验路径，真实 Win32 调用需管理员权限并由集成测试验证。
/// </summary>
public sealed class ServiceProtectionTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ApplyServiceProtection_EmptyName_ReturnsInvalidArgument(string? name)
    {
        var result = ServiceSecurity.ApplyServiceProtection(name!);

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.InvalidArgument, result.ErrorCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ApplyServiceRecovery_EmptyName_ReturnsInvalidArgument(string? name)
    {
        var result = ServiceRecovery.ApplyServiceRecovery(name!);

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.InvalidArgument, result.ErrorCode);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-99)]
    public void ProtectProcess_InvalidPid_ReturnsInvalidArgument(int pid)
    {
        var result = ProcessSecurity.ProtectProcess(pid);

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.InvalidArgument, result.ErrorCode);
    }

    [Fact]
    public void IsRunningAsAdministrator_ReturnsBooleanWithoutThrowing()
    {
        // 纯断言：方法可安全调用，返回值随运行身份变化
        var value = ServiceSecurity.IsRunningAsAdministrator();
        Assert.IsType<bool>(value);
    }
}
