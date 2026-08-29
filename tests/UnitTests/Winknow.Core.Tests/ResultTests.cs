using Winknow.Core.Results;

namespace Winknow.Core.Tests;

public sealed class ResultTests
{
    [Fact]
    public void Success_WithData_ShouldExposeSuccessfulResult()
    {
        var result = Result<string>.Success("value");

        Assert.True(result.IsSuccess);
        Assert.Equal("value", result.Data);
        Assert.Equal(ErrorCode.Success, result.ErrorCode);
        Assert.Null(result.ErrorMessage);
    }

    [Fact]
    public void Failure_WithError_ShouldExposeFailureDetails()
    {
        var result = Result<string>.Failure(ErrorCode.InvalidParameter, "invalid input");

        Assert.False(result.IsSuccess);
        Assert.Null(result.Data);
        Assert.Equal(ErrorCode.InvalidParameter, result.ErrorCode);
        Assert.Equal("invalid input", result.ErrorMessage);
    }

    [Fact]
    public void Failure_WithSuccessCode_ShouldThrowArgumentException()
    {
        Assert.Throws<ArgumentException>(() => Result<string>.Failure(ErrorCode.Success));
    }
}

public sealed class NonGenericResultTests
{
    [Fact]
    public void Success_ShouldExposeSuccessfulResult()
    {
        var result = Result.Success();

        Assert.True(result.IsSuccess);
        Assert.Equal(ErrorCode.Success, result.ErrorCode);
        Assert.Null(result.ErrorMessage);
    }

    [Fact]
    public void Failure_WithError_ShouldExposeFailureDetails()
    {
        var result = Result.Failure(ErrorCode.AccessDenied, "denied");

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.AccessDenied, result.ErrorCode);
        Assert.Equal("denied", result.ErrorMessage);
    }

    [Fact]
    public void Failure_WithSuccessCode_ShouldThrowArgumentException()
    {
        Assert.Throws<ArgumentException>(() => Result.Failure(ErrorCode.Success));
    }

    [Theory]
    [InlineData(ErrorCode.InvalidArgument, "服务名不能为空")]
    [InlineData(ErrorCode.AccessDenied, "需要管理员权限")]
    [InlineData(ErrorCode.ExternalError, "Win32 调用失败")]
    public void Failure_NewErrorCodes_ShouldRoundtrip(ErrorCode code, string message)
    {
        var result = Result.Failure(code, message);

        Assert.False(result.IsSuccess);
        Assert.Equal(code, result.ErrorCode);
        Assert.Equal(message, result.ErrorMessage);
    }
}
