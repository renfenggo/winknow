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
