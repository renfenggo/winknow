using System.Text;
using Winknow.Core.Results;

namespace Winknow.CodeRunner;

/// <summary>
/// RunnerRequest 语义校验（runner.schema.json 的代码侧等价实现；
/// IPC 边界反序列化后、进入沙箱前必须通过本校验，防契约外请求进入执行链）。
/// </summary>
public static class RunnerRequestValidator
{
    /// <summary>源码上限（字节，UTF-8）。</summary>
    public const int MaxSourceBytes = 262_144;

    /// <summary>标准输入上限（字节，UTF-8）。</summary>
    public const int MaxStdinBytes = 1_048_576;

    /// <summary>请求标识长度上限（字符）。</summary>
    public const int MaxRequestIdLength = 128;

    /// <summary>校验请求（全部字段范围与契约一致；失败返回 InvalidArgument 与字段级原因）。</summary>
    /// <param name="request">待校验请求。</param>
    /// <returns>成功时回带原请求；失败时含安全错误消息。</returns>
    public static Result<RunnerRequest> Validate(RunnerRequest? request)
    {
        if (request is null)
        {
            return Result<RunnerRequest>.Failure(ErrorCode.InvalidArgument, "request is null.");
        }

        if (string.IsNullOrWhiteSpace(request.RequestId) || request.RequestId.Length > MaxRequestIdLength)
        {
            return Result<RunnerRequest>.Failure(ErrorCode.InvalidArgument,
                $"request_id must be a non-empty string of at most {MaxRequestIdLength} characters.");
        }

        if (request.Language is not (RunnerLanguage.Cpp14 or RunnerLanguage.Cpp17))
        {
            return Result<RunnerRequest>.Failure(ErrorCode.InvalidArgument,
                "language must be cpp14 or cpp17.");
        }

        if (Encoding.UTF8.GetByteCount(request.Source) > MaxSourceBytes)
        {
            return Result<RunnerRequest>.Failure(ErrorCode.InvalidArgument,
                $"source exceeds {MaxSourceBytes} UTF-8 bytes.");
        }

        if (request.Stdin is not null && Encoding.UTF8.GetByteCount(request.Stdin) > MaxStdinBytes)
        {
            return Result<RunnerRequest>.Failure(ErrorCode.InvalidArgument,
                $"stdin exceeds {MaxStdinBytes} UTF-8 bytes.");
        }

        var limits = request.Limits;
        if (limits is null)
        {
            return Result<RunnerRequest>.Failure(ErrorCode.InvalidArgument, "limits is required.");
        }

        if (limits.WallClockMs is < 100 or > 60_000)
        {
            return FieldFailure("limits.wall_clock_ms", 100, 60_000);
        }

        if (limits.CpuMs is < 100 or > 60_000)
        {
            return FieldFailure("limits.cpu_ms", 100, 60_000);
        }

        if (limits.MemoryMb is < 16 or > 512)
        {
            return FieldFailure("limits.memory_mb", 16, 512);
        }

        if (limits.ProcessCount is < 1 or > 8)
        {
            return FieldFailure("limits.process_count", 1, 8);
        }

        if (limits.OutputBytes is < 1_024 or > 1_048_576)
        {
            return FieldFailure("limits.output_bytes", 1_024, 1_048_576);
        }

        if (limits.FileBytes is < 1_024 or > 10_485_760)
        {
            return FieldFailure("limits.file_bytes", 1_024, 10_485_760);
        }

        return Result<RunnerRequest>.Success(request);
    }

    private static Result<RunnerRequest> FieldFailure(string field, int min, int max) =>
        Result<RunnerRequest>.Failure(ErrorCode.InvalidArgument,
            $"{field} must be an integer within [{min}, {max}].");
}
