using System.Text.Json;
using Winknow.Core.Results;
using Winknow.CodeRunner;

namespace Winknow.CodeRunner.Tests;

/// <summary>
/// Runner 契约模型与请求校验器测试（对齐 contracts/runner/runner.schema.json）。
/// </summary>
public sealed class RunnerContractTests
{
    private static ResourceLimits ValidLimits() => new()
    {
        WallClockMs = 5_000,
        CpuMs = 5_000,
        MemoryMb = 128,
        ProcessCount = 4,
        OutputBytes = 65_536,
        FileBytes = 1_048_576,
    };

    private static RunnerRequest ValidRequest() => new()
    {
        RequestId = "req-1",
        Language = RunnerLanguage.Cpp17,
        Source = "int main() { return 0; }",
        Stdin = null,
        Limits = ValidLimits(),
        TraceId = "trace-1",
    };

    [Fact]
    public void Result_Serialize_UsesContractSnakeCaseFields()
    {
        var result = new RunnerResult
        {
            RequestId = "req-1",
            Status = RunnerStatus.RunOk,
            CompileExitCode = 0,
            RunExitCode = 0,
            Stdout = "hello",
            Stderr = null,
            ElapsedMs = 42,
            PeakMemoryKb = 2_048,
            TimedOut = false,
            OutputTruncated = false,
            ArtifactsCleaned = true,
            TraceId = "trace-1",
        };

        var json = JsonSerializer.Serialize(result, RunnerJson.Options);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // 契约必填字段 snake_case 全部在位
        Assert.True(root.TryGetProperty("request_id", out _), "request_id");
        Assert.True(root.TryGetProperty("status", out _), "status");
        Assert.True(root.TryGetProperty("elapsed_ms", out _), "elapsed_ms");
        Assert.True(root.TryGetProperty("peak_memory_kb", out _), "peak_memory_kb");
        Assert.True(root.TryGetProperty("timed_out", out _), "timed_out");
        Assert.True(root.TryGetProperty("output_truncated", out _), "output_truncated");
        Assert.True(root.TryGetProperty("artifacts_cleaned", out _), "artifacts_cleaned");

        // 可选字段 null 时省略
        Assert.False(root.TryGetProperty("stderr", out _), "stderr null 应省略");

        // 枚举序列化为大写下划线契约形式
        Assert.Equal("RUN_OK", root.GetProperty("status").GetString());
        Assert.Equal(0, root.GetProperty("compile_exit_code").GetInt32());
        Assert.Equal(42, root.GetProperty("elapsed_ms").GetInt64());
    }

    [Fact]
    public void Request_Deserialize_FromContractSnakeCaseJson()
    {
        const string json = """
            {
              "request_id": "req-42",
              "language": "cpp14",
              "source": "#include <cstdio>\nint main(){ std::puts(\"hi\"); }",
              "stdin": "1 2 3",
              "limits": {
                "wall_clock_ms": 10000,
                "cpu_ms": 8000,
                "memory_mb": 64,
                "process_count": 2,
                "output_bytes": 8192,
                "file_bytes": 4096
              },
              "trace_id": "t-9"
            }
            """;

        var request = JsonSerializer.Deserialize<RunnerRequest>(json, RunnerJson.Options);

        Assert.NotNull(request);
        Assert.Equal("req-42", request.RequestId);
        Assert.Equal(RunnerLanguage.Cpp14, request.Language);
        Assert.Equal("1 2 3", request.Stdin);
        Assert.Equal(10_000, request.Limits.WallClockMs);
        Assert.Equal(8_000, request.Limits.CpuMs);
        Assert.Equal(64, request.Limits.MemoryMb);
        Assert.Equal(2, request.Limits.ProcessCount);
        Assert.Equal(8_192, request.Limits.OutputBytes);
        Assert.Equal(4_096, request.Limits.FileBytes);
        Assert.Equal("t-9", request.TraceId);
    }

    [Theory]
    [InlineData(RunnerLanguage.Cpp14, "cpp14")]
    [InlineData(RunnerLanguage.Cpp17, "cpp17")]
    public void Language_RoundTripsAsContractString(RunnerLanguage language, string expected)
    {
        var request = ValidRequest() with { };
        var json = JsonSerializer.Serialize(new { language }, RunnerJson.Options);
        Assert.Contains($"\"{expected}\"", json);

        var roundTrip = JsonSerializer.Deserialize<RunnerRequest>(
            JsonSerializer.Serialize(request with { Language = language }, RunnerJson.Options), RunnerJson.Options);
        Assert.NotNull(roundTrip);
        Assert.Equal(language, roundTrip.Language);
    }

    [Fact]
    public void Validator_AcceptsContractValidRequest()
    {
        var result = RunnerRequestValidator.Validate(ValidRequest());

        Assert.True(result.IsSuccess, result.ErrorMessage ?? "应通过校验");
        Assert.Equal("req-1", result.Data!.RequestId);
    }

    [Fact]
    public void Validator_RejectsNullRequest()
    {
        var result = RunnerRequestValidator.Validate(null);

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.InvalidArgument, result.ErrorCode);
    }

    [Fact]
    public void Validator_RejectsEmptyOrOverlongRequestId()
    {
        var empty = RunnerRequestValidator.Validate(ValidRequest() with { RequestId = "" });
        Assert.False(empty.IsSuccess, "空 request_id 应拒绝");

        var overlong = RunnerRequestValidator.Validate(ValidRequest() with
        {
            RequestId = new string('r', RunnerRequestValidator.MaxRequestIdLength + 1),
        });
        Assert.False(overlong.IsSuccess, "超长 request_id 应拒绝");
    }

    [Fact]
    public void Validator_RejectsSourceOver256Kb()
    {
        var request = ValidRequest() with
        {
            Source = new string('a', RunnerRequestValidator.MaxSourceBytes + 1),
        };

        var result = RunnerRequestValidator.Validate(request);

        Assert.False(result.IsSuccess);
        Assert.Contains("source", result.ErrorMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validator_RejectsStdinOver1Mb()
    {
        var request = ValidRequest() with
        {
            Stdin = new string('s', RunnerRequestValidator.MaxStdinBytes + 1),
        };

        var result = RunnerRequestValidator.Validate(request);

        Assert.False(result.IsSuccess);
        Assert.Contains("stdin", result.ErrorMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(99, false)]
    [InlineData(100, true)]
    [InlineData(60_000, true)]
    [InlineData(60_001, false)]
    public void Validator_EnforcesWallClockRange(int value, bool expectedValid)
    {
        var request = ValidRequest() with { Limits = ValidLimits() with { WallClockMs = value } };

        var result = RunnerRequestValidator.Validate(request);

        Assert.Equal(expectedValid, result.IsSuccess);
    }

    [Theory]
    [InlineData(99, false)]
    [InlineData(100, true)]
    [InlineData(60_000, true)]
    [InlineData(60_001, false)]
    public void Validator_EnforcesCpuRange(int value, bool expectedValid)
    {
        var request = ValidRequest() with { Limits = ValidLimits() with { CpuMs = value } };

        var result = RunnerRequestValidator.Validate(request);

        Assert.Equal(expectedValid, result.IsSuccess);
    }

    [Theory]
    [InlineData(15, false)]
    [InlineData(16, true)]
    [InlineData(512, true)]
    [InlineData(513, false)]
    public void Validator_EnforcesMemoryRange(int value, bool expectedValid)
    {
        var request = ValidRequest() with { Limits = ValidLimits() with { MemoryMb = value } };

        var result = RunnerRequestValidator.Validate(request);

        Assert.Equal(expectedValid, result.IsSuccess);
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    [InlineData(8, true)]
    [InlineData(9, false)]
    public void Validator_EnforcesProcessCountRange(int value, bool expectedValid)
    {
        var request = ValidRequest() with { Limits = ValidLimits() with { ProcessCount = value } };

        var result = RunnerRequestValidator.Validate(request);

        Assert.Equal(expectedValid, result.IsSuccess);
    }

    [Theory]
    [InlineData(1_023, false)]
    [InlineData(1_024, true)]
    [InlineData(1_048_576, true)]
    [InlineData(1_048_577, false)]
    public void Validator_EnforcesOutputBytesRange(int value, bool expectedValid)
    {
        var request = ValidRequest() with { Limits = ValidLimits() with { OutputBytes = value } };

        var result = RunnerRequestValidator.Validate(request);

        Assert.Equal(expectedValid, result.IsSuccess);
    }

    [Theory]
    [InlineData(1_023, false)]
    [InlineData(1_024, true)]
    [InlineData(10_485_760, true)]
    [InlineData(10_485_761, false)]
    public void Validator_EnforcesFileBytesRange(int value, bool expectedValid)
    {
        var request = ValidRequest() with { Limits = ValidLimits() with { FileBytes = value } };

        var result = RunnerRequestValidator.Validate(request);

        Assert.Equal(expectedValid, result.IsSuccess);
    }
}
