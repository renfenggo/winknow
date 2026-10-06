using System.Text.Json;
using System.Text.Json.Serialization;

namespace Winknow.CodeRunner;

/// <summary>
/// 源语言（契约 runner.schema.json $defs/Language，V1 仅 C++14/C++17）。
/// </summary>
public enum RunnerLanguage
{
    /// <summary>C++14（序列化为 cpp14）。</summary>
    Cpp14,

    /// <summary>C++17（序列化为 cpp17）。</summary>
    Cpp17,
}

/// <summary>
/// 执行状态（契约 runner.schema.json $defs/RunnerStatus；兼容性：枚举只增不改）。
/// </summary>
public enum RunnerStatus
{
    /// <summary>编译成功（序列化为 COMPILED_OK）。</summary>
    CompiledOk,

    /// <summary>编译失败（COMPILE_FAILED）。</summary>
    CompileFailed,

    /// <summary>运行成功（RUN_OK）。</summary>
    RunOk,

    /// <summary>运行失败（RUN_FAILED）。</summary>
    RunFailed,

    /// <summary>运行超时（RUN_TIMEOUT）。</summary>
    RunTimeout,

    /// <summary>触发资源限制（RESOURCE_LIMIT）。</summary>
    ResourceLimit,

    /// <summary>Runner 内部错误（INTERNAL_ERROR）。</summary>
    InternalError,

    /// <summary>请求被拒绝（REJECTED，校验失败等）。</summary>
    Rejected,
}

/// <summary>
/// 资源限制（契约 $defs/ResourceLimits，全部字段必填且带范围）。
/// </summary>
public sealed record ResourceLimits
{
    /// <summary>墙钟超时（毫秒，契约范围 [100, 60000]）。</summary>
    public int WallClockMs { get; init; }

    /// <summary>CPU 时间上限（毫秒，契约范围 [100, 60000]）。</summary>
    public int CpuMs { get; init; }

    /// <summary>内存上限（MB，契约范围 [16, 512]）。</summary>
    public int MemoryMb { get; init; }

    /// <summary>进程数上限（含子进程，契约范围 [1, 8]）。</summary>
    public int ProcessCount { get; init; }

    /// <summary>输出字节上限（stdout+stderr 合计，契约范围 [1024, 1048576]）。</summary>
    public int OutputBytes { get; init; }

    /// <summary>单文件写入字节上限（契约范围 [1024, 10485760]）。</summary>
    public int FileBytes { get; init; }
}

/// <summary>
/// 执行请求（契约 $defs/RunnerRequest）。
/// </summary>
public sealed record RunnerRequest
{
    /// <summary>请求标识（调用方生成，结果原样回带）。</summary>
    public string RequestId { get; init; } = string.Empty;

    /// <summary>源语言。</summary>
    public RunnerLanguage Language { get; init; }

    /// <summary>UTF-8 源码（≤ 256KB）。</summary>
    public string Source { get; init; } = string.Empty;

    /// <summary>可选标准输入（≤ 1MB）。</summary>
    public string? Stdin { get; init; }

    /// <summary>资源限制。</summary>
    public ResourceLimits Limits { get; init; } = new();

    /// <summary>可选链路追踪 ID。</summary>
    public string? TraceId { get; init; }
}

/// <summary>
/// 执行结果（契约 $defs/RunnerResult；必填字段始终输出，可选字段 null 时省略）。
/// </summary>
public sealed record RunnerResult
{
    /// <summary>请求标识（回带）。</summary>
    public string RequestId { get; init; } = string.Empty;

    /// <summary>执行状态。</summary>
    public RunnerStatus Status { get; init; }

    /// <summary>编译退出码（未到编译阶段为 null）。</summary>
    public int? CompileExitCode { get; init; }

    /// <summary>编译诊断输出（≤ 64KB，超出截断）。</summary>
    public string? CompileDiagnostics { get; init; }

    /// <summary>运行退出码（未到运行阶段为 null）。</summary>
    public int? RunExitCode { get; init; }

    /// <summary>标准输出（≤ 1MB，超出截断）。</summary>
    public string? Stdout { get; init; }

    /// <summary>标准错误（≤ 256KB，超出截断）。</summary>
    public string? Stderr { get; init; }

    /// <summary>端到端耗时（毫秒）。</summary>
    public long ElapsedMs { get; init; }

    /// <summary>峰值内存（KB，来自 Job Object 记账）。</summary>
    public long PeakMemoryKb { get; init; }

    /// <summary>是否发生超时终止。</summary>
    public bool TimedOut { get; init; }

    /// <summary>输出是否被截断。</summary>
    public bool OutputTruncated { get; init; }

    /// <summary>工作目录与产物是否已清理。</summary>
    public bool ArtifactsCleaned { get; init; }

    /// <summary>可选链路追踪 ID（回带）。</summary>
    public string? TraceId { get; init; }
}

/// <summary>
/// Runner 能力快照（IPC runner.get_capabilities 响应结果）。
/// 工具链不可用时 available=false 且语言列表为空——调用方据此决定是否下发执行请求。
/// </summary>
public sealed record RunnerCapabilities
{
    /// <summary>组件名（恒 code_runner）。</summary>
    public string Component { get; init; } = "code_runner";

    /// <summary>工具链是否可用（g++ 探测成功）。</summary>
    public bool Available { get; init; }

    /// <summary>编译器完整路径（不可用为 null）。</summary>
    public string? CompilerPath { get; init; }

    /// <summary>编译器版本描述（不可用为 null）。</summary>
    public string? CompilerVersion { get; init; }

    /// <summary>支持的语言列表（cpp14/cpp17 子集，按工具链 -std= 能力过滤）。</summary>
    public IReadOnlyList<RunnerLanguage> Languages { get; init; } = Array.Empty<RunnerLanguage>();
}

/// <summary>
/// Runner 契约 JSON 序列化选项（snake_case 字段 + 枚举字符串：
/// Language → cpp14/cpp17；Status → COMPILED_OK 等大写下划线，与 runner.schema.json 对齐）。
/// </summary>
public static class RunnerJson
{
    /// <summary>
    /// 将 PascalCase 枚举名转为大写下划线契约形式（CompiledOk → COMPILED_OK）。
    /// </summary>
    private sealed class UpperSnakeCaseNamingPolicy : JsonNamingPolicy
    {
        public override string ConvertName(string name)
        {
            var sb = new System.Text.StringBuilder(name.Length + 8);
            for (var i = 0; i < name.Length; i++)
            {
                if (i > 0 && char.IsUpper(name[i]))
                {
                    sb.Append('_');
                }
                sb.Append(char.ToUpperInvariant(name[i]));
            }
            return sb.ToString();
        }
    }

    /// <summary>契约对齐的序列化选项（只读单例）。</summary>
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters =
        {
            new JsonStringEnumConverter<RunnerLanguage>(JsonNamingPolicy.SnakeCaseLower),
            new JsonStringEnumConverter<RunnerStatus>(new UpperSnakeCaseNamingPolicy()),
        },
    };
}
