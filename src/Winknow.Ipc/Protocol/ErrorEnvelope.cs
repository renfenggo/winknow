using System.Text.Json;
using System.Text.Json.Serialization;

namespace Winknow.Ipc.Protocol;

/// <summary>
/// 错误信封（contracts/errors/error_envelope.schema.json）。
/// </summary>
public sealed class ErrorEnvelope
{
    /// <summary>错误信封 schema 版本。</summary>
    public const string SchemaVersion = "1.0";

    /// <summary>错误信封 schema 版本（序列化字段 schema_version）。</summary>
    [JsonPropertyName("schema_version")]
    public string SchemaVersionValue { get; init; } = SchemaVersion;

    /// <summary>契约错误码（IpcErrorCodes）。</summary>
    [JsonPropertyName("code")]
    public string Code { get; init; } = string.Empty;

    /// <summary>人类可读错误消息。</summary>
    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;

    /// <summary>是否可重试（按错误码注册表推导，不接受外部伪造）。</summary>
    [JsonPropertyName("retryable")]
    public bool Retryable => IpcErrorCodes.RetryableCodes.Contains(Code);

    /// <summary>调用方携带的 trace_id（可选）。</summary>
    [JsonPropertyName("trace_id")]
    public string? TraceId { get; init; }

    /// <summary>附加明细（如 expected/actual 版本、retry_after_s）。</summary>
    [JsonPropertyName("details")]
    public IReadOnlyDictionary<string, object?>? Details { get; init; }

    /// <summary>构造错误信封。</summary>
    public static ErrorEnvelope Create(string code, string message, string? traceId = null,
        IReadOnlyDictionary<string, object?>? details = null) => new()
    {
        Code = code,
        Message = message,
        TraceId = traceId,
        Details = details,
    };

    /// <summary>序列化为契约 JSON。</summary>
    public string Serialize() => JsonSerializer.Serialize(this, Json.Options);

    /// <summary>从契约 JSON 反序列化。</summary>
    public static ErrorEnvelope? Deserialize(string json) => JsonSerializer.Deserialize<ErrorEnvelope>(json, Json.Options);
}

/// <summary>协议层共享 JSON 选项。</summary>
public static class Json
{
    /// <summary>camelCase + 忽略 null 的序列化选项。</summary>
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}
