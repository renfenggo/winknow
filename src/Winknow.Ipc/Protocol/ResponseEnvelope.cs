using System.Text.Json;
using System.Text.Json.Serialization;

namespace Winknow.Ipc.Protocol;

/// <summary>
/// 响应信封（contracts/ipc/envelope.schema.json ResponseEnvelope）。
/// ok=true 时必须有 result 且无 error；ok=false 时必须有 error 且无 result。
/// </summary>
public sealed class ResponseEnvelope
{
    /// <summary>信封版本。</summary>
    public const int CurrentVersion = 1;

    /// <summary>信封版本（恒为 1）。</summary>
    [JsonPropertyName("v")]
    public int V { get; init; } = CurrentVersion;

    /// <summary>是否成功。</summary>
    [JsonPropertyName("ok")]
    public bool Ok { get; init; }

    /// <summary>成功结果（ok=true 时必有）。</summary>
    [JsonPropertyName("result")]
    public JsonElement? Result { get; init; }

    /// <summary>错误信封（ok=false 时必有）。</summary>
    [JsonPropertyName("error")]
    public ErrorEnvelope? Error { get; init; }

    /// <summary>由任意结果对象构造成功响应。</summary>
    public static ResponseEnvelope FromResult(object result)
    {
        var json = JsonSerializer.Serialize(result, Json.Options);
        return new ResponseEnvelope
        {
            Ok = true,
            Result = JsonSerializer.Deserialize<JsonElement>(json),
        };
    }

    /// <summary>由结果 JSON 文本构造成功响应。</summary>
    public static ResponseEnvelope FromRawJson(string resultJson) => new()
    {
        Ok = true,
        Result = JsonSerializer.Deserialize<JsonElement>(resultJson),
    };

    /// <summary>由错误信封构造失败响应。</summary>
    public static ResponseEnvelope FromError(ErrorEnvelope error) => new() { Ok = false, Error = error };

    /// <summary>序列化为契约 JSON。</summary>
    public string Serialize() => JsonSerializer.Serialize(this, Json.Options);

    /// <summary>从契约 JSON 反序列化。</summary>
    public static ResponseEnvelope? Deserialize(string json) =>
        JsonSerializer.Deserialize<ResponseEnvelope>(json, Json.Options);
}
