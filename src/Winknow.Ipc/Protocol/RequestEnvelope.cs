using System.Text.Json;
using System.Text.Json.Serialization;

namespace Winknow.Ipc.Protocol;

/// <summary>
/// 请求信封（contracts/ipc/envelope.schema.json RequestEnvelope）。
/// 安全元数据（时间戳/Nonce/SID/RequestId）在二进制帧头，此处不重复。
/// </summary>
public sealed class RequestEnvelope
{
    /// <summary>信封版本。</summary>
    public const int CurrentVersion = 1;

    /// <summary>校验方法名是否满足 "域.动词" 白名单格式（^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$）。</summary>
    public static bool IsValidMethodName(string? method)
    {
        if (string.IsNullOrEmpty(method))
        {
            return false;
        }

        var parts = method.Split('.');
        if (parts.Length < 2)
        {
            return false;
        }

        foreach (var part in parts)
        {
            if (part.Length == 0 || !IsLowerAlpha(part[0]))
            {
                return false;
            }

            foreach (var c in part)
            {
                if (!IsLowerAlpha(c) && !char.IsAsciiDigit(c) && c != '_')
                {
                    return false;
                }
            }
        }

        return true;

        static bool IsLowerAlpha(char c) => c is >= 'a' and <= 'z';
    }

    /// <summary>信封版本（恒为 1）。</summary>
    [JsonPropertyName("v")]
    public int V { get; init; } = CurrentVersion;

    /// <summary>请求方法名（必须在 method_registry.md 注册）。</summary>
    [JsonPropertyName("method")]
    public string Method { get; init; } = string.Empty;

    /// <summary>方法参数（按方法 schema 解释）。</summary>
    [JsonPropertyName("params")]
    public JsonElement? Params { get; init; }

    /// <summary>调用链追踪 ID（可选）。</summary>
    [JsonPropertyName("trace_id")]
    public string? TraceId { get; init; }

    /// <summary>序列化为契约 JSON。</summary>
    public string Serialize() => JsonSerializer.Serialize(this, Json.Options);

    /// <summary>从契约 JSON 反序列化。</summary>
    public static RequestEnvelope? Deserialize(string json) =>
        JsonSerializer.Deserialize<RequestEnvelope>(json, Json.Options);
}
