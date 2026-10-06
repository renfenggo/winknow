using System.Text.Json.Serialization;

namespace Winknow.Ipc.Protocol;

/// <summary>
/// 连接期握手请求参数（contracts/ipc/envelope.schema.json HandshakeRequest.params）。
/// 首帧必须是 ipc.handshake；版本不兼容显式拒绝（ADR-001）。
/// </summary>
public sealed class HandshakeParams
{
    /// <summary>握手方法名。</summary>
    public const string MethodName = "ipc.handshake";

    /// <summary>契约允许的组件枚举。</summary>
    public static readonly IReadOnlySet<string> KnownComponents = new HashSet<string>(StringComparer.Ordinal)
    {
        "bridge", "admin_tool", "test_client", "session_agent",
    };

    /// <summary>客户端协议版本（"Major.Minor"）。</summary>
    [JsonPropertyName("protocol_version")]
    public string ProtocolVersion { get; init; } = string.Empty;

    /// <summary>组件类型（bridge/admin_tool/test_client/session_agent）。</summary>
    [JsonPropertyName("component")]
    public string Component { get; init; } = string.Empty;

    /// <summary>组件自身版本（如 0.1.0 / 7.0.0-fusion.1）。</summary>
    [JsonPropertyName("component_version")]
    public string ComponentVersion { get; init; } = string.Empty;

    /// <summary>客户端请求的能力列表。</summary>
    [JsonPropertyName("capabilities")]
    public IReadOnlyList<string> Capabilities { get; init; } = Array.Empty<string>();

    /// <summary>客户端设备 ID（与本机绑定）。</summary>
    [JsonPropertyName("device_id")]
    public string DeviceId { get; init; } = string.Empty;

    /// <summary>调用方 SID（须与帧头 SenderSid 一致）。</summary>
    [JsonPropertyName("caller_sid")]
    public string CallerSid { get; init; } = string.Empty;

    /// <summary>客户端会话 ID。</summary>
    [JsonPropertyName("session_id")]
    public string SessionId { get; init; } = string.Empty;

    /// <summary>校验字段格式（schema 约束的手写实现，不引入 JSON Schema 依赖）。</summary>
    public bool Validate(out string reason)
    {
        if (!global::Winknow.Ipc.Protocol.ProtocolVersion.TryParse(ProtocolVersion, out _))
        {
            reason = "protocol_version must be Major.Minor.";
            return false;
        }

        if (!KnownComponents.Contains(Component))
        {
            reason = $"unknown component '{Component}'.";
            return false;
        }

        if (string.IsNullOrEmpty(ComponentVersion))
        {
            reason = "component_version is required.";
            return false;
        }

        foreach (var capability in Capabilities)
        {
            // capability 采用与 method 一致的 "域.动词" 分段形式（method_registry.md：
            // status.read / classroom.control 等），schema 的 items pattern 已同步修正。
            var segments = capability.Split('.');
            if (segments.Length == 0 ||
                segments.Any(s => s.Length == 0 || s[0] is < 'a' or > 'z' ||
                    s.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '_')))
            {
                reason = $"invalid capability '{capability}'.";
                return false;
            }
        }

        if (DeviceId.Length < 8)
        {
            reason = "device_id must be at least 8 characters.";
            return false;
        }

        if (!CallerSid.StartsWith("S-1-", StringComparison.Ordinal))
        {
            reason = "caller_sid must be a SID string (S-1-...).";
            return false;
        }

        if (string.IsNullOrEmpty(SessionId))
        {
            reason = "session_id is required.";
            return false;
        }

        reason = string.Empty;
        return true;
    }
}

/// <summary>握手成功响应结果（HandshakeResponse.result）。</summary>
public sealed class HandshakeResult
{
    /// <summary>服务端接受的协议版本。</summary>
    [JsonPropertyName("protocol_version")]
    public string ProtocolVersion { get; init; } = string.Empty;

    /// <summary>服务端组件版本。</summary>
    [JsonPropertyName("component_version")]
    public string ComponentVersion { get; init; } = string.Empty;

    /// <summary>服务端授予的能力交集。</summary>
    [JsonPropertyName("capabilities")]
    public IReadOnlyList<string> Capabilities { get; init; } = Array.Empty<string>();

    /// <summary>会话有效期（秒，≥60）。</summary>
    [JsonPropertyName("session_ttl_s")]
    public int SessionTtlSeconds { get; init; }

    /// <summary>服务端 Unix 时间（秒）。</summary>
    [JsonPropertyName("server_time_unix")]
    public long ServerTimeUnix { get; init; }
}
