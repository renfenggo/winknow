using System.Text.Json;
using Winknow.Ipc.Protocol;

namespace Winknow.Ipc.Session;

/// <summary>服务端握手结果（含响应信封与断连决策）。</summary>
public sealed record HandshakeOutcome(
    bool Accepted,
    ResponseEnvelope Response,
    bool CloseConnection,
    IReadOnlySet<string> GrantedCapabilities,
    string SessionId,
    string Component)
{
    /// <summary>构造拒绝结果。</summary>
    public static HandshakeOutcome Reject(string code, string message, bool closeConnection,
        IReadOnlyDictionary<string, object?>? details = null) => new(
        Accepted: false,
        Response: ResponseEnvelope.FromError(ErrorEnvelope.Create(code, message, details: details)),
        CloseConnection: closeConnection,
        GrantedCapabilities: new HashSet<string>(),
        SessionId: string.Empty,
        Component: string.Empty);
}

/// <summary>
/// 服务端自描述信息（握手协商输入）。
/// </summary>
public sealed class IpcServerDescriptor
{
    /// <summary>服务端协议版本。</summary>
    public ProtocolVersion Protocol { get; init; } = ProtocolVersion.Current;

    /// <summary>服务端组件版本（如 7.0.0-fusion.1）。</summary>
    public string ComponentVersion { get; init; } = string.Empty;

    /// <summary>服务端支持的能力全集。</summary>
    public IReadOnlySet<string> SupportedCapabilities { get; init; } = new HashSet<string>();

    /// <summary>本机设备 ID（设备绑定）。</summary>
    public string DeviceId { get; init; } = string.Empty;

    /// <summary>会话有效期（秒）。</summary>
    public int SessionTtlSeconds { get; init; } = 28800;

    /// <summary>时间提供者（便于测试）。</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}

/// <summary>
/// 连接期握手校验器（ADR-001）：
/// 首帧必须是 ipc.handshake；版本不兼容/设备不匹配/身份不一致显式拒绝并断连，不得静默运行。
/// 纯逻辑组件，不绑定管道，可独立单元测试。
/// </summary>
public sealed class IpcHandshakeValidator
{
    private readonly IpcServerDescriptor _server;

    /// <summary>创建握手校验器。</summary>
    public IpcHandshakeValidator(IpcServerDescriptor server)
    {
        _server = server ?? throw new ArgumentNullException(nameof(server));
    }

    /// <summary>处理握手帧 payload，返回结果与响应信封。</summary>
    public HandshakeOutcome Handle(ReadOnlySpan<byte> payload, string frameSenderSid)
    {
        RequestEnvelope? request;
        try
        {
            var json = System.Text.Encoding.UTF8.GetString(payload);
            request = RequestEnvelope.Deserialize(json);
        }
        catch (JsonException)
        {
            return RejectInvalid("handshake payload is not valid JSON.");
        }

        if (request is null)
        {
            return RejectInvalid("handshake payload is empty.");
        }

        if (request.V != RequestEnvelope.CurrentVersion)
        {
            return RejectInvalid($"envelope version must be {RequestEnvelope.CurrentVersion}.");
        }

        if (!string.Equals(request.Method, HandshakeParams.MethodName, StringComparison.Ordinal))
        {
            return RejectInvalid($"first frame method must be '{HandshakeParams.MethodName}'.");
        }

        HandshakeParams handshake;
        try
        {
            handshake = request.Params!.Value.Deserialize<HandshakeParams>(Protocol.Json.Options) ?? new HandshakeParams();
        }
        catch (JsonException)
        {
            return RejectInvalid("handshake params are malformed.");
        }

        if (!handshake.Validate(out var reason))
        {
            return RejectInvalid($"handshake params invalid: {reason}");
        }

        // 版本兼容：主版本一致且客户端次版本不高于服务端（显式拒绝，不静默降级）
        if (!ProtocolVersion.TryParse(handshake.ProtocolVersion, out var clientVersion) ||
            !_server.Protocol.Accepts(clientVersion))
        {
            return HandshakeOutcome.Reject(
                IpcErrorCodes.IpcVersionMismatch,
                "protocol version incompatible.",
                closeConnection: true,
                details: new Dictionary<string, object?>
                {
                    ["expected"] = _server.Protocol.ToString(),
                    ["actual"] = handshake.ProtocolVersion,
                });
        }

        // 设备绑定：DeviceId 必须与本机一致
        if (!string.Equals(handshake.DeviceId, _server.DeviceId, StringComparison.Ordinal))
        {
            return HandshakeOutcome.Reject(
                IpcErrorCodes.PermissionDenied,
                "device binding failed.",
                closeConnection: true);
        }

        // 身份一致：payload caller_sid 必须与帧头 SenderSid（管道模拟身份）一致
        if (!string.Equals(handshake.CallerSid, frameSenderSid, StringComparison.Ordinal))
        {
            return HandshakeOutcome.Reject(
                IpcErrorCodes.PermissionDenied,
                "caller_sid does not match frame sender identity.",
                closeConnection: true);
        }

        // 能力协商：仅授予请求 ∩ 服务端支持
        var granted = new HashSet<string>(
            handshake.Capabilities.Where(c => _server.SupportedCapabilities.Contains(c)),
            StringComparer.Ordinal);

        var result = new HandshakeResult
        {
            ProtocolVersion = _server.Protocol.ToString(),
            ComponentVersion = _server.ComponentVersion,
            Capabilities = granted.OrderBy(c => c, StringComparer.Ordinal).ToArray(),
            SessionTtlSeconds = _server.SessionTtlSeconds,
            ServerTimeUnix = _server.TimeProvider.GetUtcNow().ToUnixTimeSeconds(),
        };

        return new HandshakeOutcome(
            Accepted: true,
            Response: ResponseEnvelope.FromResult(result),
            CloseConnection: false,
            GrantedCapabilities: granted,
            SessionId: handshake.SessionId,
            Component: handshake.Component);
    }

    private HandshakeOutcome RejectInvalid(string reason) => HandshakeOutcome.Reject(
        IpcErrorCodes.InvalidArgument,
        reason,
        closeConnection: true);
}
