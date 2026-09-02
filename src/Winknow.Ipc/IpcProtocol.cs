using System.Text.Json;
using System.Text.Json.Serialization;

namespace Winknow.Ipc;

/// <summary>
/// V7 最小消息协议的载荷 DTO 与编解码（P2-04）。
///
/// 所有载荷使用 camelCase JSON（UTF-8）。
/// 握手（Hello/HelloAck）绑定协议版本、PID、SessionId、DeviceId 与双方随机挑战（TD-05）。
/// </summary>
public static class IpcProtocol
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>序列化任意协议载荷。</summary>
    public static byte[] Encode<T>(T payload) where T : class
    {
        ArgumentNullException.ThrowIfNull(payload);
        return JsonSerializer.SerializeToUtf8Bytes(payload, Options);
    }

    /// <summary>反序列化协议载荷；失败返回 null（调用方拒绝并审计）。</summary>
    public static T? Decode<T>(byte[] payload) where T : class
    {
        ArgumentNullException.ThrowIfNull(payload);
        try
        {
            return JsonSerializer.Deserialize<T>(payload, Options);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>
/// 握手请求（Agent → Service，连接后首条消息）。
/// SenderSid 仅用于审计；身份以服务端 Impersonation 取得的真实 SID 为准。
/// </summary>
public sealed class HelloPayload
{
    /// <summary>客户端声明的协议版本（必须等于 IpcMessage.CurrentVersion）。</summary>
    public ushort ProtocolVersion { get; init; }

    /// <summary>客户端进程 PID（用于会话登记与审计）。</summary>
    public int Pid { get; init; }

    /// <summary>客户端所在 WTS 会话 ID。</summary>
    public int SessionId { get; init; }

    /// <summary>客户端设备 ID（服务端校验与本机一致）。</summary>
    public string DeviceId { get; init; } = string.Empty;

    /// <summary>客户端随机挑战（base64，16 字节）。</summary>
    public string ClientNonce { get; init; } = string.Empty;

    /// <summary>客户端组件版本（如 Agent 版本号）。</summary>
    public string ClientVersion { get; init; } = string.Empty;
}

/// <summary>
/// 握手应答（Service → Agent）。
/// </summary>
public sealed class HelloAckPayload
{
    /// <summary>服务端协议版本。</summary>
    public ushort ProtocolVersion { get; init; }

    /// <summary>是否授予连接（false 时客户端必须断开）。</summary>
    public bool Granted { get; init; }

    /// <summary>拒绝原因（Granted=false 时非空）。</summary>
    public string? Reason { get; init; }

    /// <summary>服务端随机挑战（base64，16 字节）；本连接会话的 RequestId 防重放边界随之建立。</summary>
    public string ServerNonce { get; init; } = string.Empty;
}

/// <summary>锁屏显示载荷（ShowLock）。</summary>
public sealed class LockPayload
{
    /// <summary>锁定原因（展示给学生，不包含敏感信息；null 时序列化省略）。</summary>
    public string? Reason { get; init; }

    /// <summary>触发锁定的策略版本（审计关联）。</summary>
    public string PolicyVersion { get; init; } = string.Empty;
}

/// <summary>状态查询请求载荷（Status）。</summary>
public sealed class StatusQueryPayload
{
    /// <summary>查询方感兴趣的能力域（保留字段）。</summary>
    public string? Scope { get; init; }
}

/// <summary>状态查询应答载荷（StatusAck）。</summary>
public sealed class StatusAckPayload
{
    /// <summary>应答方组件版本。</summary>
    public string Version { get; init; } = string.Empty;

    /// <summary>是否处于锁屏状态（Agent 应答）。</summary>
    public bool IsLocked { get; init; }

    /// <summary>进程存活时长（秒）。</summary>
    public long UptimeSeconds { get; init; }

    /// <summary>策略版本（最近一次 ApplyPolicy 收到的版本）。</summary>
    public string PolicyVersion { get; init; } = string.Empty;
}
