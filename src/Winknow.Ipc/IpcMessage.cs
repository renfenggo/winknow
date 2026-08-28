using System.Buffers.Binary;
using System.Security.Principal;
using System.Text;
using Winknow.Core;

namespace Winknow.Ipc;

/// <summary>
/// IPC 消息协议结构（见《V7.0 组件架构设计》第 6.3 节）。
///
/// 二进制布局（小端序）：
///   偏移 0:  Version         (uint16)  协议版本
///   偏移 2:  RequestId       (uint32)  请求号，单调递增
///   偏移 6:  Timestamp       (int64)   Unix 毫秒时间戳
///   偏移 14: Nonce           (16字节)  随机数
///   偏移 30: SenderSidLength (uint16)  发送方 SID 字节长度
///   偏移 32: SenderSid       (变长)    发送方 SID（UTF-8）
///   偏移 N:  MessageType     (uint16)  消息类型
///   偏移 N+2: PayloadLength  (uint32)  载荷长度
///   偏移 N+6: Payload        (变长)    载荷（JSON 或二进制）
///
/// 防重放规则：
/// - 时间戳偏差超过 ±60 秒 → 拒绝
/// - RequestId 必须大于上次收到的值
/// - Nonce 在 5 分钟内不得重复
/// - DeviceId 必须与本机匹配（外部校验，本结构不包含）
/// </summary>
public sealed class IpcMessage
{
    /// <summary>当前协议版本。</summary>
    public const ushort CurrentVersion = 1;

    /// <summary>固定头部长度（Version + RequestId + Timestamp + Nonce）。</summary>
    private const int FixedHeaderLength = 2 + 4 + 8 + 16;

    /// <summary>获取协议版本。</summary>
    public ushort Version { get; init; }

    /// <summary>获取请求号（单调递增）。</summary>
    public uint RequestId { get; init; }

    /// <summary>获取 Unix 毫秒时间戳。</summary>
    public long Timestamp { get; init; }

    /// <summary>获取 16 字节随机数。</summary>
    public byte[] Nonce { get; init; } = new byte[16];

    /// <summary>获取发送方 SID。</summary>
    public string SenderSid { get; init; } = string.Empty;

    /// <summary>获取消息类型。</summary>
    public ushort MessageType { get; init; }

    /// <summary>获取载荷。</summary>
    public byte[] Payload { get; init; } = Array.Empty<byte>();

    /// <summary>创建新消息。</summary>
    public static IpcMessage Create(uint requestId, ushort messageType, byte[] payload, string? senderSid = null)
    {
        return new IpcMessage
        {
            Version = CurrentVersion,
            RequestId = requestId,
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            Nonce = SecurityUtils.GenerateNonce(),
            SenderSid = senderSid ?? WindowsIdentity.GetCurrent().User?.Value ?? string.Empty,
            MessageType = messageType,
            Payload = payload
        };
    }

    /// <summary>序列化为字节数组。</summary>
    public byte[] ToBytes()
    {
        var sidBytes = Encoding.UTF8.GetBytes(SenderSid);
        if (sidBytes.Length > ushort.MaxValue)
        {
            throw new InvalidOperationException("Sender SID exceeds maximum length.");
        }

        var totalLength = FixedHeaderLength + 2 + sidBytes.Length + 2 + 4 + Payload.Length;
        var buffer = new byte[totalLength];
        var span = buffer.AsSpan();

        var offset = 0;
        BinaryPrimitives.WriteUInt16LittleEndian(span[offset..], Version); offset += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(span[offset..], RequestId); offset += 4;
        BinaryPrimitives.WriteInt64LittleEndian(span[offset..], Timestamp); offset += 8;
        Nonce.AsSpan().CopyTo(span[offset..]); offset += 16;
        BinaryPrimitives.WriteUInt16LittleEndian(span[offset..], (ushort)sidBytes.Length); offset += 2;
        sidBytes.AsSpan().CopyTo(span[offset..]); offset += sidBytes.Length;
        BinaryPrimitives.WriteUInt16LittleEndian(span[offset..], MessageType); offset += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(span[offset..], (uint)Payload.Length); offset += 4;
        Payload.AsSpan().CopyTo(span[offset..]);

        return buffer;
    }

    /// <summary>从字节数组反序列化。</summary>
    public static IpcMessage FromBytes(byte[] buffer)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        if (buffer.Length < FixedHeaderLength + 4)
        {
            throw new InvalidDataException("IPC message buffer is too short.");
        }

        var span = buffer.AsSpan();
        var offset = 0;

        var version = BinaryPrimitives.ReadUInt16LittleEndian(span[offset..]); offset += 2;
        var requestId = BinaryPrimitives.ReadUInt32LittleEndian(span[offset..]); offset += 4;
        var timestamp = BinaryPrimitives.ReadInt64LittleEndian(span[offset..]); offset += 8;

        var nonce = new byte[16];
        span.Slice(offset, 16).CopyTo(nonce); offset += 16;

        var sidLength = BinaryPrimitives.ReadUInt16LittleEndian(span[offset..]); offset += 2;
        if (offset + sidLength + 6 > buffer.Length)
        {
            throw new InvalidDataException("IPC message SID length exceeds buffer bounds.");
        }

        var senderSid = Encoding.UTF8.GetString(span.Slice(offset, sidLength)); offset += sidLength;

        var messageType = BinaryPrimitives.ReadUInt16LittleEndian(span[offset..]); offset += 2;
        var payloadLength = BinaryPrimitives.ReadUInt32LittleEndian(span[offset..]); offset += 4;

        // 防止恶意超大 PayloadLength（包括负数溢出）
        if (payloadLength == 0 || payloadLength > (uint)IpcConstants.MaxMessageLength ||
            offset + payloadLength > (uint)buffer.Length)
        {
            throw new InvalidDataException("IPC message payload length exceeds buffer bounds.");
        }

        var payload = new byte[payloadLength];
        span.Slice(offset, (int)payloadLength).CopyTo(payload);

        return new IpcMessage
        {
            Version = version,
            RequestId = requestId,
            Timestamp = timestamp,
            Nonce = nonce,
            SenderSid = senderSid,
            MessageType = messageType,
            Payload = payload
        };
    }
}
