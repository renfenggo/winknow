using System.Buffers.Binary;
using System.Text;
using Winknow.Ipc;

namespace Winknow.Ipc.Tests;

/// <summary>
/// IPC 消息序列化/反序列化测试。
/// </summary>
public sealed class IpcMessageTests
{
    private const string TestSid = "S-1-5-21-100-200-300-1000";

    [Fact]
    public void RoundTrip_ShouldPreserveAllFields()
    {
        var original = IpcMessage.Create(
            requestId: 42,
            messageType: IpcConstants.MessageTypeHeartbeat,
            payload: Encoding.UTF8.GetBytes("test payload"),
            senderSid: TestSid);

        var bytes = original.ToBytes();
        var restored = IpcMessage.FromBytes(bytes);

        Assert.Equal(original.Version, restored.Version);
        Assert.Equal(original.RequestId, restored.RequestId);
        Assert.Equal(original.Timestamp, restored.Timestamp);
        Assert.Equal(original.Nonce, restored.Nonce);
        Assert.Equal(original.SenderSid, restored.SenderSid);
        Assert.Equal(original.MessageType, restored.MessageType);
        Assert.Equal(original.Payload, restored.Payload);
    }

    [Fact]
    public void FromBytes_TooShortBuffer_ShouldThrow()
    {
        var shortBuffer = new byte[10];
        Assert.Throws<InvalidDataException>(() => IpcMessage.FromBytes(shortBuffer));
    }

    [Fact]
    public void FromBytes_PayloadExceedsBuffer_ShouldThrow()
    {
        var message = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, new byte[100], TestSid);
        var bytes = message.ToBytes();

        // 计算 PayloadLength 字段的偏移量
        var sidByteLength = Encoding.UTF8.GetByteCount(TestSid);
        var payloadLengthOffset = 2 + 4 + 8 + 16 + 2 + sidByteLength + 2; // 头部+SID长度+SID+MessageType

        // 篡改 PayloadLength 为超大值
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(payloadLengthOffset), 0xFFFFFFFF);

        Assert.Throws<InvalidDataException>(() => IpcMessage.FromBytes(bytes));
    }

    [Fact]
    public void Create_ShouldSetCurrentVersion()
    {
        var message = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), TestSid);
        Assert.Equal(IpcMessage.CurrentVersion, message.Version);
    }

    [Fact]
    public void Create_ShouldGenerate16ByteNonce()
    {
        var message = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), TestSid);
        Assert.Equal(16, message.Nonce.Length);
    }

    [Fact]
    public void Create_TwoMessagesShouldHaveDifferentNonces()
    {
        var msg1 = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), TestSid);
        var msg2 = IpcMessage.Create(2, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), TestSid);
        Assert.NotEqual(msg1.Nonce, msg2.Nonce);
    }
}
