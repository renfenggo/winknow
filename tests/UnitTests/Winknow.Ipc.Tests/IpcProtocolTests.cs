using Winknow.Ipc;

namespace Winknow.Ipc.Tests;

/// <summary>
/// P2-04 最小消息协议：载荷 DTO 编解码（camelCase JSON）。
/// </summary>
public sealed class IpcProtocolTests
{
    [Fact]
    public void HelloPayload_RoundTrip_ShouldPreserveFields()
    {
        var hello = new HelloPayload
        {
            ProtocolVersion = IpcMessage.CurrentVersion,
            Pid = 1234,
            SessionId = 2,
            DeviceId = "DEV123",
            ClientNonce = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 }),
            ClientVersion = "7.0.1"
        };

        var decoded = IpcProtocol.Decode<HelloPayload>(IpcProtocol.Encode(hello));

        Assert.NotNull(decoded);
        Assert.Equal(hello.ProtocolVersion, decoded.ProtocolVersion);
        Assert.Equal(hello.Pid, decoded.Pid);
        Assert.Equal(hello.SessionId, decoded.SessionId);
        Assert.Equal(hello.DeviceId, decoded.DeviceId);
        Assert.Equal(hello.ClientNonce, decoded.ClientNonce);
        Assert.Equal(hello.ClientVersion, decoded.ClientVersion);
    }

    [Fact]
    public void Encode_ShouldUseCamelCase()
    {
        var payload = new HelloAckPayload
        {
            ProtocolVersion = 1,
            Granted = true,
            ServerNonce = "nonce"
        };

        var json = System.Text.Encoding.UTF8.GetString(IpcProtocol.Encode(payload));

        Assert.Contains("\"granted\":true", json);
        Assert.Contains("\"serverNonce\":\"nonce\"", json);
    }

    [Fact]
    public void Decode_InvalidJson_ShouldReturnNull()
    {
        Assert.Null(IpcProtocol.Decode<HelloPayload>(System.Text.Encoding.UTF8.GetBytes("{ not json")));
    }

    [Fact]
    public void Decode_EmptyPayload_ShouldReturnNull()
    {
        Assert.Throws<ArgumentNullException>(() => IpcProtocol.Decode<HelloPayload>(null!));
    }

    [Fact]
    public void StatusAckPayload_RoundTrip_ShouldPreserveFields()
    {
        var ack = new StatusAckPayload
        {
            Version = "7.0.0",
            IsLocked = true,
            UptimeSeconds = 42,
            PolicyVersion = "v1"
        };

        var decoded = IpcProtocol.Decode<StatusAckPayload>(IpcProtocol.Encode(ack));

        Assert.NotNull(decoded);
        Assert.Equal(ack.Version, decoded.Version);
        Assert.True(decoded.IsLocked);
        Assert.Equal(42U, (uint)decoded.UptimeSeconds);
        Assert.Equal("v1", decoded.PolicyVersion);
    }

    [Fact]
    public void LockPayload_NullReason_ShouldBeOmitted()
    {
        var payload = new LockPayload { PolicyVersion = "v9" };
        var json = System.Text.Encoding.UTF8.GetString(IpcProtocol.Encode(payload));
        Assert.DoesNotContain("reason", json);
    }
}
