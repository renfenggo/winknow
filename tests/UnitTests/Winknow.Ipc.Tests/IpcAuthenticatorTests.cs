using Winknow.Core;
using Winknow.Core.Results;
using Winknow.Ipc;

namespace Winknow.Ipc.Tests;

/// <summary>
/// IPC 身份验证和防重放测试。
///
/// 验收项：
/// - 普通学生自写程序不能发送管理命令（SID 校验）
/// - IPC 非法消息不导致服务崩溃（异常处理）
/// - 防重放（时间戳/RequestId/Nonce）
/// </summary>
public sealed class IpcAuthenticatorTests : IDisposable
{
    private const string AllowedSid = "S-1-5-21-100-200-300-1000";
    private const string AttackerSid = "S-1-5-21-999-888-777-6666";
    private const string TestDeviceId = "ABCDEF0123456789";
    private readonly IpcAuthenticator _authenticator;

    public IpcAuthenticatorTests()
    {
        _authenticator = new IpcAuthenticator(new[] { AllowedSid }, TestDeviceId);
    }

    [Fact]
    public void ValidateMessage_ValidMessage_ShouldSucceed()
    {
        var message = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), AllowedSid);
        var result = _authenticator.ValidateMessage(message);
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void ValidateMessage_UnauthorizedSid_ShouldReject()
    {
        // 验收项：普通学生自写程序不能发送管理命令
        var message = IpcMessage.Create(1, IpcConstants.MessageTypeAdminCommand, Array.Empty<byte>(), AttackerSid);
        var result = _authenticator.ValidateMessage(message);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.Unauthorized, result.ErrorCode);
    }

    [Fact]
    public void ValidateMessage_EmptySid_ShouldReject()
    {
        var message = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), "");
        var result = _authenticator.ValidateMessage(message);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.Unauthorized, result.ErrorCode);
    }

    [Fact]
    public void ValidateMessage_ReplayedRequestId_ShouldReject()
    {
        var msg1 = IpcMessage.Create(100, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), AllowedSid);
        var result1 = _authenticator.ValidateMessage(msg1);
        Assert.True(result1.IsSuccess);

        // 重放：RequestId 相同
        var msg2 = IpcMessage.Create(100, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), AllowedSid);
        var result2 = _authenticator.ValidateMessage(msg2);
        Assert.False(result2.IsSuccess);
        Assert.Equal(ErrorCode.IpcReplayDetected, result2.ErrorCode);
    }

    [Fact]
    public void ValidateMessage_LowerRequestId_ShouldReject()
    {
        var msg1 = IpcMessage.Create(200, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), AllowedSid);
        _authenticator.ValidateMessage(msg1);

        var msg2 = IpcMessage.Create(199, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), AllowedSid);
        var result2 = _authenticator.ValidateMessage(msg2);
        Assert.False(result2.IsSuccess);
        Assert.Equal(ErrorCode.IpcReplayDetected, result2.ErrorCode);
    }

    [Fact]
    public void ValidateMessage_ReplayedNonce_ShouldReject()
    {
        var nonce = new byte[16];
        Random.Shared.NextBytes(nonce);

        var msg1 = new IpcMessage
        {
            Version = IpcMessage.CurrentVersion,
            RequestId = 1,
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            Nonce = nonce,
            SenderSid = AllowedSid,
            MessageType = IpcConstants.MessageTypeHeartbeat,
            Payload = Array.Empty<byte>()
        };
        _authenticator.ValidateMessage(msg1);

        // 重放：相同 Nonce，不同 RequestId
        var msg2 = new IpcMessage
        {
            Version = msg1.Version,
            RequestId = 2,
            Timestamp = msg1.Timestamp,
            Nonce = msg1.Nonce,
            SenderSid = msg1.SenderSid,
            MessageType = msg1.MessageType,
            Payload = msg1.Payload
        };
        var result2 = _authenticator.ValidateMessage(msg2);
        Assert.False(result2.IsSuccess);
        Assert.Equal(ErrorCode.IpcReplayDetected, result2.ErrorCode);
    }

    [Fact]
    public void ValidateMessage_ExpiredTimestamp_ShouldReject()
    {
        var oldTimestamp = DateTimeOffset.UtcNow.AddSeconds(-120).ToUnixTimeMilliseconds();
        var message = new IpcMessage
        {
            Version = IpcMessage.CurrentVersion,
            RequestId = 1,
            Timestamp = oldTimestamp,
            Nonce = new byte[16],
            SenderSid = AllowedSid,
            MessageType = IpcConstants.MessageTypeHeartbeat,
            Payload = Array.Empty<byte>()
        };

        var result = _authenticator.ValidateMessage(message);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.IpcTimeout, result.ErrorCode);
    }

    [Fact]
    public void ValidateMessage_FutureTimestamp_ShouldReject()
    {
        var futureTimestamp = DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeMilliseconds();
        var message = new IpcMessage
        {
            Version = IpcMessage.CurrentVersion,
            RequestId = 1,
            Timestamp = futureTimestamp,
            Nonce = new byte[16],
            SenderSid = AllowedSid,
            MessageType = IpcConstants.MessageTypeHeartbeat,
            Payload = Array.Empty<byte>()
        };

        var result = _authenticator.ValidateMessage(message);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.IpcTimeout, result.ErrorCode);
    }

    [Fact]
    public void ValidateMessage_WrongVersion_ShouldReject()
    {
        var original = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), AllowedSid);
        var message = new IpcMessage
        {
            Version = 999,
            RequestId = original.RequestId,
            Timestamp = original.Timestamp,
            Nonce = original.Nonce,
            SenderSid = original.SenderSid,
            MessageType = original.MessageType,
            Payload = original.Payload
        };
        var result = _authenticator.ValidateMessage(message);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.IpcReplayDetected, result.ErrorCode);
    }

    [Fact]
    public void ValidateMessage_DeviceIdMismatch_ShouldReject()
    {
        var message = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), AllowedSid);
        var result = _authenticator.ValidateMessage(message, actualDeviceId: "WRONG_DEVICE_ID");
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.Unauthorized, result.ErrorCode);
    }

    [Fact]
    public void ValidateMessage_DeviceIdMatch_ShouldSucceed()
    {
        var message = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), AllowedSid);
        var result = _authenticator.ValidateMessage(message, actualDeviceId: TestDeviceId);
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void AllowSid_NewSid_ShouldBeAllowed()
    {
        var newSid = "S-1-5-21-555-666-777-8888";
        _authenticator.AllowSid(newSid);

        var message = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), newSid);
        var result = _authenticator.ValidateMessage(message);
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void RevokeSid_RemovedSid_ShouldReject()
    {
        var message1 = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), AllowedSid);
        _authenticator.ValidateMessage(message1);

        _authenticator.RevokeSid(AllowedSid);

        var message2 = IpcMessage.Create(2, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), AllowedSid);
        var result = _authenticator.ValidateMessage(message2);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.Unauthorized, result.ErrorCode);
    }

    [Fact]
    public void ValidateMessage_SequenceOfIncreasingRequestIds_ShouldAllSucceed()
    {
        for (uint i = 1; i <= 10; i++)
        {
            var message = IpcMessage.Create(i, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), AllowedSid);
            var result = _authenticator.ValidateMessage(message);
            Assert.True(result.IsSuccess, $"RequestId {i} should succeed.");
        }
    }

    [Fact]
    public void ValidateMessage_NullMessage_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => _authenticator.ValidateMessage(null!));
    }

    public void Dispose()
    {
        _authenticator.Dispose();
    }
}
