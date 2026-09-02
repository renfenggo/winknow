using Winknow.Core;
using Winknow.Core.Results;
using Winknow.Ipc;

namespace Winknow.Ipc.Tests;

/// <summary>
/// IPC 身份验证和防重放测试（P2-01 realSid 制）。
///
/// 验收项：
/// - 身份唯一凭证是服务端 Impersonation 取得的真实 SID（realSid 参数）
/// - 消息体 SenderSid 与真实 SID 不一致（伪造）→ 拒绝
/// - 真实 SID 不在允许集合（如学生自写程序）→ 拒绝
/// - 防重放（时间戳/Nonce）；RequestId 单调性由 IpcConnectionGuard 按连接维护（另测）
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
        var result = _authenticator.ValidateMessage(message, realSid: AllowedSid);
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void ValidateMessage_ImpersonatedSidNotInAllowedSet_ShouldReject()
    {
        // 验收项：真实 SID（Impersonation）不在允许集合 → 拒绝，无论消息体声明什么
        var message = IpcMessage.Create(1, IpcConstants.MessageTypeAdminCommand, Array.Empty<byte>(), AttackerSid);
        var result = _authenticator.ValidateMessage(message, realSid: AttackerSid);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.Unauthorized, result.ErrorCode);
    }

    [Fact]
    public void ValidateMessage_ClaimedSidMismatchWithImpersonated_ShouldReject()
    {
        // 验收项：攻击者连接（真实 SID = AttackerSid），但消息体声称自己是 AllowedSid → 拒绝
        var message = IpcMessage.Create(1, IpcConstants.MessageTypeAdminCommand, Array.Empty<byte>(), AllowedSid);
        var result = _authenticator.ValidateMessage(message, realSid: AttackerSid);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.Unauthorized, result.ErrorCode);
    }

    [Fact]
    public void ValidateMessage_EmptyClaimedSid_ShouldReject()
    {
        var message = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), "");
        var result = _authenticator.ValidateMessage(message, realSid: AllowedSid);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.Unauthorized, result.ErrorCode);
    }

    [Fact]
    public void ValidateMessage_ErrorTypeInbound_ShouldReject()
    {
        // 验收项：伪造 Error 消息注入 → 拒绝
        var message = IpcMessage.Create(1, IpcConstants.MessageTypeError, Array.Empty<byte>(), AllowedSid);
        var result = _authenticator.ValidateMessage(message, realSid: AllowedSid);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.InvalidParameter, result.ErrorCode);
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
        Assert.True(_authenticator.ValidateMessage(msg1, realSid: AllowedSid).IsSuccess);

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
        var result2 = _authenticator.ValidateMessage(msg2, realSid: AllowedSid);
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

        var result = _authenticator.ValidateMessage(message, realSid: AllowedSid);
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

        var result = _authenticator.ValidateMessage(message, realSid: AllowedSid);
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
        var result = _authenticator.ValidateMessage(message, realSid: AllowedSid);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.IpcReplayDetected, result.ErrorCode);
    }

    [Fact]
    public void ValidateMessage_DeviceIdMismatch_ShouldReject()
    {
        var message = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), AllowedSid);
        var result = _authenticator.ValidateMessage(message, realSid: AllowedSid, actualDeviceId: "WRONG_DEVICE_ID");
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.Unauthorized, result.ErrorCode);
    }

    [Fact]
    public void ValidateMessage_DeviceIdMatch_ShouldSucceed()
    {
        var message = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), AllowedSid);
        var result = _authenticator.ValidateMessage(message, realSid: AllowedSid, actualDeviceId: TestDeviceId);
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void AllowSid_NewSid_ShouldBeAllowed()
    {
        var newSid = "S-1-5-21-555-666-777-8888";
        _authenticator.AllowSid(newSid);

        var message = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), newSid);
        var result = _authenticator.ValidateMessage(message, realSid: newSid);
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void RevokeSid_RemovedSid_ShouldReject()
    {
        var message1 = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), AllowedSid);
        _authenticator.ValidateMessage(message1, realSid: AllowedSid);

        _authenticator.RevokeSid(AllowedSid);

        var message2 = IpcMessage.Create(2, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), AllowedSid);
        var result = _authenticator.ValidateMessage(message2, realSid: AllowedSid);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.Unauthorized, result.ErrorCode);
    }

    [Fact]
    public void IsSidAllowed_ReflectsAllowedSet()
    {
        Assert.True(_authenticator.IsSidAllowed(AllowedSid));
        Assert.False(_authenticator.IsSidAllowed(AttackerSid));
    }

    [Fact]
    public void ValidateMessage_SequenceOfIncreasingRequestIds_ShouldAllSucceed()
    {
        // RequestId 单调性已移交 IpcConnectionGuard（连接级）；此处验证 authenticator 不再拦截同号消息
        for (uint i = 1; i <= 3; i++)
        {
            var message = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), AllowedSid);
            var result = _authenticator.ValidateMessage(message, realSid: AllowedSid);
            Assert.True(result.IsSuccess, $"Message {i} should pass authenticator (nonce differs per message).");
        }
    }

    [Fact]
    public void ValidateMessage_NullArguments_ShouldThrow()
    {
        var message = IpcMessage.Create(1, IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), AllowedSid);
        Assert.Throws<ArgumentNullException>(() => _authenticator.ValidateMessage(null!, realSid: AllowedSid));
        Assert.Throws<ArgumentException>(() => _authenticator.ValidateMessage(message, realSid: ""));
    }

    public void Dispose()
    {
        _authenticator.Dispose();
    }
}
