using Winknow.Core;
using Winknow.Core.Results;
using Winknow.Ipc;
using Winknow.Ipc.Session;

namespace Winknow.Ipc.Tests;

/// <summary>
/// M2-4 学生 SID 动态授权测试（ADR-002）：
/// 登录会话建立 → AllowSid(TTL≤8h)；过期显式 IpcSidExpired 且与未授权区分；
/// 注销/锁定的撤销语义由 DynamicSidAuthorizer 编排。
/// </summary>
public sealed class IpcDynamicAuthorizationTests
{
    private const string StudentSid = "S-1-5-21-3623811015-3361044348-30300820-4321";
    private const string DeviceId = "0123456789abcdef0123456789abcdef";

    /// <summary>可推进的时钟（测试专用）。</summary>
    private sealed class MutableTimeProvider(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _utcNow = start;

        public void Advance(TimeSpan delta) => _utcNow = _utcNow.Add(delta);

        public override DateTimeOffset GetUtcNow() => _utcNow;
    }

    private static IpcMessage Frame(uint requestId, string sid, long timestampMs) => new()
    {
        Version = IpcMessage.CurrentVersion,
        RequestId = requestId,
        Timestamp = timestampMs,
        Nonce = Guid.NewGuid().ToByteArray(),
        SenderSid = sid,
        MessageType = IpcConstants.MessageTypeHeartbeat,
        Payload = Array.Empty<byte>(),
    };

    private static long NowMs(TimeProvider time) => time.GetUtcNow().ToUnixTimeMilliseconds();

    [Fact]
    public void AllowSid_WithTtl_ValidBeforeExpiry_ExpiredAfter()
    {
        var time = new MutableTimeProvider(DateTimeOffset.UtcNow);
        var authenticator = new IpcAuthenticator(Array.Empty<string>(), DeviceId, time);
        authenticator.AllowSid(StudentSid, TimeSpan.FromHours(1));

        var valid = authenticator.ValidateMessage(Frame(1, StudentSid, NowMs(time)));
        Assert.True(valid.IsSuccess);

        time.Advance(TimeSpan.FromHours(1) + TimeSpan.FromSeconds(1));
        var expired = authenticator.ValidateMessage(Frame(2, StudentSid, NowMs(time)));
        Assert.False(expired.IsSuccess);
        Assert.Equal(ErrorCode.IpcSidExpired, expired.ErrorCode);

        // 过期条目已被移除：后续帧按"未授权"处理（与"已过期"显式区分）
        var afterward = authenticator.ValidateMessage(Frame(3, StudentSid, NowMs(time) + 1_000));
        Assert.False(afterward.IsSuccess);
        Assert.Equal(ErrorCode.Unauthorized, afterward.ErrorCode);
        Assert.DoesNotContain(StudentSid, authenticator.GetAllowedSids());
    }

    [Fact]
    public void AllowSid_StaticEntry_NeverExpires()
    {
        var time = new MutableTimeProvider(DateTimeOffset.UtcNow);
        var authenticator = new IpcAuthenticator(new[] { StudentSid }, DeviceId, time);

        time.Advance(TimeSpan.FromDays(365));
        var result = authenticator.ValidateMessage(Frame(1, StudentSid, NowMs(time)));
        Assert.True(result.IsSuccess);
        Assert.Contains(StudentSid, authenticator.GetAllowedSids());
    }

    [Fact]
    public void GetAllowedSids_HidesExpiredEntriesWithoutValidation()
    {
        var time = new MutableTimeProvider(DateTimeOffset.UtcNow);
        var authenticator = new IpcAuthenticator(Array.Empty<string>(), DeviceId, time);
        authenticator.AllowSid(StudentSid, TimeSpan.FromSeconds(30));

        time.Advance(TimeSpan.FromSeconds(31));
        Assert.DoesNotContain(StudentSid, authenticator.GetAllowedSids());
    }

    [Fact]
    public void AllowSid_NonPositiveTtl_Throws()
    {
        var authenticator = new IpcAuthenticator(Array.Empty<string>(), DeviceId);

        Assert.Throws<ArgumentOutOfRangeException>(() => authenticator.AllowSid(StudentSid, TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => authenticator.AllowSid(StudentSid, TimeSpan.FromMinutes(-1)));
    }

    [Fact]
    public void Authorizer_Logon_GrantsSid_Logoff_Revokes()
    {
        var authenticator = new IpcAuthenticator(Array.Empty<string>(), DeviceId);
        var authorizer = new DynamicSidAuthorizer(
            authenticator, sessionId => sessionId == 3 ? StudentSid : null);

        authorizer.HandleSessionChange(WtsSessionChangeKind.SessionLogon, 3);
        Assert.Contains(StudentSid, authenticator.GetAllowedSids());

        authorizer.HandleSessionChange(WtsSessionChangeKind.SessionLogoff, 3);
        Assert.DoesNotContain(StudentSid, authenticator.GetAllowedSids());
    }

    [Fact]
    public void Authorizer_LockAndDisconnect_DoNotRevoke()
    {
        var authenticator = new IpcAuthenticator(Array.Empty<string>(), DeviceId);
        var authorizer = new DynamicSidAuthorizer(
            authenticator, sessionId => sessionId == 3 ? StudentSid : null);

        authorizer.HandleSessionChange(WtsSessionChangeKind.SessionLogon, 3);

        authorizer.HandleSessionChange(WtsSessionChangeKind.SessionLock, 3);
        authorizer.HandleSessionChange(WtsSessionChangeKind.ConsoleDisconnect, 3);
        authorizer.HandleSessionChange(WtsSessionChangeKind.RemoteDisconnect, 3);
        Assert.Contains(StudentSid, authenticator.GetAllowedSids());
    }

    [Fact]
    public void Authorizer_LogonWithUnresolvableSid_NoGrantNoThrow()
    {
        var authenticator = new IpcAuthenticator(Array.Empty<string>(), DeviceId);
        var authorizer = new DynamicSidAuthorizer(authenticator, sessionId => null);

        authorizer.HandleSessionChange(WtsSessionChangeKind.SessionLogon, 42);

        Assert.DoesNotContain(StudentSid, authenticator.GetAllowedSids());
        Assert.Empty(authenticator.GetAllowedSids());
    }

    [Fact]
    public void Authorizer_TtlClampedToEightHours()
    {
        var time = new MutableTimeProvider(DateTimeOffset.UtcNow);
        var authenticator = new IpcAuthenticator(Array.Empty<string>(), DeviceId, time);
        var authorizer = new DynamicSidAuthorizer(authenticator, _ => StudentSid)
        {
            SessionTtl = TimeSpan.FromHours(10),
        };

        authorizer.HandleSessionChange(WtsSessionChangeKind.SessionLogon, 1);

        // 8 小时内有效（配置了 10h 也被截断到上限）
        time.Advance(TimeSpan.FromHours(8) - TimeSpan.FromSeconds(1));
        var stillValid = authenticator.ValidateMessage(Frame(1, StudentSid, NowMs(time)));
        Assert.True(stillValid.IsSuccess);

        time.Advance(TimeSpan.FromSeconds(2));
        var expired = authenticator.ValidateMessage(Frame(2, StudentSid, NowMs(time)));
        Assert.False(expired.IsSuccess);
        Assert.Equal(ErrorCode.IpcSidExpired, expired.ErrorCode);
    }

    [Fact]
    public void Authorizer_AuthorizeSession_ExplicitGrantWorks()
    {
        var time = new MutableTimeProvider(DateTimeOffset.UtcNow);
        var authenticator = new IpcAuthenticator(Array.Empty<string>(), DeviceId, time);
        var authorizer = new DynamicSidAuthorizer(authenticator);

        // 服务重启后恢复既有会话的路径（显式传入 sessionId 与 SID，无需解析器）
        authorizer.AuthorizeSession(1, StudentSid);

        var result = authenticator.ValidateMessage(Frame(1, StudentSid, NowMs(time)));
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Authorizer_LogoffWithoutPriorLogon_NoThrow()
    {
        var authenticator = new IpcAuthenticator(Array.Empty<string>(), DeviceId);
        var authorizer = new DynamicSidAuthorizer(authenticator, _ => null);

        authorizer.HandleSessionChange(WtsSessionChangeKind.SessionLogoff, 99);

        Assert.Empty(authenticator.GetAllowedSids());
    }
}
