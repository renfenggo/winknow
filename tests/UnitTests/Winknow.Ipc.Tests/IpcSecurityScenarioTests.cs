using System.Text;
using Winknow.Ipc;
using Winknow.Ipc.Commands;
using Winknow.Ipc.Protocol;

namespace Winknow.Ipc.Tests;

/// <summary>
/// M2-8 安全测试套件（指导书 04 Tests 十类场景的集成级覆盖）：
/// 真实命名管道 + 完整帧协议 + 白名单注册表，逐类验证跨边界拒绝行为。
/// 单元级覆盖见 IpcAuthenticatorTests / IpcHandshakeValidatorTests / IpcCommandRegistryTests。
/// </summary>
public sealed class IpcSecurityScenarioTests
{
    private const string SystemSid = "S-1-5-18";

    private static uint _requestId = 10_000;

    private static uint NextRequestId() => ++_requestId;

    private static IpcCommandRegistry CreateRegistry()
    {
        var registry = new IpcCommandRegistry(sid => sid == SystemSid);
        registry.Register(new IpcCommandSpec
        {
            Method = "system.get_status",
            RequiredCapability = "status.read",
            AllowedRoles = new HashSet<IpcCallerRole> { IpcCallerRole.Bridge },
            Timeout = TimeSpan.FromSeconds(5),
            AuditLevel = "meta",
            Handler = (_, _) => Task.FromResult(ResponseEnvelope.FromResult(new { component = "test-server" })),
        });
        registry.Register(new IpcCommandSpec
        {
            Method = "classroom.begin",
            RequiredCapability = "classroom.control",
            AllowedRoles = new HashSet<IpcCallerRole> { IpcCallerRole.System },
            Timeout = TimeSpan.FromSeconds(5),
            AuditLevel = "full",
            Handler = (_, _) => Task.FromResult(ResponseEnvelope.FromResult(new { started = true })),
        });
        return registry;
    }

    private static byte[] RequestPayload(string method) =>
        Encoding.UTF8.GetBytes(new RequestEnvelope { Method = method }.Serialize());

    [Fact]
    public async Task Sec3_UnauthorizedSidOnWire_FrameRejected()
    {
        // 场景：未授权 SID。帧头 SenderSid 声称 SYSTEM（在白名单）但管道
        // impersonation 身份是当前测试用户 → 身份不一致显式拒绝
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        using var authenticator = new IpcAuthenticator(
            new[] { IpcTestHarness.CurrentSid, SystemSid }, IpcTestHarness.DeviceId);
        await using var server = await IpcTestHarness.StartServerAsync(pipeName, CreateRegistry(), authenticator);

        using var stream = await IpcTestHarness.ConnectRawAsync(pipeName);

        var response = await IpcTestHarness.SendRawFrameAsync(stream,
            IpcMessage.Create(NextRequestId(), IpcConstants.MessageTypeHeartbeat,
                Array.Empty<byte>(), senderSid: SystemSid));

        // 帧级拒绝（服务端 MessageReceived + Ack 兼容路径下的身份校验失败）
        // 心跳帧错误信封帧类型仍为 Response
        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcSidNotAuthorized, response.Error!.Code);
    }

    [Fact]
    public async Task Sec4_ExpiredDynamicSid_FrameRejectedWithSidExpired()
    {
        // 场景：过期 SID。动态授权 TTL 极短，过期后帧被拒且显式区分 IPC_SID_EXPIRED
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        using var authenticator = new IpcAuthenticator(Array.Empty<string>(), IpcTestHarness.DeviceId);
        await using var server = await IpcTestHarness.StartServerAsync(pipeName, CreateRegistry(), authenticator);

        authenticator.AllowSid(IpcTestHarness.CurrentSid, TimeSpan.FromMilliseconds(1));
        await Task.Delay(50);

        using var stream = await IpcTestHarness.ConnectRawAsync(pipeName);
        var response = await IpcTestHarness.SendRawFrameAsync(stream,
            IpcMessage.Create(NextRequestId(), IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>()));

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcSidExpired, response.Error!.Code);
    }

    [Fact]
    public async Task Sec5_CrossConnectionReplay_NonceRejected()
    {
        // 场景：replay（跨连接）。捕获完整原始帧字节，在第二条连接原样重发：
        // Nonce 全局查重（跨连接）必须拒绝；服务端不崩溃
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var server = await IpcTestHarness.StartServerAsync(pipeName, CreateRegistry());

        byte[] captured;
        using (var first = await IpcTestHarness.ConnectRawAsync(pipeName))
        {
            await IpcTestHarness.HandshakeRawAsync(first);
            captured = IpcMessage.Create(
                NextRequestId(), IpcConstants.MessageTypeRequest, RequestPayload("system.get_status")).ToBytes();

            // 先正常发送一次（消耗 Nonce）
            var ok = await IpcTestHarness.SendRawFrameAsync(first, IpcMessage.FromBytes(captured));
            Assert.True(ok.Ok);
        }

        using var second = await IpcTestHarness.ConnectRawAsync(pipeName);
        await IpcTestHarness.HandshakeRawAsync(second);

        var replayFrame = IpcMessage.FromBytes(captured);
        var replayResponse = await IpcTestHarness.SendRawFrameAsync(second, replayFrame);

        Assert.False(replayResponse.Ok);
        Assert.Equal(IpcErrorCodes.IpcSidNotAuthorized, replayResponse.Error!.Code);
    }

    [Fact]
    public async Task Sec7_MalformedRequestPayload_RejectedConnectionSurvives()
    {
        // 场景：malformed payload。业务帧 payload 非法 JSON：
        // 返回错误信封且连接保持可用（后续合法调用仍成功）
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var server = await IpcTestHarness.StartServerAsync(pipeName, CreateRegistry());

        using var stream = await IpcTestHarness.ConnectRawAsync(pipeName);
        await IpcTestHarness.HandshakeRawAsync(stream);

        var malformed = await IpcTestHarness.SendRawFrameAsync(stream,
            IpcMessage.Create(NextRequestId(), IpcConstants.MessageTypeRequest,
                Encoding.UTF8.GetBytes("not-a-json-envelope")));
        Assert.False(malformed.Ok);

        var recovered = await IpcTestHarness.SendRawFrameAsync(stream,
            IpcMessage.Create(NextRequestId(), IpcConstants.MessageTypeRequest, RequestPayload("system.get_status")));
        Assert.True(recovered.Ok, $"connection should survive malformed payload: {recovered.Error?.Code}");
    }

    [Fact]
    public async Task Sec10_CapabilityMismatch_MethodNeedsUnnegotiatedCapability()
    {
        // 场景：capability mismatch。Bridge 角色被允许调用 system.get_status，
        // 但握手未申请 status.read（分发顺序：角色 → capability）→ IPC_CAPABILITY_MISMATCH
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var server = await IpcTestHarness.StartServerAsync(pipeName, CreateRegistry());

        using var stream = await IpcTestHarness.ConnectRawAsync(pipeName);
        await IpcTestHarness.HandshakeRawAsync(stream, IpcTestHarness.Handshake(capabilities: "device.read"));

        var response = await IpcTestHarness.SendRawFrameAsync(stream,
            IpcMessage.Create(NextRequestId(), IpcConstants.MessageTypeRequest, RequestPayload("system.get_status")));

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcCapabilityMismatch, response.Error!.Code);
    }

    [Fact]
    public async Task Sec8_PermissionDenied_RoleNotAllowed()
    {
        // 场景：permission denied。Bridge 身份调用 system-only 方法：
        // capability 已协商但角色不符 → IPC_SID_NOT_AUTHORIZED + denied_reason
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var server = await IpcTestHarness.StartServerAsync(pipeName, CreateRegistry());

        using var stream = await IpcTestHarness.ConnectRawAsync(pipeName);
        await IpcTestHarness.HandshakeRawAsync(stream,
            IpcTestHarness.Handshake(capabilities: "classroom.control"));

        var response = await IpcTestHarness.SendRawFrameAsync(stream,
            IpcMessage.Create(NextRequestId(), IpcConstants.MessageTypeRequest, RequestPayload("classroom.begin")));

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcSidNotAuthorized, response.Error!.Code);
        Assert.NotNull(response.Error.Details);
        Assert.True(response.Error.Details.ContainsKey("denied_reason"));
    }
}
