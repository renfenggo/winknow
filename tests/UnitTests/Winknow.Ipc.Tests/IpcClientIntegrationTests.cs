using System.Text;
using System.Text.Json;
using Winknow.DesktopBridge;
using Winknow.Ipc;
using Winknow.Ipc.Protocol;
using Winknow.Ipc.Session;

namespace Winknow.Ipc.Tests;

/// <summary>
/// M2-6 IpcClient 与 DesktopBridge 行协议集成测试（充当测试客户端，指导书 04 Exit Criteria）：
/// 进程内启动真实 IpcServer（随机管道名），客户端经完整帧协议握手 + 调用；
/// Bridge 行协议以 StringReader/StringWriter 端到端驱动（stderr 约定由 Program 承担）。
/// </summary>
public sealed class IpcClientIntegrationTests
{
    [Fact]
    public async Task Client_HandshakeAndInvoke_RoundTrip()
    {
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var server = await IpcTestHarness.StartServerAsync(pipeName, IpcTestHarness.CreateRegistry());
        await using var client = await IpcTestHarness.ConnectHandshakedClientAsync(
            pipeName, IpcTestHarness.Handshake(capabilities: "status.read"));

        var response = await client.InvokeAsync(new RequestEnvelope { Method = "system.get_status" });

        Assert.True(response.Ok);
        Assert.Equal("test-server", response.Result!.Value.GetProperty("component").GetString());
    }

    [Fact]
    public async Task Client_HandshakeVersionMismatch_RejectedExplicitly()
    {
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var server = await IpcTestHarness.StartServerAsync(pipeName, IpcTestHarness.CreateRegistry());
        await using var client = new IpcClient(pipeName);
        await client.ConnectAsync();

        var response = await client.HandshakeAsync(
            IpcTestHarness.Handshake(protocolVersion: "9.9", capabilities: "status.read"));

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcVersionMismatch, response.Error!.Code);
    }

    [Fact]
    public async Task Client_InvokeBeforeHandshake_ReturnsHandshakeRequired()
    {
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var server = await IpcTestHarness.StartServerAsync(pipeName, IpcTestHarness.CreateRegistry());
        await using var client = new IpcClient(pipeName);
        await client.ConnectAsync();

        var response = await client.InvokeAsync(new RequestEnvelope { Method = "system.get_status" });

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcHandshakeRequired, response.Error!.Code);
    }

    [Fact]
    public async Task Client_InvokeUnknownMethod_ReturnsIpcUnknownMethod()
    {
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var server = await IpcTestHarness.StartServerAsync(pipeName, IpcTestHarness.CreateRegistry());
        await using var client = await IpcTestHarness.ConnectHandshakedClientAsync(
            pipeName, IpcTestHarness.Handshake(capabilities: "status.read"));

        var response = await client.InvokeAsync(new RequestEnvelope { Method = "system.no_such" });

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcUnknownMethod, response.Error!.Code);
    }

    [Fact]
    public async Task Server_HandshakeBackfillsComponent_BridgeRoleMethodAllowed()
    {
        // system.get_status 仅 Bridge 角色可调（见 CreateRegistry）：
        // 若服务端不回填 session.Component，角色解析永远不是 Bridge → 拒绝
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var server = await IpcTestHarness.StartServerAsync(pipeName, IpcTestHarness.CreateRegistry());
        await using var client = await IpcTestHarness.ConnectHandshakedClientAsync(
            pipeName, IpcTestHarness.Handshake(component: "bridge", capabilities: "status.read"));

        var response = await client.InvokeAsync(new RequestEnvelope { Method = "system.get_status" });

        Assert.True(response.Ok);
    }

    [Fact]
    public async Task Server_SecondPipeInstanceCreatedAfterFirstClientConnected()
    {
        // 多实例根因回归：首个客户端接入后监听循环需创建第二个管道实例，
        // 若当前运行身份对既有管道对象无 CreatePipeInstance 权限将被拒绝
        // （生产 SYSTEM 不受影响；普通用户身份运行的测试/开发环境需要显式授权）
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var server = await IpcTestHarness.StartServerAsync(pipeName, IpcTestHarness.CreateRegistry());

        var first = await IpcTestHarness.ConnectHandshakedClientAsync(pipeName, IpcTestHarness.Handshake(capabilities: "status.read"));
        var firstResponse = await first.InvokeAsync(new RequestEnvelope { Method = "system.get_status" });
        Assert.True(firstResponse.Ok);

        await using var second = await IpcTestHarness.ConnectHandshakedClientAsync(pipeName, IpcTestHarness.Handshake(capabilities: "status.read"));
        var secondResponse = await second.InvokeAsync(new RequestEnvelope { Method = "system.get_status" });
        Assert.True(secondResponse.Ok, $"second client invoke failed: {secondResponse.Error?.Code} {secondResponse.Error?.Message}");

        await first.DisposeAsync();
    }

    [Fact]
    public async Task Server_RegressedRequestIdWithinConnection_RejectedAsReplay()
    {
        // 连接级 RequestId 单调检查（原 per-SID 全局检查会误杀同 SID 多客户端并发，
        // 已迁移到 IpcServer 会话层；跨连接重放由 Nonce 全局查重承担）
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var server = await IpcTestHarness.StartServerAsync(pipeName, IpcTestHarness.CreateRegistry());

        using var stream = await IpcTestHarness.ConnectRawAsync(pipeName);
        await IpcTestHarness.HandshakeRawAsync(stream);

        var invokePayload = new RequestEnvelope { Method = "system.get_status" }.Serialize();
        var okResponse = await IpcTestHarness.SendRawFrameAsync(stream,
            IpcMessage.Create(5010, IpcConstants.MessageTypeRequest, Encoding.UTF8.GetBytes(invokePayload)));
        Assert.True(okResponse.Ok);

        // 同一连接回退重发 RequestId = 5010（新 Nonce，绕不过连接级单调检查）
        var replayResponse = await IpcTestHarness.SendRawFrameAsync(stream,
            IpcMessage.Create(5010, IpcConstants.MessageTypeRequest, Encoding.UTF8.GetBytes(invokePayload)));
        Assert.False(replayResponse.Ok);
        Assert.Equal(IpcErrorCodes.IpcReplayDetected, replayResponse.Error!.Code);
    }

    [Fact]
    public async Task BridgeLineProtocol_EndToEnd_WithTestClient()
    {
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var server = await IpcTestHarness.StartServerAsync(pipeName, IpcTestHarness.CreateRegistry());
        await using var connection = new BridgeConnection(pipeName, IpcTestHarness.Handshake(capabilities: "status.read"));

        var input = new StringReader(string.Join('\n',
            "{\"id\":1,\"method\":\"system.get_status\",\"trace_id\":\"t-1\"}",
            "{\"id\":2,\"method\":\"system.no_such\"}",
            "not-json-at-all"));
        var output = new StringWriter();

        await BridgeLineProtocol.RunAsync(input, output, connection.InvokeAsync, CancellationToken.None);

        var lines = output.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(3, lines.Length);

        using var ok = JsonDocument.Parse(lines[0]);
        Assert.Equal(1, ok.RootElement.GetProperty("id").GetInt32());
        Assert.True(ok.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("test-server", ok.RootElement.GetProperty("result").GetProperty("component").GetString());
        Assert.Equal("t-1", ok.RootElement.GetProperty("trace_id").GetString());

        using var unknown = JsonDocument.Parse(lines[1]);
        Assert.Equal(2, unknown.RootElement.GetProperty("id").GetInt32());
        Assert.False(unknown.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal(IpcErrorCodes.IpcUnknownMethod,
            unknown.RootElement.GetProperty("error").GetProperty("code").GetString());

        using var malformed = JsonDocument.Parse(lines[2]);
        Assert.False(malformed.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal(IpcErrorCodes.InvalidArgument,
            malformed.RootElement.GetProperty("error").GetProperty("code").GetString());
        Assert.False(malformed.RootElement.TryGetProperty("id", out _));
    }

    [Fact]
    public async Task BridgeConnection_ServerUnreachable_ReturnsUnavailable()
    {
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var connection = new BridgeConnection(pipeName, IpcTestHarness.Handshake(capabilities: "status.read"));

        var response = await connection.InvokeAsync(
            new RequestEnvelope { Method = "system.get_status" }, CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.Unavailable, response.Error!.Code);
        Assert.True(response.Error.Retryable);
    }

    [Fact]
    public async Task BridgeConnection_HandshakeRejected_ReturnsUnavailable()
    {
        // 服务端在但设备 ID 不匹配：握手被显式拒绝，不得静默成功
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var server = await IpcTestHarness.StartServerAsync(pipeName, IpcTestHarness.CreateRegistry());
        await using var connection = new BridgeConnection(
            pipeName, IpcTestHarness.Handshake(deviceId: "wrong-device-999", capabilities: "status.read"));

        var response = await connection.InvokeAsync(
            new RequestEnvelope { Method = "system.get_status" }, CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.Unavailable, response.Error!.Code);
    }
}
