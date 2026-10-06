using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Winknow.DesktopBridge;
using Winknow.Ipc;
using Winknow.Ipc.Commands;
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
    private const string DeviceId = "itest-device-0001";

    private static string CurrentSid => WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;

    private static HandshakeParams Handshake(string deviceId = DeviceId, string component = "bridge",
        string protocolVersion = "1.0", params string[] capabilities) => new()
    {
        ProtocolVersion = protocolVersion,
        Component = component,
        ComponentVersion = "test-client",
        Capabilities = capabilities,
        DeviceId = deviceId,
        CallerSid = CurrentSid,
        SessionId = "itest-session-1",
    };

    private static IpcCommandRegistry CreateRegistry()
    {
        var registry = new IpcCommandRegistry(sid => sid == "S-1-5-18");
        registry.Register(new IpcCommandSpec
        {
            Method = "system.get_status",
            RequiredCapability = "status.read",
            // 仅 Bridge 角色：验证服务端把握手 component 回填进会话（M2-6 修复）
            AllowedRoles = new HashSet<IpcCallerRole> { IpcCallerRole.Bridge },
            Timeout = TimeSpan.FromSeconds(5),
            AuditLevel = "meta",
            Handler = (_, _) => Task.FromResult(ResponseEnvelope.FromResult(new { component = "test-server" })),
        });
        return registry;
    }

    private static async Task<IpcServer> StartServerAsync(string pipeName, IpcCommandRegistry registry, string deviceId = DeviceId)
    {
        var authenticator = new IpcAuthenticator(new[] { CurrentSid }, deviceId);
        var descriptor = new IpcServerDescriptor
        {
            ComponentVersion = "test-server",
            SupportedCapabilities = new HashSet<string>(StringComparer.Ordinal)
            {
                "status.read", "device.read", "runner.read",
            },
            DeviceId = deviceId,
        };
        var server = new IpcServer(pipeName, authenticator, new IpcHandshakeValidator(descriptor));
        server.RequestReceived += (context, ct) =>
        {
            var json = Encoding.UTF8.GetString(context.Message.Payload);
            var request = RequestEnvelope.Deserialize(json)
                ?? new RequestEnvelope { Method = string.Empty };
            return registry.DispatchAsync(request, context.Session, ct, context.Message.RequestId);
        };
        await server.StartAsync();
        return server;
    }

    private static async Task<IpcClient> ConnectHandshakedClientAsync(
        string pipeName, HandshakeParams handshake)
    {
        var client = new IpcClient(pipeName);
        await client.ConnectAsync();
        var handshakeResponse = await client.HandshakeAsync(handshake);
        Assert.True(handshakeResponse.Ok, $"handshake failed: {handshakeResponse.Error?.Code}");
        return client;
    }

    [Fact]
    public async Task Client_HandshakeAndInvoke_RoundTrip()
    {
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var server = await StartServerAsync(pipeName, CreateRegistry());
        await using var client = await ConnectHandshakedClientAsync(
            pipeName, Handshake(capabilities: "status.read"));

        var response = await client.InvokeAsync(new RequestEnvelope { Method = "system.get_status" });

        Assert.True(response.Ok);
        Assert.Equal("test-server", response.Result!.Value.GetProperty("component").GetString());
    }

    [Fact]
    public async Task Client_HandshakeVersionMismatch_RejectedExplicitly()
    {
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var server = await StartServerAsync(pipeName, CreateRegistry());
        await using var client = new IpcClient(pipeName);
        await client.ConnectAsync();

        var response = await client.HandshakeAsync(Handshake(protocolVersion: "9.9", capabilities: "status.read"));

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcVersionMismatch, response.Error!.Code);
    }

    [Fact]
    public async Task Client_InvokeBeforeHandshake_ReturnsHandshakeRequired()
    {
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var server = await StartServerAsync(pipeName, CreateRegistry());
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
        await using var server = await StartServerAsync(pipeName, CreateRegistry());
        await using var client = await ConnectHandshakedClientAsync(
            pipeName, Handshake(capabilities: "status.read"));

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
        await using var server = await StartServerAsync(pipeName, CreateRegistry());
        await using var client = await ConnectHandshakedClientAsync(
            pipeName, Handshake(component: "bridge", capabilities: "status.read"));

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
        await using var server = await StartServerAsync(pipeName, CreateRegistry());

        var first = await ConnectHandshakedClientAsync(pipeName, Handshake(capabilities: "status.read"));
        var firstResponse = await first.InvokeAsync(new RequestEnvelope { Method = "system.get_status" });
        Assert.True(firstResponse.Ok);

        await using var second = await ConnectHandshakedClientAsync(pipeName, Handshake(capabilities: "status.read"));
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
        await using var server = await StartServerAsync(pipeName, CreateRegistry());

        using var stream = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut,
            PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation);
        await stream.ConnectAsync(IpcConstants.ConnectionTimeoutMs);

        var handshakePayload = new RequestEnvelope
        {
            Method = HandshakeParams.MethodName,
            Params = JsonSerializer.SerializeToElement(Handshake(capabilities: "status.read"), Json.Options),
        }.Serialize();
        var handshakeResponse = await SendRawFrameAsync(stream,
            IpcMessage.Create(100, IpcConstants.MessageTypeHandshake, Encoding.UTF8.GetBytes(handshakePayload)));
        Assert.True(handshakeResponse.Ok, $"handshake failed: {handshakeResponse.Error?.Code}");

        var invokePayload = new RequestEnvelope { Method = "system.get_status" }.Serialize();
        var okResponse = await SendRawFrameAsync(stream,
            IpcMessage.Create(101, IpcConstants.MessageTypeRequest, Encoding.UTF8.GetBytes(invokePayload)));
        Assert.True(okResponse.Ok);

        // 同一连接回退重发 RequestId = 101（新 Nonce，绕不过连接级单调检查）
        var replayResponse = await SendRawFrameAsync(stream,
            IpcMessage.Create(101, IpcConstants.MessageTypeRequest, Encoding.UTF8.GetBytes(invokePayload)));
        Assert.False(replayResponse.Ok);
        Assert.Equal(IpcErrorCodes.IpcReplayDetected, replayResponse.Error!.Code);
    }

    private static async Task<ResponseEnvelope> SendRawFrameAsync(NamedPipeClientStream stream, IpcMessage frame)
    {
        var bytes = frame.ToBytes();
        var lengthPrefix = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(lengthPrefix, (uint)bytes.Length);
        await stream.WriteAsync(lengthPrefix);
        await stream.WriteAsync(bytes);
        await stream.FlushAsync();

        var lengthBuffer = new byte[4];
        await ReadExactRawAsync(stream, lengthBuffer, 4);
        var length = BinaryPrimitives.ReadUInt32LittleEndian(lengthBuffer);
        var body = new byte[length];
        await ReadExactRawAsync(stream, body, (int)length);
        var responseFrame = IpcMessage.FromBytes(body);
        Assert.Equal(IpcConstants.MessageTypeResponse, responseFrame.MessageType);
        return ResponseEnvelope.Deserialize(Encoding.UTF8.GetString(responseFrame.Payload))
            ?? throw new InvalidOperationException("server response is not a valid envelope.");
    }

    private static async Task ReadExactRawAsync(Stream stream, byte[] buffer, int count)
    {
        var totalRead = 0;
        while (totalRead < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(totalRead, count - totalRead));
            if (read == 0)
            {
                throw new IOException("connection closed by server.");
            }

            totalRead += read;
        }
    }

    [Fact]
    public async Task BridgeLineProtocol_EndToEnd_WithTestClient()
    {
        var pipeName = "Winknow_IpcTests_" + Guid.NewGuid().ToString("N");
        await using var server = await StartServerAsync(pipeName, CreateRegistry());
        await using var connection = new BridgeConnection(pipeName, Handshake(capabilities: "status.read"));

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
        await using var connection = new BridgeConnection(pipeName, Handshake(capabilities: "status.read"));

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
        await using var server = await StartServerAsync(pipeName, CreateRegistry());
        await using var connection = new BridgeConnection(
            pipeName, Handshake(deviceId: "wrong-device-999", capabilities: "status.read"));

        var response = await connection.InvokeAsync(
            new RequestEnvelope { Method = "system.get_status" }, CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.Unavailable, response.Error!.Code);
    }
}
