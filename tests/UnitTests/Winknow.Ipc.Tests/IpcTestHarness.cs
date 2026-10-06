using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Winknow.Ipc;
using Winknow.Ipc.Commands;
using Winknow.Ipc.Protocol;
using Winknow.Ipc.Session;

namespace Winknow.Ipc.Tests;

/// <summary>
/// IPC 集成测试公共设施：进程内真实 IpcServer（随机管道名）+ 原生管道帧读写。
/// </summary>
internal static class IpcTestHarness
{
    public const string DeviceId = "itest-device-0001";

    public static string CurrentSid => WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;

    public static HandshakeParams Handshake(string deviceId = DeviceId, string component = "bridge",
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

    public static IpcCommandRegistry CreateRegistry()
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

    /// <summary>
    /// 启动进程内 IpcServer：当前用户 SID 白名单（可替换 authenticator 以构造过期等状态）。
    /// </summary>
    public static async Task<IpcServer> StartServerAsync(string pipeName, IpcCommandRegistry registry,
        IpcAuthenticator? authenticator = null, string deviceId = DeviceId)
    {
        authenticator ??= new IpcAuthenticator(new[] { CurrentSid }, deviceId);
        var descriptor = new IpcServerDescriptor
        {
            ComponentVersion = "test-server",
            SupportedCapabilities = new HashSet<string>(StringComparer.Ordinal)
            {
                "status.read", "device.read", "runner.read", "classroom.control",
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

    /// <summary>建立原生管道连接（impersonation 级别，与 IpcClient 一致）。</summary>
    public static async Task<NamedPipeClientStream> ConnectRawAsync(string pipeName)
    {
        var stream = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut,
            PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation);
        await stream.ConnectAsync(IpcConstants.ConnectionTimeoutMs);
        return stream;
    }

    /// <summary>发送握手并断言成功。</summary>
    public static async Task HandshakeRawAsync(NamedPipeClientStream stream, HandshakeParams? handshake = null)
    {
        var payload = new RequestEnvelope
        {
            Method = HandshakeParams.MethodName,
            Params = JsonSerializer.SerializeToElement(handshake ?? Handshake(capabilities: "status.read"), Json.Options),
        }.Serialize();
        var response = await SendRawFrameAsync(stream,
            IpcMessage.Create(PickRequestId(), IpcConstants.MessageTypeHandshake, Encoding.UTF8.GetBytes(payload)));
        Assert.True(response.Ok, $"handshake failed: {response.Error?.Code} {response.Error?.Message}");
    }

    private static uint _requestIdSeed = 5_000;

    /// <summary>harness 侧 RequestId 种子（避开 IpcClient 毫秒时间戳区间，防止跨连接水位误判）。</summary>
    private static uint PickRequestId() => ++_requestIdSeed;

    public static async Task<IpcClient> ConnectHandshakedClientAsync(
        string pipeName, HandshakeParams handshake)
    {
        var client = new IpcClient(pipeName);
        await client.ConnectAsync();
        var handshakeResponse = await client.HandshakeAsync(handshake);
        Assert.True(handshakeResponse.Ok, $"handshake failed: {handshakeResponse.Error?.Code}");
        return client;
    }

    /// <summary>写一帧（长度前缀 + IpcMessage）。</summary>
    public static async Task WriteFrameAsync(NamedPipeClientStream stream, IpcMessage frame)
    {
        var bytes = frame.ToBytes();
        var lengthPrefix = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(lengthPrefix, (uint)bytes.Length);
        await stream.WriteAsync(lengthPrefix);
        await stream.WriteAsync(bytes);
        await stream.FlushAsync();
    }

    /// <summary>读取一帧并反序列化为响应信封（帧类型必须是 MessageTypeResponse）。</summary>
    public static async Task<ResponseEnvelope> ReadResponseEnvelopeAsync(NamedPipeClientStream stream)
    {
        var frame = await ReadFrameAsync(stream);
        Assert.Equal(IpcConstants.MessageTypeResponse, frame.MessageType);
        return ResponseEnvelope.Deserialize(Encoding.UTF8.GetString(frame.Payload))
            ?? throw new InvalidOperationException("server response is not a valid envelope.");
    }

    /// <summary>写帧并读取响应信封。</summary>
    public static async Task<ResponseEnvelope> SendRawFrameAsync(NamedPipeClientStream stream, IpcMessage frame)
    {
        await WriteFrameAsync(stream, frame);
        return await ReadResponseEnvelopeAsync(stream);
    }

    /// <summary>读取原始响应帧（帧级拒绝等场景需要检查帧类型）。</summary>
    public static async Task<IpcMessage> ReadFrameAsync(NamedPipeClientStream stream)
    {
        var lengthBuffer = new byte[4];
        await ReadExactAsync(stream, lengthBuffer, 4);
        var length = BinaryPrimitives.ReadUInt32LittleEndian(lengthBuffer);
        Assert.InRange((long)length, 1, IpcConstants.MaxMessageLength);
        var body = new byte[length];
        await ReadExactAsync(stream, body, (int)length);
        return IpcMessage.FromBytes(body);
    }

    public static async Task ReadExactAsync(Stream stream, byte[] buffer, int count)
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
}
