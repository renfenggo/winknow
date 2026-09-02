using System.Diagnostics;
using System.Security.Principal;
using Winknow.Core;
using Winknow.Core.Results;
using Winknow.Ipc;

namespace Winknow.Ipc.Tests;

/// <summary>
/// P2-01/P2-04 本机回环集成：IpcServer ↔ IpcClient 握手准入、服务端推送、请求-响应。
/// 同进程同用户：Impersonation 取得的真实 SID 即当前测试进程用户 SID。
/// </summary>
public sealed class IpcRoundTripTests
{
    private static string CurrentSid => WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;

    private static (IpcServer Server, string PipeName, IpcAuthenticator Authenticator) CreateServer(
        Func<IpcHandshakeContext, bool>? admissionCheck = null,
        string expectedDeviceId = "TEST-DEVICE")
    {
        var pipeName = "Winknow_Test_" + Guid.NewGuid().ToString("N");
        var authenticator = new IpcAuthenticator(new[] { CurrentSid }, expectedDeviceId);
        var server = new IpcServer(
            pipeName,
            authenticator,
            admissionCheck: admissionCheck ?? (_ => true),
            expectedDeviceId: expectedDeviceId);
        return (server, pipeName, authenticator);
    }

    private static async Task WaitUntilAsync(Func<bool> condition, TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(5));
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
            {
                return;
            }

            await Task.Delay(50);
        }

        Assert.Fail("Condition not met within timeout.");
    }

    [Fact]
    public async Task Handshake_AdmittedClient_ShouldBeGranted()
    {
        var (server, pipeName, authenticator) = CreateServer();
        await using (server)
        using (authenticator)
        {
            await server.StartAsync();

            await using var client = new IpcClient(pipeName, CurrentSid, "TEST-DEVICE", "7.0.0-test");
            var result = await client.ConnectAsync();

            Assert.True(result.IsSuccess, result.ErrorMessage);
            Assert.NotNull(client.Handshake);
            Assert.True(client.Handshake.Granted);
            Assert.False(string.IsNullOrEmpty(client.Handshake.ServerNonce));

            await client.DisconnectAsync();
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task Handshake_AdmissionDenied_ShouldReturnUnauthorized()
    {
        var (server, pipeName, authenticator) = CreateServer(admissionCheck: _ => false);
        await using (server)
        using (authenticator)
        {
            await server.StartAsync();

            await using var client = new IpcClient(pipeName, CurrentSid, "TEST-DEVICE", "7.0.0-test");
            var result = await client.ConnectAsync();

            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.Unauthorized, result.ErrorCode);
            Assert.Null(client.Handshake);

            await server.StopAsync();
        }
    }

    [Fact]
    public async Task Handshake_DeviceIdMismatch_ShouldBeRejected()
    {
        // 服务端期望 TEST-DEVICE，客户端声明 OTHER-DEVICE → 拒绝
        var (server, pipeName, authenticator) = CreateServer(expectedDeviceId: "TEST-DEVICE");
        await using (server)
        using (authenticator)
        {
            await server.StartAsync();

            await using var client = new IpcClient(pipeName, CurrentSid, "OTHER-DEVICE", "7.0.0-test");
            var result = await client.ConnectAsync();

            Assert.False(result.IsSuccess);
            Assert.Null(client.Handshake);

            await server.StopAsync();
        }
    }

    [Fact]
    public async Task ServerPush_ClientMessageHandler_ShouldReceive()
    {
        var (server, pipeName, authenticator) = CreateServer();
        await using (server)
        using (authenticator)
        {
            var sessionId = Process.GetCurrentProcess().SessionId;
            await server.StartAsync();

            var received = new TaskCompletionSource<IpcMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
            await using var client = new IpcClient(pipeName, CurrentSid, "TEST-DEVICE", "7.0.0-test");
            client.MessageReceived += (message, _) =>
            {
                received.TrySetResult(message);
                return Task.CompletedTask;
            };

            var connectResult = await client.ConnectAsync();
            Assert.True(connectResult.IsSuccess, connectResult.ErrorMessage);

            await WaitUntilAsync(() => server.TryGetSession(sessionId, out var conn) && conn is { IsConnected: true });

            var payload = IpcProtocol.Encode(new LockPayload { Reason = "测试锁定", PolicyVersion = "v1" });
            Assert.True(server.TryGetSession(sessionId, out var connection));
            var sendResult = await connection!.SendAsync(IpcConstants.MessageTypeShowLock, payload);
            Assert.True(sendResult.IsSuccess, sendResult.ErrorMessage);

            var message = await received.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(IpcConstants.MessageTypeShowLock, message.MessageType);
            var lockPayload = IpcProtocol.Decode<LockPayload>(message.Payload);
            Assert.NotNull(lockPayload);
            Assert.Equal("测试锁定", lockPayload.Reason);

            await client.DisconnectAsync();
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task RequestResponse_ClientDoesNotAnswer_ShouldTimeOut()
    {
        // 客户端不注册 Status 应答 → 服务端请求应按超时失败，而非永久挂起
        var (server, pipeName, authenticator) = CreateServer();
        await using (server)
        using (authenticator)
        {
            var sessionId = Process.GetCurrentProcess().SessionId;
            await server.StartAsync();

            await using var client = new IpcClient(pipeName, CurrentSid, "TEST-DEVICE", "7.0.0-test");
            var connectResult = await client.ConnectAsync();
            Assert.True(connectResult.IsSuccess, connectResult.ErrorMessage);
            await WaitUntilAsync(() => server.TryGetSession(sessionId, out var conn) && conn is { IsConnected: true });

            Assert.True(server.TryGetSession(sessionId, out var connection));
            var response = await connection!.SendRequestAsync(
                IpcConstants.MessageTypeStatus,
                IpcProtocol.Encode(new StatusQueryPayload { Scope = "agent" }),
                IpcConstants.MessageTypeStatusAck,
                timeout: TimeSpan.FromSeconds(2));

            Assert.False(response.IsSuccess);
            Assert.Equal(ErrorCode.IpcTimeout, response.ErrorCode);

            await client.DisconnectAsync();
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task RequestResponse_ClientAnswers_ShouldCompleteServerPendingRequest()
    {
        var (server, pipeName, authenticator) = CreateServer();
        await using (server)
        using (authenticator)
        {
            var sessionId = Process.GetCurrentProcess().SessionId;
            await server.StartAsync();

            await using var client = new IpcClient(pipeName, CurrentSid, "TEST-DEVICE", "7.0.0-test");
            client.MessageReceived += async (message, ct) =>
            {
                if (message.MessageType == IpcConstants.MessageTypeStatus)
                {
                    var ack = new StatusAckPayload
                    {
                        Version = "7.0.0-agent",
                        IsLocked = true,
                        UptimeSeconds = 99,
                        PolicyVersion = "v2"
                    };
                    await client.SendResponseAsync(
                        message, IpcConstants.MessageTypeStatusAck, IpcProtocol.Encode(ack), ct);
                }
            };

            var connectResult = await client.ConnectAsync();
            Assert.True(connectResult.IsSuccess, connectResult.ErrorMessage);
            await WaitUntilAsync(() => server.TryGetSession(sessionId, out var conn) && conn is { IsConnected: true });

            Assert.True(server.TryGetSession(sessionId, out var connection));
            var response = await connection!.SendRequestAsync(
                IpcConstants.MessageTypeStatus,
                IpcProtocol.Encode(new StatusQueryPayload { Scope = "agent" }),
                IpcConstants.MessageTypeStatusAck,
                timeout: TimeSpan.FromSeconds(5));

            Assert.True(response.IsSuccess, response.ErrorMessage);
            var ackPayload = IpcProtocol.Decode<StatusAckPayload>(response.Data!.Payload);
            Assert.NotNull(ackPayload);
            Assert.True(ackPayload.IsLocked);
            Assert.Equal("7.0.0-agent", ackPayload.Version);
            Assert.Equal("v2", ackPayload.PolicyVersion);

            await client.DisconnectAsync();
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task ConnectionClosed_ServerShouldRemoveSessionRoute()
    {
        var (server, pipeName, authenticator) = CreateServer();
        await using (server)
        using (authenticator)
        {
            var sessionId = Process.GetCurrentProcess().SessionId;
            await server.StartAsync();

            await using var client = new IpcClient(pipeName, CurrentSid, "TEST-DEVICE", "7.0.0-test");
            Assert.True((await client.ConnectAsync()).IsSuccess);
            await WaitUntilAsync(() => server.TryGetSession(sessionId, out var conn) && conn is { IsConnected: true });

            await client.DisconnectAsync();
            await WaitUntilAsync(() => !server.TryGetSession(sessionId, out _));
            await server.StopAsync();
        }
    }
}
