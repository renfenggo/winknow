using System.Text;
using System.Text.Json;
using Winknow.Ipc;
using Winknow.Ipc.Protocol;

namespace Winknow.Ipc.Tests;

/// <summary>
/// R06（GO_LIVE §3.4b）服务端推送通道集成测试：进程内真实管道，
/// session_agent 握手注册后，TryPushToComponentAsync 下发 LockOverlay 帧
/// （0x03E9，payload {"action":"show"/"hide"}），客户端 ReadServerFrameAsync
/// 接收；双工模式下只写心跳与推送帧共存由读循环统一消费。
/// </summary>
public sealed class LockOverlayPushTests
{
    private static readonly IReadOnlySet<string> Capabilities = new HashSet<string>(StringComparer.Ordinal)
    {
        "status.read", "lock_overlay",
    };

    private static async Task<IpcServer> StartServerAsync(string pipeName) =>
        await IpcTestHarness.StartServerAsync(
            pipeName, IpcTestHarness.CreateRegistry(), supportedCapabilities: Capabilities);

    [Fact]
    public async Task Push_ToConnectedSessionAgent_DeliversLockOverlayFrame()
    {
        var pipeName = "Winknow_LockPush_" + Guid.NewGuid().ToString("N");
        await using var server = await StartServerAsync(pipeName);
        await using var client = await IpcTestHarness.ConnectHandshakedClientAsync(
            pipeName, IpcTestHarness.Handshake(component: "session_agent", capabilities: "lock_overlay"));

        Assert.True(server.IsComponentConnected("session_agent"));

        var pushed = await server.TryPushToComponentAsync(
            "session_agent",
            IpcConstants.MessageTypeLockOverlay,
            Encoding.UTF8.GetBytes("""{"action":"show"}"""));

        Assert.True(pushed);
        var frame = await client.ReadServerFrameAsync();
        Assert.Equal(IpcConstants.MessageTypeLockOverlay, frame.MessageType);
        Assert.Equal(0u, frame.RequestId);
        using var payload = JsonDocument.Parse(Encoding.UTF8.GetString(frame.Payload));
        Assert.Equal("show", payload.RootElement.GetProperty("action").GetString());
    }

    [Fact]
    public async Task Push_ToComponentWithoutConnection_ReturnsFalse()
    {
        var pipeName = "Winknow_LockPush_" + Guid.NewGuid().ToString("N");
        await using var server = await StartServerAsync(pipeName);

        Assert.False(server.IsComponentConnected("session_agent"));
        Assert.False(await server.TryPushToComponentAsync(
            "session_agent",
            IpcConstants.MessageTypeLockOverlay,
            Encoding.UTF8.GetBytes("""{"action":"show"}""")));
    }

    [Fact]
    public async Task Push_AfterClientDisconnect_ReturnsFalse()
    {
        var pipeName = "Winknow_LockPush_" + Guid.NewGuid().ToString("N");
        await using var server = await StartServerAsync(pipeName);
        var client = await IpcTestHarness.ConnectHandshakedClientAsync(
            pipeName, IpcTestHarness.Handshake(component: "session_agent", capabilities: "lock_overlay"));
        Assert.True(server.IsComponentConnected("session_agent"));

        await client.DisposeAsync();

        // 服务端读循环感知断连并注销注册（轮询等待，最多 5s）
        var deadline = Environment.TickCount64 + 5_000;
        while (server.IsComponentConnected("session_agent") && Environment.TickCount64 < deadline)
        {
            await Task.Delay(50);
        }

        Assert.False(server.IsComponentConnected("session_agent"));
        Assert.False(await server.TryPushToComponentAsync(
            "session_agent",
            IpcConstants.MessageTypeLockOverlay,
            Encoding.UTF8.GetBytes("""{"action":"hide"}""")));
    }

    [Fact]
    public async Task Push_BeforeHandshake_ComponentNotRegistered()
    {
        // 建立裸连接但未握手：连接不应注册为组件推送目标
        var pipeName = "Winknow_LockPush_" + Guid.NewGuid().ToString("N");
        await using var server = await StartServerAsync(pipeName);
        await using var raw = await IpcTestHarness.ConnectRawAsync(pipeName);

        Assert.False(server.IsComponentConnected("session_agent"));
    }

    [Fact]
    public async Task Duplex_WriteHeartbeatAndServerPush_BothConsumedByReadLoop()
    {
        // R06 双工契约：客户端只写心跳（不读 Ack），服务端推送帧与心跳 Ack
        // 交错到达时由接收循环按帧类型统一消费，不产生乱序失败
        var pipeName = "Winknow_LockPush_" + Guid.NewGuid().ToString("N");
        await using var server = await StartServerAsync(pipeName);
        await using var client = await IpcTestHarness.ConnectHandshakedClientAsync(
            pipeName, IpcTestHarness.Handshake(component: "session_agent", capabilities: "lock_overlay"));

        await client.WriteHeartbeatAsync();
        var pushed = await server.TryPushToComponentAsync(
            "session_agent",
            IpcConstants.MessageTypeLockOverlay,
            Encoding.UTF8.GetBytes("""{"action":"show"}"""));
        Assert.True(pushed);

        var receivedTypes = new HashSet<ushort>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (receivedTypes.Count < 2)
        {
            var frame = await client.ReadServerFrameAsync(cts.Token);
            if (frame.MessageType is IpcConstants.MessageTypeAck
                or IpcConstants.MessageTypeLockOverlay)
            {
                receivedTypes.Add(frame.MessageType);
            }
        }

        Assert.Contains(IpcConstants.MessageTypeAck, receivedTypes);
        Assert.Contains(IpcConstants.MessageTypeLockOverlay, receivedTypes);
    }
}
