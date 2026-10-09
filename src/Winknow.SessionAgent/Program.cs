using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using Winknow.Core;
using Winknow.Ipc;
using Winknow.Ipc.Protocol;
using Winknow.Ipc.Session;

namespace Winknow.SessionAgent;

/// <summary>
/// SessionAgent 会话代理入口。
/// 运行身份：学生用户 | 输出类型：WinExe（无控制台窗口）
///
/// 启动方式：由 ControlService 在用户登录时通过 CreateProcessAsUser 拉起
/// （服务端自动拉起为后续里程碑项；当前由部署/人工启动，canary 演练环境
/// 手工拉起即可满足配对前提）。
/// 实例数：每个活动用户会话 1 个（通过 SessionMutex 保证）。
///
/// M2 定位（ADR-002）：SessionAgent 降级保留——主 UI 职责由 Flutter 经
/// DesktopBridge 承担，Agent 维持连接期握手 + 旧帧心跳保活（ADR-001 兼容
/// 路径）。
/// R06（GO_LIVE §3.4b 真实锁屏下发链路）：握手声明 lock_overlay 能力，
/// 双工接收循环消费服务端主动下发的 LockOverlay 帧（0x03E9，
/// payload {"action":"show"/"hide"}）并驱动 [LockOverlay] 遮罩；
/// 心跳改为只写（Ack 由接收循环消费，防推送帧与 Ack 交错读乱序）。
/// </summary>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        // 1. 会话互斥：确保每个用户会话只有一个 Agent（用真实 Terminal Services
        //    会话 ID，而非进程 ID——进程 ID 每次启动都不同，无法标识会话）
        var sessionId = GetCurrentSessionId();
        using var mutex = new SessionMutex(sessionId);
        if (!mutex.IsAcquired)
        {
            return 2;
        }

        var senderSid = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;
        using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
        var logger = loggerFactory.CreateLogger("Winknow.SessionAgent");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cts.Cancel();
        };

        // 2. 连接 ControlService 并完成连接期握手（component=session_agent）
        var deviceId = DeviceId.Generate();
        var componentVersion = "7.0.1";
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "--version")
            {
                componentVersion = args[i + 1];
            }
        }

        await using var client = new IpcClient(IpcConstants.ControlPipeName);
        try
        {
            await client.ConnectAsync(cancellationToken: cts.Token);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to connect to ControlService IPC pipe {PipeName}.", IpcConstants.ControlPipeName);
            return 3;
        }

        // R06：声明 lock_overlay 能力（服务端能力集含 lock_overlay 时授予，
        // classroom.lock/unlock 的推送目标即本组件）
        var handshake = new HandshakeParams
        {
            ProtocolVersion = ProtocolVersion.Current.ToString(),
            Component = "session_agent",
            ComponentVersion = componentVersion,
            Capabilities = new[] { "lock_overlay" },
            DeviceId = deviceId,
            CallerSid = senderSid,
            SessionId = $"session-{sessionId}",
        };

        var handshakeResponse = await client.HandshakeAsync(handshake, cts.Token);
        if (!handshakeResponse.Ok)
        {
            logger.LogError(
                "Handshake rejected: {ErrorCode} {Message}.",
                handshakeResponse.Error?.Code, handshakeResponse.Error?.Message);
            return 4;
        }

        logger.LogInformation(
            "SessionAgent started: session={SessionId} sid={SenderSid} device={DeviceId}.",
            sessionId, senderSid, deviceId);

        // 3. 双工运行：只写心跳（Ack 由接收循环消费）+ 接收服务端推送帧
        using var overlay = new LockOverlay(loggerFactory.CreateLogger<LockOverlay>());
        using var heartbeatTimer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        var heartbeatTask = HeartbeatLoopAsync(client, heartbeatTimer, logger, cts.Token);
        var receiveTask = ReceiveLoopAsync(client, overlay, logger, cts.Token);

        // 4. 等待退出信号（服务注销时进程被终止；Ctrl+C 供调试）
        try
        {
            await Task.Delay(Timeout.Infinite, cts.Token);
        }
        catch (OperationCanceledException)
        {
            // 正常退出
        }

        await Task.WhenAll(heartbeatTask, receiveTask);
        return 0;
    }

    private static async Task HeartbeatLoopAsync(IpcClient client, PeriodicTimer timer,
        ILogger logger, CancellationToken cancellationToken)
    {
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken))
            {
                // R06 双工模式：只写不读——服务端 Ack 帧与推送帧统一由接收循环消费，
                // 避免"期待 Ack 却先读到推送帧"的乱序失败
                await client.WriteHeartbeatAsync(cancellationToken);
                logger.LogDebug("Heartbeat sent.");
            }
        }
        catch (OperationCanceledException)
        {
            // 正常关闭
        }
        catch (Exception ex)
        {
            // 连接中断等致命错误：通知主流程退出，由 ControlService 在下个周期重新拉起
            logger.LogError(ex, "Heartbeat failed, exiting.");
            Environment.Exit(5);
        }
    }

    /// <summary>
    /// 服务端推送接收循环（R06）：LockOverlay 帧（0x03E9）驱动遮罩 Show/Hide；
    /// 心跳 Ack / 请求响应帧静默消费。连接中断视为致命错误退出主流程。
    /// </summary>
    private static async Task ReceiveLoopAsync(IpcClient client, LockOverlay overlay,
        ILogger logger, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var frame = await client.ReadServerFrameAsync(cancellationToken);
                switch (frame.MessageType)
                {
                    case IpcConstants.MessageTypeLockOverlay:
                        HandleLockOverlayFrame(frame, overlay, logger);
                        break;

                    case IpcConstants.MessageTypeAck:
                    case IpcConstants.MessageTypeResponse:
                        // 心跳 Ack（只写心跳模式）/握手响应后续帧：已无等待方，静默消费
                        logger.LogDebug("Server frame 0x{Type:X4} consumed.", frame.MessageType);
                        break;

                    default:
                        logger.LogDebug("Ignored server frame type 0x{Type:X4}.", frame.MessageType);
                        break;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // 正常关闭
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "IPC receive loop failed, exiting.");
            Environment.Exit(6);
        }
    }

    private static void HandleLockOverlayFrame(IpcMessage frame, LockOverlay overlay, ILogger logger)
    {
        string action;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(frame.Payload);
            action = doc.RootElement.TryGetProperty("action", out var actionElement)
                ? actionElement.GetString() ?? string.Empty
                : string.Empty;
        }
        catch (System.Text.Json.JsonException ex)
        {
            logger.LogWarning(ex, "Malformed lock overlay payload; frame ignored.");
            return;
        }

        var applied = action switch
        {
            "show" => overlay.Show(),
            "hide" => overlay.Hide(),
            _ => false,
        };
        if (applied)
        {
            logger.LogInformation("Lock overlay {Action} applied.", action);
        }
        else
        {
            logger.LogWarning("Lock overlay action '{Action}' not applied.", action);
        }
    }

    /// <summary>
    /// 获取当前进程所在的 Terminal Services 会话 ID（0 为服务会话，交互会话 &gt;= 1）。
    /// </summary>
    private static int GetCurrentSessionId()
    {
        return ProcessIdToSessionId((uint)Environment.ProcessId, out var sessionId) ? (int)sessionId : 0;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);
}
