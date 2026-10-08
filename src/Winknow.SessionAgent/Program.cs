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
/// 启动方式：由 ControlService 在用户登录时通过 CreateProcessAsUser 拉起。
/// 实例数：每个活动用户会话 1 个（通过 SessionMutex 保证）。
///
/// M2 定位（ADR-002）：SessionAgent 降级保留——主 UI 职责由 Flutter 经
/// DesktopBridge 承担，Agent 仅维持连接期握手 + 旧帧心跳保活（ADR-001 兼容
/// 路径）；LockOverlay 遮罩组件保留在 LockOverlay.cs，下发链路待后续
/// 里程碑契约扩展（method_registry v1 无 session 维度方法）后接入。
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

        var handshake = new HandshakeParams
        {
            ProtocolVersion = ProtocolVersion.Current.ToString(),
            Component = "session_agent",
            ComponentVersion = componentVersion,
            Capabilities = Array.Empty<string>(),
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

        // 3. 心跳保活（旧帧类型，服务端 MessageReceived + Ack 兼容路径）
        using var heartbeatTimer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        var heartbeatTask = HeartbeatLoopAsync(client, heartbeatTimer, logger, cts.Token);

        // 4. 等待退出信号（服务注销时进程被终止；Ctrl+C 供调试）
        try
        {
            await Task.Delay(Timeout.Infinite, cts.Token);
        }
        catch (OperationCanceledException)
        {
            // 正常退出
        }

        await heartbeatTask;
        return 0;
    }

    private static async Task HeartbeatLoopAsync(IpcClient client, PeriodicTimer timer,
        ILogger logger, CancellationToken cancellationToken)
    {
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken))
            {
                await client.SendHeartbeatAsync(cancellationToken);
                logger.LogDebug("Heartbeat acknowledged.");
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
