using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using Winknow.Core;
using Winknow.Ipc;

namespace Winknow.SessionAgent;

/// <summary>
/// SessionAgent 会话代理入口（P2-03 重写）。
/// 运行身份：学生用户 | 输出类型：WinExe（无控制台窗口）
///
/// 线程模型：
/// - 主线程 [STAThread] 运行 Win32 消息泵（GetMessage/Translate/Dispatch），
///   LockOverlay 窗口创建、销毁与绘制全部发生在该线程（窗口只属于创建它的线程）；
/// - IPC 连接、握手、心跳与断线重连在后台任务中运行，
///   锁屏/解锁/退出命令经 PostThreadMessage 转发到泵线程执行。
///
/// 修复（相对旧版）：
/// - SessionId 取 Process.GetCurrentProcess().SessionId（旧版误用 Environment.ProcessId）；
/// - 真实 Win32 消息泵替代 Task.Delay 占位（旧版遮罩窗口根本收不到 WM_PAINT）；
/// - 事件委托保存到字段，退订生效（旧版 lambda 订阅/退订是两个不同实例）；
/// - 消息类型改用 IpcConstants（旧版硬编码 1001）；
/// - 断线后按指数退避自动重连（旧版断线即死）。
/// </summary>
internal static class Program
{
    // 泵线程自定义消息（WM_APP 起），由 IPC 线程 PostThreadMessage 转发
    private const uint WmAppShowLock = 0x8000 + 0x0001;
    private const uint WmAppHideLock = 0x8000 + 0x0002;
    private const uint WmAppShutdown = 0x8000 + 0x0003;
    private const uint WmQuit = 0x0012;

    private static uint _pumpThreadId;
    private static string _policyVersion = string.Empty;
    private static readonly DateTimeOffset StartedAt = DateTimeOffset.UtcNow;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetCurrentThreadId();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool PostThreadMessage(uint threadId, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool TranslateMessage(ref MSG lpMsg);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr DispatchMessage(ref MSG lpMsg);

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public IntPtr hwnd;
        public uint message;
        public IntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public int ptX;
        public int ptY;
    }

    [STAThread]
    private static async Task<int> Main(string[] args)
    {
        // 1. 会话 ID：Agent 由 ControlService 经 CreateProcessAsUser 拉起在学生会话内，
        //    进程所属 WTS 会话即目标会话（旧版误用 Environment.ProcessId，属致命 bug）
        var sessionId = Process.GetCurrentProcess().SessionId;

        // 2. 互斥锁：确保每会话只有一个 Agent
        using var mutex = new SessionMutex(sessionId);
        if (!mutex.IsAcquired)
        {
            return 2;
        }

        using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
        var logger = loggerFactory.CreateLogger("SessionAgent");
        var overlayLogger = loggerFactory.CreateLogger<LockOverlay>();
        using var overlay = new LockOverlay(overlayLogger);

        var senderSid = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;
        var deviceId = DeviceId.Generate();
        var clientVersion = typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            RequestShutdown();
        };

        // 3. IPC 循环（连接 + 握手 + 心跳 + 断线重连）在后台任务
        var ipcTask = Task.Run(() => RunIpcLoopAsync(
            sessionId, senderSid, deviceId, clientVersion, overlay, logger,
            loggerFactory.CreateLogger<IpcClient>(), cts.Token));

        // 4. 主线程消息泵：窗口消息（WM_PAINT/WM_DISPLAYCHANGE）与转发的锁屏命令在此处理
        _pumpThreadId = GetCurrentThreadId();
        var exitCode = RunMessagePump(overlay, logger);

        // 5. 泵退出（Shutdown/Ctrl+C）→ 停止 IPC 并等待收尾
        cts.Cancel();
        overlay.Dispose();
        try
        {
            await ipcTask;
        }
        catch (OperationCanceledException)
        {
            // 正常关闭
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "IPC loop terminated with error");
        }

        logger.LogInformation("SessionAgent exited with code {ExitCode} (session {SessionId})", exitCode, sessionId);
        return exitCode;
    }

    /// <summary>
    /// Win32 消息泵。锁屏/解锁/退出命令经线程消息进入；其余消息分发到窗口过程。
    /// </summary>
    private static int RunMessagePump(LockOverlay overlay, ILogger logger)
    {
        while (GetMessage(out var msg, IntPtr.Zero, 0, 0) > 0)
        {
            switch (msg.message)
            {
                case WmAppShowLock:
                    overlay.Show(msg.wParam != IntPtr.Zero ? MsgPtrToString(msg.wParam) : null);
                    continue;

                case WmAppHideLock:
                    overlay.Hide();
                    continue;

                case WmAppShutdown:
                case WmQuit:
                    logger.LogInformation("Shutdown message received, exiting message pump");
                    return 0;

                default:
                    TranslateMessage(ref msg);
                    DispatchMessage(ref msg);
                    break;
            }
        }

        return 0;
    }

    /// <summary>
    /// IPC 主循环：连接 → 握手 → 心跳保持；连接失败或断线后按指数退避重连。
    /// </summary>
    private static async Task RunIpcLoopAsync(
        int sessionId,
        string senderSid,
        string deviceId,
        string clientVersion,
        LockOverlay overlay,
        ILogger logger,
        ILogger<IpcClient> ipcLogger,
        CancellationToken cancellationToken)
    {
        var backoff = new ReconnectBackoff();

        while (!cancellationToken.IsCancellationRequested)
        {
            await using var client = new IpcClient(
                IpcConstants.ControlPipeName,
                senderSid,
                deviceId,
                clientVersion,
                logger: ipcLogger);

            // 委托保存到局部变量：订阅/退订必须是同一实例（旧版 lambda 两次书写导致退订无效）
            Func<IpcMessage, CancellationToken, Task> handler =
                (message, ct) => OnMessageReceived(message, ct, overlay, client, logger);
            client.MessageReceived += handler;
            try
            {
                var connectResult = await client.ConnectAsync(cancellationToken);
                if (!connectResult.IsSuccess)
                {
                    var delay = backoff.Next();
                    logger.LogWarning(
                        "IPC connect/handshake failed ({ErrorCode} {Error}); retrying in {Delay}ms",
                        connectResult.ErrorCode,
                        connectResult.ErrorMessage ?? "unknown",
                        delay.TotalMilliseconds);
                    await Task.Delay(delay, cancellationToken);
                    continue;
                }

                backoff.Reset();
                logger.LogInformation(
                    "Connected to ControlService (session {SessionId}, pid {Pid})",
                    sessionId, Environment.ProcessId);

                // 心跳保持，直到连接断开（服务端停止/管道破裂）
                await HeartbeatUntilDisconnectAsync(client, logger, cancellationToken);

                var reconnectDelay = backoff.Next();
                logger.LogWarning("IPC connection lost; reconnecting in {Delay}ms", reconnectDelay.TotalMilliseconds);
                await client.DisconnectAsync();
                await Task.Delay(reconnectDelay, cancellationToken);
            }
            finally
            {
                client.MessageReceived -= handler;
            }
        }
    }

    /// <summary>
    /// 按 HeartbeatIntervalSeconds 发心跳；Disconnected 事件或发送失败即返回（触发重连）。
    /// </summary>
    private static async Task HeartbeatUntilDisconnectAsync(
        IpcClient client, ILogger logger, CancellationToken cancellationToken)
    {
        var disconnected = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void OnDisconnected() => disconnected.TrySetResult();
        client.Disconnected += OnDisconnected;
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(IpcConstants.HeartbeatIntervalSeconds));
            while (!cancellationToken.IsCancellationRequested)
            {
                var tickTask = timer.WaitForNextTickAsync(cancellationToken).AsTask();
                var finished = await Task.WhenAny(tickTask, disconnected.Task);
                if (finished == disconnected.Task)
                {
                    return;
                }

                var sendResult = await client.SendHeartbeatAsync(cancellationToken);
                if (!sendResult.IsSuccess)
                {
                    logger.LogWarning("Heartbeat send failed: {Error}", sendResult.ErrorMessage ?? "unknown");
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // 正常关闭
        }
        finally
        {
            client.Disconnected -= OnDisconnected;
        }
    }

    /// <summary>
    /// 服务端消息处理（IPC 接收线程）：锁屏/解锁/退出转发到泵线程；Status 就地应答。
    /// </summary>
    private static Task OnMessageReceived(
        IpcMessage message, CancellationToken cancellationToken, LockOverlay overlay, IpcClient client, ILogger logger)
    {
        switch (message.MessageType)
        {
            case IpcConstants.MessageTypeShowLock:
                var lockPayload = IpcProtocol.Decode<LockPayload>(message.Payload);
                _policyVersion = lockPayload?.PolicyVersion ?? string.Empty;
                logger.LogInformation("Lock requested (reason: {Reason}, policy: {Policy})",
                    lockPayload?.Reason ?? "(default)", _policyVersion);
                PostToPump(WmAppShowLock, lockPayload is { Reason.Length: > 0 } ? StringToMsgPtr(lockPayload.Reason) : IntPtr.Zero);
                break;

            case IpcConstants.MessageTypeHideLock:
                logger.LogInformation("Unlock requested");
                PostToPump(WmAppHideLock, IntPtr.Zero);
                break;

            case IpcConstants.MessageTypeShutdown:
                logger.LogInformation("Shutdown requested by ControlService");
                RequestShutdown();
                break;

            case IpcConstants.MessageTypeStatus:
                // 状态查询：就地构造 StatusAck 应答（响应沿用请求 RequestId）
                var ack = new StatusAckPayload
                {
                    Version = typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "0.0.0",
                    IsLocked = overlay.IsLocked,
                    UptimeSeconds = (long)(DateTimeOffset.UtcNow - StartedAt).TotalSeconds,
                    PolicyVersion = _policyVersion
                };
                _ = client.SendResponseAsync(
                    message, IpcConstants.MessageTypeStatusAck, IpcProtocol.Encode(ack), cancellationToken);
                break;

            default:
                logger.LogDebug("Unhandled IPC message type 0x{MessageType:X4}", message.MessageType);
                break;
        }

        return Task.CompletedTask;
    }

    /// <summary>向消息泵线程投递命令；reason 跨线程传递经 Marshal 分配 HGlobal，泵线程读取后释放。</summary>
    private static void PostToPump(uint message, IntPtr lParam)
    {
        if (_pumpThreadId != 0)
        {
            PostThreadMessage(_pumpThreadId, message, IntPtr.Zero, lParam);
        }
    }

    private static void RequestShutdown()
    {
        if (_pumpThreadId != 0)
        {
            PostThreadMessage(_pumpThreadId, WmAppShutdown, IntPtr.Zero, IntPtr.Zero);
        }
    }

    private static IntPtr StringToMsgPtr(string value)
    {
        return Marshal.StringToHGlobalUni(value);
    }

    private static string? MsgPtrToString(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            return Marshal.PtrToStringUni(ptr);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }
}
