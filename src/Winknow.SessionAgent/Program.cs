using System.Security.Principal;
using Winknow.Ipc;

namespace Winknow.SessionAgent;

/// <summary>
/// SessionAgent 会话代理入口。
/// 运行身份：学生用户 | 输出类型：WinExe（无控制台窗口）
///
/// 启动方式：由 ControlService 在用户登录时通过 CreateProcessAsUser 拉起。
/// 实例数：每个活动用户会话 1 个（通过 SessionMutex 保证）。
/// </summary>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        var sessionId = GetCurrentSessionId();

        // 1. 互斥锁：确保每会话只有一个 Agent
        using var mutex = new SessionMutex(sessionId);
        if (!mutex.IsAcquired)
        {
            // 本会话已有 Agent 运行，退出
            return 2;
        }

        // 2. 获取当前用户 SID
        var senderSid = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;

        // 3. 连接 ControlService IPC
        using var cts = new CancellationTokenSource();
        await using var ipcClient = new IpcClient(IpcConstants.ControlPipeName, senderSid);

        var connectResult = await ipcClient.ConnectAsync(cts.Token);
        if (!connectResult.IsSuccess)
        {
            return 3;
        }

        // 4. 注册消息处理
        ipcClient.MessageReceived += OnMessageReceived;

        // 5. 启动心跳定时器
        using var heartbeatTimer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        _ = HeartbeatLoopAsync(ipcClient, heartbeatTimer, cts.Token);

        // 6. 等待退出信号
        await WaitForExitAsync(cts.Token);

        // 7. 清理
        cts.Cancel();
        ipcClient.MessageReceived -= OnMessageReceived;

        return 0;
    }

    private static Task OnMessageReceived(IpcMessage message, CancellationToken cancellationToken)
    {
        // TODO 第3周：处理策略更新、屏幕控制等命令
        // TODO 第3周：根据消息类型执行对应操作
        return Task.CompletedTask;
    }

    private static async Task HeartbeatLoopAsync(IpcClient client, PeriodicTimer timer, CancellationToken cancellationToken)
    {
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken))
            {
                await client.SendHeartbeatAsync(cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            // 正常关闭
        }
    }

    private static int GetCurrentSessionId()
    {
        // SessionAgent 由 ControlService 在用户会话中启动，
        // 可通过 GetCurrentProcess 的 SessionId 获取。
        return Environment.ProcessId;
    }

    private static Task WaitForExitAsync(CancellationToken cancellationToken)
    {
        // TODO 第3周：集成 Win32 消息循环（GetMessage）处理键盘钩子
        // 当前为占位实现，等待 Ctrl+C 或取消
        try
        {
            return Task.Delay(Timeout.Infinite, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return Task.CompletedTask;
        }
    }
}
