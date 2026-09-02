using Microsoft.Extensions.Logging;
using Winknow.ControlService.Sessions;
using Winknow.Ipc;

namespace Winknow.ControlService.Tests;

/// <summary>
/// P2-02 SessionManager 生命周期闭环（fake WTS）：
/// 登录 → 登记会话 + 拉起 Agent；注销 → 移除登记；环境开关禁用 → 不拉起。
/// </summary>
public sealed class SessionManagerTests
{
    private const string StudentSid = "S-1-5-21-100-200-300-1000";
    private const string EnabledVariable = "SessionAgentEnabled";

    private static SessionManager CreateManager(
        FakeTerminalServicesApi api, string? agentExePath = "C:\\fake\\Winknow.SessionAgent.exe")
    {
        var loggerFactory = LoggerFactory.Create(_ => { });
        return new SessionManager(loggerFactory, terminalServicesApi: api, agentExePath: agentExePath);
    }

    [Fact]
    public void SessionLoggedOn_ShouldRegisterAndLaunchAgent()
    {
        // Launcher 启动前校验 exe 存在性，用临时文件充当 Agent 二进制
        var agentPath = Path.GetTempFileName();
        try
        {
            var api = new FakeTerminalServicesApi();
            api.SessionUserSids[3] = StudentSid;
            using var manager = CreateManager(api, agentPath);

            // 直接驱动：等价于 Monitor 事件回调（避免轮询定时的不稳定）
            api.Sessions.Add(new WtsSession(3, WtsSessionState.Active));
            using (var monitor = new WtsSessionMonitor(api))
            {
                monitor.SessionChanged += manager.OnSessionChanged;
                monitor.PollOnce();
                monitor.PollOnce();
            }

            Assert.True(manager.Registry.TryGet(3, out var record));
            Assert.Equal(StudentSid, record!.UserSid);
            Assert.Contains(3, api.LaunchRequests);
        }
        finally
        {
            File.Delete(agentPath);
        }
    }

    [Fact]
    public void SessionLoggedOff_ShouldUnregister()
    {
        var api = new FakeTerminalServicesApi();
        api.SessionUserSids[3] = StudentSid;
        using var manager = CreateManager(api);

        manager.Registry.Register(3, StudentSid);
        manager.OnSessionChanged(new SessionChange(3, SessionChangeKind.LoggedOff));

        Assert.False(manager.Registry.TryGet(3, out _));
    }

    [Fact]
    public void SessionDisconnected_ShouldKeepRegistration()
    {
        var api = new FakeTerminalServicesApi();
        using var manager = CreateManager(api);

        manager.Registry.Register(3, StudentSid);
        manager.OnSessionChanged(new SessionChange(3, SessionChangeKind.Disconnected));

        Assert.True(manager.Registry.TryGet(3, out _));
    }

    [Fact]
    public void CheckAdmission_RegisteredSessionMatchingSid_ShouldAllow()
    {
        var api = new FakeTerminalServicesApi();
        using var manager = CreateManager(api);

        manager.Registry.Register(3, StudentSid);

        Assert.True(manager.CheckAdmission(NewContext(3, StudentSid)));
    }

    [Fact]
    public void CheckAdmission_UnregisteredOrMismatched_ShouldDeny()
    {
        var api = new FakeTerminalServicesApi();
        using var manager = CreateManager(api);

        manager.Registry.Register(3, StudentSid);

        Assert.False(manager.CheckAdmission(NewContext(4, StudentSid)));
        Assert.False(manager.CheckAdmission(NewContext(3, "S-1-5-21-999-888-777-6666")));
    }

    [Fact]
    public void AgentLaunchThrottled_RepeatedLoggedOnWithinMinInterval_ShouldLaunchOnce()
    {
        var agentPath = Path.GetTempFileName();
        try
        {
            var api = new FakeTerminalServicesApi();
            api.SessionUserSids[3] = StudentSid;
            using var manager = CreateManager(api, agentPath);

            manager.OnSessionChanged(new SessionChange(3, SessionChangeKind.LoggedOn));
            manager.OnSessionChanged(new SessionChange(3, SessionChangeKind.Reconnected));

            // 第二次（10 秒内）被限流拒绝
            Assert.Single(api.LaunchRequests);
        }
        finally
        {
            File.Delete(agentPath);
        }
    }

    [Fact]
    public void DisabledByEnvironment_ShouldNotLaunch()
    {
        var previous = Environment.GetEnvironmentVariable(EnabledVariable);
        Environment.SetEnvironmentVariable(EnabledVariable, "0");
        try
        {
            var api = new FakeTerminalServicesApi();
            api.SessionUserSids[3] = StudentSid;
            using var manager = CreateManager(api);

            Assert.False(manager.Enabled);
            manager.OnSessionChanged(new SessionChange(3, SessionChangeKind.LoggedOn));

            Assert.Empty(api.LaunchRequests);
        }
        finally
        {
            Environment.SetEnvironmentVariable(EnabledVariable, previous);
        }
    }

    [Fact]
    public void EnabledByDefault_WhenEnvironmentUnset()
    {
        var previous = Environment.GetEnvironmentVariable(EnabledVariable);
        Environment.SetEnvironmentVariable(EnabledVariable, null);
        try
        {
            var api = new FakeTerminalServicesApi();
            using var manager = CreateManager(api);
            Assert.True(manager.Enabled);
        }
        finally
        {
            Environment.SetEnvironmentVariable(EnabledVariable, previous);
        }
    }

    private static IpcHandshakeContext NewContext(int sessionId, string realSid) =>
        new() { RealSid = realSid, Pid = 1000 + sessionId, SessionId = sessionId };
}
