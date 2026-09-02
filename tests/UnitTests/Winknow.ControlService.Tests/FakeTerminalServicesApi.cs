using Winknow.ControlService.Sessions;

namespace Winknow.ControlService.Tests;

/// <summary>
/// 可配置的终端服务 fake：会话列表 / SID 查询 / 启动结果均可注入。
/// </summary>
public sealed class FakeTerminalServicesApi : ITerminalServicesApi
{
    public List<WtsSession> Sessions { get; } = new();

    public Dictionary<int, string> SessionUserSids { get; } = new();

    public List<int> LaunchRequests { get; } = new();

    public bool LaunchResult { get; set; } = true;

    public string LaunchError { get; set; } = string.Empty;

    public IReadOnlyList<WtsSession> EnumerateSessions() => Sessions.ToList();

    public bool TryGetSessionUserSid(int sessionId, out string userSid)
        => SessionUserSids.TryGetValue(sessionId, out userSid!) && !string.IsNullOrEmpty(userSid);

    public bool TryLaunchProcessInSession(int sessionId, string exePath, out int pid, out string error)
    {
        LaunchRequests.Add(sessionId);
        pid = LaunchResult ? 4000 + sessionId : 0;
        error = LaunchResult ? string.Empty : LaunchError;
        return LaunchResult;
    }
}
