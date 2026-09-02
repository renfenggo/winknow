namespace Winknow.ControlService.Sessions;

/// <summary>
/// 终端服务（WTS）API 抽象。
/// 抽象成接口便于单元测试注入 fake（差异检测与启动逻辑不依赖真实 WTS）。
/// </summary>
public interface ITerminalServicesApi
{
    /// <summary>枚举当前所有 WTS 会话快照。</summary>
    IReadOnlyList<WtsSession> EnumerateSessions();

    /// <summary>查询指定会话登录用户的 SID（无用户令牌的服务会话返回 false）。</summary>
    bool TryGetSessionUserSid(int sessionId, out string userSid);

    /// <summary>
    /// 在指定用户会话内以该用户身份启动进程（WTSQueryUserToken + CreateProcessAsUserW）。
    /// </summary>
    /// <param name="sessionId">目标 WTS 会话 ID。</param>
    /// <param name="exePath">要启动的 exe 绝对路径。</param>
    /// <param name="pid">启动成功时的进程 ID。</param>
    /// <param name="error">失败原因。</param>
    bool TryLaunchProcessInSession(int sessionId, string exePath, out int pid, out string error);
}
