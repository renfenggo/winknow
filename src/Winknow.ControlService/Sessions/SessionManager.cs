using Microsoft.Extensions.Logging;
using Winknow.Ipc;

namespace Winknow.ControlService.Sessions;

/// <summary>
/// 会话生命周期管理器（P2-02）：组合 SessionRegistry / WtsSessionMonitor / SessionAgentLauncher，
/// 与 IpcServer 协同形成闭环：
///
/// 1. WTS 轮询发现登录 → 取用户 SID 登记（SessionRegistry）→ 会话内拉起 SessionAgent；
/// 2. Agent 连接 ControlService → IpcServer 握手 admissionCheck 回调本管理器：
///    会话已登记 且 管道真实 SID 与登记 SID 一致才授予；
/// 3. 用户注销 → 注销登记（后续同会话 ID 复用的连接将被拒绝）；
/// 4. 服务停止 → 向所有活动 Agent 连接广播 Shutdown（优雅退出，避免 Agent 无限退避重连）。
///
/// 总开关：环境变量 SessionAgentEnabled=0/false 时禁用（回滚用），默认启用。
/// </summary>
public sealed class SessionManager : IDisposable
{
    private const string EnabledEnvVariable = "SessionAgentEnabled";

    private readonly ILogger<SessionManager>? _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ITerminalServicesApi _api;
    private IpcServer? _ipcServer;
    private readonly WtsSessionMonitor _monitor;
    private readonly SessionAgentLauncher _launcher;
    private bool _started;

    /// <summary>会话登记表（IPC 准入比对用）。</summary>
    public SessionRegistry Registry { get; } = new();

    /// <summary>是否启用会话管理（SessionAgentEnabled=0/false 可禁用，回滚开关）。</summary>
    public bool Enabled { get; }

    /// <summary>创建会话生命周期管理器。</summary>
    public SessionManager(
        ILoggerFactory loggerFactory,
        IpcServer? ipcServer = null,
        ITerminalServicesApi? terminalServicesApi = null,
        string? agentExePath = null)
    {
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<SessionManager>();
        _ipcServer = ipcServer;
        Enabled = IsEnabledByEnvironment();

        // 监视器与启动器共享同一 WTS API 实例（测试注入 fake 时全部走 fake）
        _api = terminalServicesApi ?? new TerminalServicesApi(loggerFactory.CreateLogger<TerminalServicesApi>());

        _monitor = new WtsSessionMonitor(
            _api,
            logger: loggerFactory.CreateLogger<WtsSessionMonitor>());
        _monitor.SessionChanged += OnSessionChanged;

        _launcher = new SessionAgentLauncher(
            _api,
            agentExePath,
            logger: loggerFactory.CreateLogger<SessionAgentLauncher>());
    }

    private static bool IsEnabledByEnvironment()
    {
        var value = Environment.GetEnvironmentVariable(EnabledEnvVariable);
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        return value.Trim() is not ("0" or "false" or "False" or "FALSE" or "disabled");
    }

    /// <summary>
    /// 延迟绑定 IPC 服务端（IpcServer 构造需要本管理器的 CheckAdmission 作准入回调，
    /// 两者相互依赖，构造顺序：new SessionManager → new IpcServer(admissionCheck) → AttachServer）。
    /// </summary>
    public void AttachServer(IpcServer ipcServer)
    {
        ArgumentNullException.ThrowIfNull(ipcServer);
        _ipcServer = ipcServer;
    }

    /// <summary>
    /// IpcServer 握手准入回调：会话已登记且真实 SID 与登记一致。
    /// （真实 SID 由 IpcServer 经管道 Impersonation 取得；本回调不做身份获取。）
    /// </summary>
    public bool CheckAdmission(IpcHandshakeContext context)
    {
        if (!Enabled)
        {
            // 禁用时学生 Agent 一律不授予（SYSTEM/Admins 管理通道仍由 authenticator 允许集合放行）
            return Registry.IsAdmissionAllowed(context.SessionId, context.RealSid);
        }

        var allowed = Registry.IsAdmissionAllowed(context.SessionId, context.RealSid);
        if (!allowed)
        {
            _logger?.LogWarning(
                "IPC admission denied for session {SessionId} (sid {Sid}, pid {Pid})",
                context.SessionId, context.RealSid, context.Pid);
        }

        return allowed;
    }

    /// <summary>启动会话监视。</summary>
    public void Start()
    {
        if (_started)
        {
            return;
        }

        _started = true;
        _logger?.LogInformation("Session manager starting (enabled: {Enabled})", Enabled);
        _monitor.Start();
    }

    /// <summary>
    /// 停止会话管理：广播 Shutdown 给所有 Agent 连接，停止监视。
    /// </summary>
    public async Task StopAsync()
    {
        if (!_started)
        {
            return;
        }

        _started = false;
        _monitor.Stop();

        if (_ipcServer is not null)
        {
            await BroadcastShutdownAsync().ConfigureAwait(false);
        }

        _logger?.LogInformation("Session manager stopped");
    }

    private async Task BroadcastShutdownAsync()
    {
        var server = _ipcServer;
        if (server is null)
        {
            return;
        }

        try
        {
            var payload = IpcProtocol.Encode(new LockPayload
            {
                Reason = "ControlService stopping",
                PolicyVersion = string.Empty
            });

            foreach (var record in Registry.Snapshot())
            {
                if (server.TryGetSession(record.SessionId, out var connection) && connection is not null)
                {
                    await connection.SendAsync(IpcConstants.MessageTypeShutdown, payload)
                        .ConfigureAwait(false);
                    _logger?.LogInformation("Shutdown sent to session {SessionId} agent", record.SessionId);
                }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to broadcast shutdown to session agents");
        }
    }

    /// <summary>会话差异事件处理（由内部监视器触发；internal 供单元测试直接驱动）。</summary>
    internal void OnSessionChanged(SessionChange change)
    {
        switch (change.Kind)
        {
            case SessionChangeKind.LoggedOn:
            case SessionChangeKind.Reconnected:
                EnsureAgentForSession(change.SessionId);
                break;

            case SessionChangeKind.LoggedOff:
                Registry.Unregister(change.SessionId);
                _logger?.LogInformation("Session {SessionId} logged off, unregistered", change.SessionId);
                break;

            case SessionChangeKind.Disconnected:
                // 断开：会话与 Agent 保留，仅记录
                _logger?.LogDebug("Session {SessionId} disconnected", change.SessionId);
                break;
        }
    }

    /// <summary>
    /// 登记会话并确保 Agent 已拉起（限流保护；Agent 单实例由其 SessionMutex 保证，
    /// 重复拉起的实例会自行退出）。
    /// </summary>
    private void EnsureAgentForSession(int sessionId)
    {
        if (!Enabled)
        {
            _logger?.LogDebug("Session agent disabled, skip launch for session {SessionId}", sessionId);
            return;
        }

        if (!Registry.TryGet(sessionId, out var record) || record is null)
        {
            if (!_api.TryGetSessionUserSid(sessionId, out var userSid))
            {
                // 服务会话（如 session 0）或无用户登录：无需登记/拉起
                _logger?.LogDebug("Session {SessionId} has no user token, skip", sessionId);
                return;
            }

            Registry.Register(sessionId, userSid);
            _logger?.LogInformation("Session {SessionId} registered (sid {Sid})", sessionId, userSid);
        }

        var result = _launcher.Launch(sessionId);
        if (!result.IsSuccess)
        {
            _logger?.LogWarning("SessionAgent launch not performed for session {SessionId}: {Error}",
                sessionId, result.ErrorMessage);
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _monitor.SessionChanged -= OnSessionChanged;
        _monitor.Dispose();
    }
}
