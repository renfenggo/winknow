using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Winknow.Core;
using Winknow.Core.Results;

namespace Winknow.ControlService.Sessions;

/// <summary>
/// SessionAgent 启动器（P2-02）：在目标用户会话内以该用户身份拉起 Agent。
///
/// - 启动前校验：exe 存在性 + SHA-256 哈希写审计（哈希基线校验属 P4-01，此处仅记录）；
/// - 崩溃重启限流：SessionLaunchThrottle（同会话 10s 间隔 + 每小时 6 次）；
/// - CreateProcessAsUser 全部封装在 TerminalServicesApi，Worker 不直接调用（架构约束）。
/// </summary>
public sealed class SessionAgentLauncher
{
    /// <summary>限流规则。</summary>
    public SessionLaunchThrottle Throttle { get; }

    private readonly ITerminalServicesApi _api;
    private readonly ILogger<SessionAgentLauncher>? _logger;
    private readonly string _agentExePath;
    private string? _lastHash;

    /// <summary>创建 Agent 启动器。</summary>
    public SessionAgentLauncher(
        ITerminalServicesApi api,
        string? agentExePath = null,
        SessionLaunchThrottle? throttle = null,
        ILogger<SessionAgentLauncher>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(api);
        _api = api;
        _logger = logger;
        Throttle = throttle ?? new SessionLaunchThrottle();
        _agentExePath = agentExePath ?? ResolveDefaultAgentPath();
    }

    /// <summary>Agent exe 路径（解析结果，供诊断）。</summary>
    public string AgentExePath => _agentExePath;

    /// <summary>解析默认 Agent 路径：优先部署 Current 槽位，开发裸跑回退输出目录。</summary>
    private static string ResolveDefaultAgentPath()
    {
        var deployed = Path.Combine(ProductPaths.CurrentAgentDir, "Winknow.SessionAgent.exe");
        if (File.Exists(deployed))
        {
            return deployed;
        }

        return Path.Combine(AppContext.BaseDirectory, "Winknow.SessionAgent.exe");
    }

    /// <summary>
    /// 在指定会话内启动 Agent。
    /// </summary>
    /// <param name="sessionId">目标 WTS 会话 ID。</param>
    public Result<int> Launch(int sessionId)
    {
        var now = DateTimeOffset.UtcNow;
        if (!Throttle.IsAllowed(sessionId, now))
        {
            _logger?.LogWarning(
                "SessionAgent launch throttled for session {SessionId} (min-interval/hourly-cap exceeded); giving up this round",
                sessionId);
            return Result<int>.Failure(ErrorCode.ExternalError, "Launch throttled.");
        }

        if (!File.Exists(_agentExePath))
        {
            _logger?.LogError("SessionAgent exe not found at {Path}; cannot launch in session {SessionId}",
                _agentExePath, sessionId);
            return Result<int>.Failure(ErrorCode.PathNotFound, $"Agent exe not found: {_agentExePath}");
        }

        // 启动前审计：记录二进制哈希（签名/哈希基线校验属 P4-01）
        var hash = ComputeSha256(_agentExePath);
        if (hash is not null)
        {
            if (_lastHash is not null && _lastHash != hash)
            {
                _logger?.LogWarning("SessionAgent binary hash changed since last launch: {Hash}", hash);
            }

            _lastHash = hash;
        }

        if (!_api.TryLaunchProcessInSession(sessionId, _agentExePath, out var pid, out var error))
        {
            _logger?.LogError("Failed to launch SessionAgent in session {SessionId}: {Error}", sessionId, error);
            return Result<int>.Failure(ErrorCode.ExternalError, error);
        }

        Throttle.Record(sessionId, now);
        _logger?.LogInformation(
            "SessionAgent launched in session {SessionId} (pid {Pid}, sha256 {Hash})",
            sessionId, pid, hash ?? "(n/a)");
        return Result<int>.Success(pid);
    }

    private static string? ComputeSha256(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream));
        }
        catch (Exception)
        {
            return null;
        }
    }
}
