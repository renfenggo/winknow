using System.Threading;
using Microsoft.Extensions.Logging;
using Winknow.Core.Results;

namespace Winknow.Security;

/// <summary>
/// 维护模式会话配置（依赖反转：审计与服务保护通过回调注入）。
/// </summary>
public sealed class MaintenanceSessionOptions
{
    /// <summary>维护密码的 Argon2id 哈希（MaintenancePassword.Hash 输出）。</summary>
    public required string PasswordHash { get; init; }

    /// <summary>TOTP 共享密钥原始字节。</summary>
    public required byte[] TotpSecret { get; init; }

    /// <summary>恢复码存储（紧急通道）。</summary>
    public required RecoveryCodeStore RecoveryCodes { get; init; }

    /// <summary>默认维护超时（分钟），默认 15。</summary>
    public int DefaultTimeoutMinutes { get; init; } = 15;

    /// <summary>进入维护时回调（如临时停止服务保护）。</summary>
    public Action? OnEnter { get; init; }

    /// <summary>退出维护时回调，参数 isTimeout 指示是否超时触发（如恢复服务保护）。</summary>
    public Action<bool>? OnExit { get; init; }

    /// <summary>审计回调：(actor, operation, reason, detail)。</summary>
    public Action<string, string, string?, string?>? OnAudit { get; init; }

    /// <summary>可选日志记录器。</summary>
    public ILogger? Logger { get; init; }
}

/// <summary>
/// 维护模式状态机 + 超时保护。
///
/// 用途：V7.0 第 6 周"维护模式权限验证、有效期、维护超时保护"。
/// 流程：Enter（密码+TOTP）或 EnterWithRecoveryCode → 启动超时定时器 →
///       Extend 延长 / Exit 主动退出 / 超时自动 Exit。
///
/// 安全约束：
/// - 不允许重入（已 Active 时 Enter 返回失败）
/// - 超时自动恢复保护（Timer 触发 OnExit(true)）
/// - 所有状态切换记审计
/// </summary>
public sealed class MaintenanceSession : IDisposable
{
    private readonly MaintenanceSessionOptions _options;
    private readonly object _lock = new();
    private Timer? _timeoutTimer;
    private bool _active;
    private DateTimeOffset _expiresAt;

    /// <summary>构造维护会话。</summary>
    /// <param name="options">会话配置。</param>
    public MaintenanceSession(MaintenanceSessionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
    }

    /// <summary>当前是否处于维护模式。</summary>
    public bool IsActive
    {
        get { lock (_lock) return _active; }
    }

    /// <summary>维护到期时间（UTC），未进入返回 null。</summary>
    public DateTimeOffset? ExpiresAt
    {
        get { lock (_lock) return _active ? _expiresAt : null; }
    }

    /// <summary>
    /// 密码 + TOTP 双因子进入维护模式。
    /// </summary>
    /// <param name="password">维护密码明文。</param>
    /// <param name="totpCode">6 位 TOTP。</param>
    /// <param name="actor">操作者标识（管理员名）。</param>
    /// <param name="reason">维护原因。</param>
    /// <returns>成功或失败结果。</returns>
    public Result Enter(string password, string totpCode, string actor, string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        ArgumentException.ThrowIfNullOrWhiteSpace(totpCode);
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);

        lock (_lock)
        {
            if (_active) return Result.Failure(ErrorCode.Unknown, "已在维护模式，请先退出");
        }

        if (!MaintenancePassword.Verify(password, _options.PasswordHash, _options.Logger))
        {
            _options.OnAudit?.Invoke(actor, "enter", reason, "password-mismatch");
            return Result.Failure(ErrorCode.Unauthorized, "维护密码错误");
        }

        if (!TotpGenerator.Verify(_options.TotpSecret, totpCode))
        {
            _options.OnAudit?.Invoke(actor, "enter", reason, "totp-mismatch");
            return Result.Failure(ErrorCode.Unauthorized, "TOTP 验证失败");
        }

        return Activate(actor, reason);
    }

    /// <summary>
    /// 紧急通道：恢复码进入（绕过密码+TOTP，码用后失效）。
    /// </summary>
    /// <param name="recoveryCode">恢复码。</param>
    /// <param name="actor">操作者标识。</param>
    /// <param name="reason">维护原因。</param>
    /// <returns>成功或失败结果。</returns>
    public Result EnterWithRecoveryCode(string recoveryCode, string actor, string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(recoveryCode);
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);

        lock (_lock)
        {
            if (_active) return Result.Failure(ErrorCode.Unknown, "已在维护模式，请先退出");
        }

        if (!_options.RecoveryCodes.VerifyAndConsume(recoveryCode))
        {
            _options.OnAudit?.Invoke(actor, "enter", reason, "recovery-code-invalid");
            return Result.Failure(ErrorCode.Unauthorized, "恢复码无效或已使用");
        }

        return Activate(actor, reason);
    }

    /// <summary>
    /// 延长维护时间（分钟），重置超时定时器。
    /// </summary>
    /// <param name="minutes">延长的分钟数。</param>
    /// <param name="actor">操作者标识。</param>
    /// <returns>成功或失败结果。</returns>
    public Result Extend(int minutes, string actor)
    {
        if (minutes <= 0)
        {
            return Result.Failure(ErrorCode.InvalidParameter, "延长时间必须为正数");
        }

        lock (_lock)
        {
            if (!_active) return Result.Failure(ErrorCode.Unknown, "未在维护模式");
            _expiresAt = _expiresAt.AddMinutes(minutes);
            ResetTimerLocked();
        }

        _options.OnAudit?.Invoke(actor, "extend", null, $"+{minutes}min");
        return Result.Success();
    }

    /// <summary>
    /// 主动退出维护模式。
    /// </summary>
    /// <param name="actor">操作者标识。</param>
    /// <param name="reason">退出原因。</param>
    /// <returns>成功或失败结果。</returns>
    public Result Exit(string actor, string? reason = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);
        return Deactivate(actor, "exit", reason, isTimeout: false);
    }

    private Result Activate(string actor, string reason)
    {
        lock (_lock)
        {
            _active = true;
            _expiresAt = DateTimeOffset.UtcNow.AddMinutes(_options.DefaultTimeoutMinutes);
            ResetTimerLocked();
        }

        try
        {
            _options.OnEnter?.Invoke();
        }
        catch (Exception ex)
        {
            _options.Logger?.LogError(ex, "OnEnter 回调异常");
        }

        _options.OnAudit?.Invoke(actor, "enter", reason, $"timeout={_options.DefaultTimeoutMinutes}min");
        return Result.Success();
    }

    private Result Deactivate(string actor, string operation, string? reason, bool isTimeout)
    {
        lock (_lock)
        {
            if (!_active) return Result.Failure(ErrorCode.Unknown, "未在维护模式");
            _active = false;
            _timeoutTimer?.Dispose();
            _timeoutTimer = null;
        }

        try
        {
            _options.OnExit?.Invoke(isTimeout);
        }
        catch (Exception ex)
        {
            _options.Logger?.LogError(ex, "OnExit 回调异常");
        }

        _options.OnAudit?.Invoke(actor, operation, reason, isTimeout ? "auto-timeout" : null);
        return Result.Success();
    }

    private void OnTimeout(object? state)
    {
        Deactivate("system", "timeout", null, isTimeout: true);
    }

    private void ResetTimerLocked()
    {
        _timeoutTimer?.Dispose();
        var dueMs = (int)Math.Max(0, (_expiresAt - DateTimeOffset.UtcNow).TotalMilliseconds);
        _timeoutTimer = new Timer(OnTimeout, null, dueMs, Timeout.Infinite);
    }

    /// <summary>释放定时器；若仍处于维护模式，触发超时退出。</summary>
    public void Dispose()
    {
        lock (_lock)
        {
            if (_active)
            {
                _active = false;
                try { _options.OnExit?.Invoke(true); }
                catch (Exception ex) { _options.Logger?.LogError(ex, "Dispose 时 OnExit 回调异常"); }
                _options.OnAudit?.Invoke("system", "timeout", null, "disposed-active");
            }
            _timeoutTimer?.Dispose();
            _timeoutTimer = null;
        }
    }
}
