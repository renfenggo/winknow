using System.Collections.Concurrent;
using System.Security.Principal;
using Winknow.Core;
using Winknow.Core.Results;

namespace Winknow.Ipc;

/// <summary>
/// IPC 身份验证器和防重放检测器（P2-01 重构，ADR-001/TD-05）。
///
/// 身份唯一凭证：服务端通过 Pipe Impersonation 取得的真实 SID（realSid）。
/// 消息体 SenderSid 仅用于审计，且必须与真实 SID 一致（固定时间比较）——伪造即拒绝。
///
/// 校验规则：
/// 1. 协议版本必须一致（防降级）
/// 2. MessageType 不得为 Error（防伪造错误消息注入）
/// 3. 时间戳偏差超过 ±60 秒 → 拒绝（防篡改时间）
/// 4. 真实 SID 必须在允许集合内（SYSTEM/Administrators；登记学生会话由准入回调判定）
/// 5. SenderSid 必须与真实 SID 一致（固定时间比较）
/// 6. Nonce 在 TTL 内不得重复（全局缓存，跨连接防重放）
/// 7. RequestId 单调性由 IpcConnectionGuard 按连接维护（重连即重置）
/// </summary>
public sealed class IpcAuthenticator : IDisposable
{
    private readonly ConcurrentDictionary<string, long> _nonceCache = new();
    private readonly HashSet<string> _allowedSids;
    private readonly string _expectedDeviceId;
    private readonly TimeProvider _timeProvider;
    private readonly object _cleanupLock = new();
    private long _lastCleanupTime;

    /// <summary>
    /// 创建 IPC 身份验证器。
    /// </summary>
    /// <param name="allowedSids">允许连接的真实 SID 集合（SYSTEM、Administrators、登记学生用户）。</param>
    /// <param name="expectedDeviceId">本机设备 ID。</param>
    /// <param name="timeProvider">时间提供者（便于测试）。</param>
    public IpcAuthenticator(IEnumerable<string> allowedSids, string expectedDeviceId, TimeProvider? timeProvider = null)
    {
        _allowedSids = new HashSet<string>(allowedSids, StringComparer.Ordinal);
        _expectedDeviceId = expectedDeviceId ?? throw new ArgumentNullException(nameof(expectedDeviceId));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _lastCleanupTime = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
    }

    /// <summary>真实 SID 是否在允许集合内（握手准入用）。</summary>
    public bool IsSidAllowed(string sid)
    {
        ArgumentException.ThrowIfNullOrEmpty(sid);
        return _allowedSids.Contains(sid);
    }

    /// <summary>
    /// 验证消息身份和防重放。
    /// </summary>
    /// <param name="message">待验证消息。</param>
    /// <param name="realSid">服务端 Impersonation 取得的真实 SID（唯一身份凭证）。</param>
    /// <param name="actualDeviceId">本机实际设备 ID（可选，用于设备绑定校验）。</param>
    public Result<IpcMessage> ValidateMessage(IpcMessage message, string realSid, string? actualDeviceId = null)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentException.ThrowIfNullOrEmpty(realSid);

        // 1. 协议版本校验（防降级）
        if (message.Version != IpcMessage.CurrentVersion)
        {
            return Result<IpcMessage>.Failure(ErrorCode.IpcReplayDetected, "Unsupported protocol version.");
        }

        // 2. 消息类型校验（防止伪造错误消息注入）
        if (message.MessageType == IpcConstants.MessageTypeError)
        {
            return Result<IpcMessage>.Failure(ErrorCode.InvalidParameter, "Error message type cannot be inbound.");
        }

        // 3. 时间戳偏差校验（±60 秒）
        var now = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
        var timestampDelta = now - message.Timestamp;
        if (Math.Abs(timestampDelta) > IpcConstants.TimestampToleranceMs)
        {
            return Result<IpcMessage>.Failure(ErrorCode.IpcTimeout, "Message timestamp out of tolerance.");
        }

        // 4. 真实 SID 准入校验（身份唯一凭证）
        if (!_allowedSids.Contains(realSid))
        {
            return Result<IpcMessage>.Failure(ErrorCode.Unauthorized, "Impersonated SID not allowed.");
        }

        // 5. 声明 SID 与真实 SID 一致性（固定时间比较，防伪造）
        if (string.IsNullOrEmpty(message.SenderSid) ||
            !SecurityUtils.FixedTimeEquals(message.SenderSid, realSid))
        {
            return Result<IpcMessage>.Failure(ErrorCode.Unauthorized, "Claimed SID does not match impersonated identity.");
        }

        // 6. Nonce 重复校验（TTL 内不得重复，跨连接生效）
        var nonceKey = Convert.ToHexString(message.Nonce);
        var nonceExpiration = message.Timestamp + IpcConstants.NonceCacheTtlMs;
        if (_nonceCache.TryGetValue(nonceKey, out var existingExpiration))
        {
            if (existingExpiration > message.Timestamp)
            {
                return Result<IpcMessage>.Failure(ErrorCode.IpcReplayDetected, "Nonce already used within TTL.");
            }
        }

        // 7. 设备 ID 校验（如果提供了实际设备 ID）
        if (actualDeviceId is not null && !SecurityUtils.FixedTimeEquals(actualDeviceId, _expectedDeviceId))
        {
            return Result<IpcMessage>.Failure(ErrorCode.Unauthorized, "Device ID mismatch.");
        }

        // 校验通过，登记 Nonce
        _nonceCache[nonceKey] = nonceExpiration;

        // 8. 定期清理过期 Nonce
        TryCleanupExpiredNonces(now);

        return Result<IpcMessage>.Success(message);
    }

    /// <summary>
    /// 添加允许的 SID。
    /// </summary>
    public void AllowSid(string sid)
    {
        ArgumentException.ThrowIfNullOrEmpty(sid);
        _allowedSids.Add(sid);
    }

    /// <summary>
    /// 移除允许的 SID（例如会话注销后移除用户 SID）。
    /// </summary>
    public void RevokeSid(string sid)
    {
        ArgumentException.ThrowIfNullOrEmpty(sid);
        _allowedSids.Remove(sid);
    }

    /// <summary>
    /// 获取当前允许的 SID 集合快照。
    /// </summary>
    public IReadOnlyCollection<string> GetAllowedSids() => _allowedSids;

    private void TryCleanupExpiredNonces(long now)
    {
        if (now - _lastCleanupTime < 60_000)
        {
            return;
        }

        lock (_cleanupLock)
        {
            if (now - _lastCleanupTime < 60_000)
            {
                return;
            }

            _lastCleanupTime = now;
            var expiredKeys = _nonceCache
                .Where(kvp => kvp.Value < now)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var key in expiredKeys)
            {
                _nonceCache.TryRemove(key, out _);
            }
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _nonceCache.Clear();
    }

    /// <summary>
    /// 创建默认身份验证器（允许 SYSTEM 和 Administrators）。
    /// </summary>
    public static IpcAuthenticator CreateForControlService(string expectedDeviceId, TimeProvider? timeProvider = null)
    {
        var allowedSids = new List<string>();

        // SYSTEM SID
        var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        allowedSids.Add(systemSid.Value);

        // Administrators SID
        var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        allowedSids.Add(adminsSid.Value);

        return new IpcAuthenticator(allowedSids, expectedDeviceId, timeProvider);
    }
}
