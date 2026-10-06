using System.Collections.Concurrent;
using System.Security.Principal;
using Winknow.Core;
using Winknow.Core.Results;

namespace Winknow.Ipc;

/// <summary>
/// IPC 身份验证器和防重放检测器。
///
/// 校验规则（见《V7.0 组件架构设计》第 6.3 节）：
/// 1. 时间戳偏差超过 ±60 秒 → 拒绝（防篡改时间）
/// 2. Nonce 在 5 分钟内不得重复（防重放，跨连接全局查重）
/// 3. SenderSid 必须属于允许的 SID 集合（身份验证）
/// 4. DeviceId 必须与本机匹配（设备绑定）
///
/// RequestId 单调递增检查按连接在 IpcServer 会话层执行：同一 SID 的多个客户端
/// （ADR-002：Bridge 与 SessionAgent 并存）各自维护独立 RequestId 时钟，跨连接的
/// 全局单调无法成立；跨连接重放防护由本类的 Nonce 全局查重承担。
/// </summary>
public sealed class IpcAuthenticator : IDisposable
{
    private readonly ConcurrentDictionary<string, long> _nonceCache = new();
    private readonly ConcurrentDictionary<string, long> _allowedSids;
    private readonly string _expectedDeviceId;
    private readonly TimeProvider _timeProvider;
    private readonly object _cleanupLock = new();
    private long _lastCleanupTime;

    /// <summary>动态 SID 条目的"永不过期"标记值（静态白名单沿用）。</summary>
    private const long NoExpiry = 0;

    /// <summary>
    /// 创建 IPC 身份验证器。
    /// </summary>
    /// <param name="allowedSids">允许的发送方 SID 集合（SYSTEM、Administrators、当前会话用户）。</param>
    /// <param name="expectedDeviceId">本机设备 ID。</param>
    /// <param name="timeProvider">时间提供者（便于测试）。</param>
    public IpcAuthenticator(IEnumerable<string> allowedSids, string expectedDeviceId, TimeProvider? timeProvider = null)
    {
        _allowedSids = new ConcurrentDictionary<string, long>(StringComparer.Ordinal);
        foreach (var sid in allowedSids) _allowedSids[sid] = NoExpiry;
        _expectedDeviceId = expectedDeviceId ?? throw new ArgumentNullException(nameof(expectedDeviceId));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _lastCleanupTime = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
    }

    /// <summary>
    /// 验证消息身份和防重放。
    /// </summary>
    public Result<IpcMessage> ValidateMessage(
        IpcMessage message,
        string? actualDeviceId = null,
        string? actualSenderSid = null)
    {
        ArgumentNullException.ThrowIfNull(message);

        // 1. 协议版本校验
        if (message.Version != IpcMessage.CurrentVersion)
        {
            return Result<IpcMessage>.Failure(ErrorCode.IpcReplayDetected, "Unsupported protocol version.");
        }

        // 2. 消息类型校验（防止伪造消息类型）
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

        // 4. SenderSid 身份校验（动态授权条目过期即移除并显式区分错误码，ADR-002）
        if (string.IsNullOrEmpty(message.SenderSid) || !_allowedSids.TryGetValue(message.SenderSid, out var sidExpiry))
        {
            return Result<IpcMessage>.Failure(ErrorCode.Unauthorized, "Sender SID not allowed.");
        }

        if (sidExpiry != NoExpiry && now >= sidExpiry)
        {
            _allowedSids.TryRemove(message.SenderSid, out _);
            return Result<IpcMessage>.Failure(ErrorCode.IpcSidExpired, "Dynamic SID authorization expired.");
        }

        // SenderSid is audit metadata only.  When a server provides the SID obtained
        // from Named Pipe impersonation it must exactly match the wire value.
        if (actualSenderSid is not null && !string.Equals(message.SenderSid, actualSenderSid, StringComparison.Ordinal))
        {
            return Result<IpcMessage>.Failure(ErrorCode.Unauthorized, "Sender SID does not match pipe client identity.");
        }

        // 5. Nonce 重复校验（5 分钟内不得重复）
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
        if (actualDeviceId is not null && !string.Equals(actualDeviceId, _expectedDeviceId, StringComparison.Ordinal))
        {
            return Result<IpcMessage>.Failure(ErrorCode.Unauthorized, "Device ID mismatch.");
        }

        // 校验通过，更新缓存
        _nonceCache[nonceKey] = nonceExpiration;

        // 6. 定期清理过期 Nonce
        TryCleanupExpiredNonces(now);

        return Result<IpcMessage>.Success(message);
    }

    /// <summary>
    /// 添加允许的 SID（静态白名单，永不过期）。
    /// </summary>
    public void AllowSid(string sid)
    {
        ArgumentException.ThrowIfNullOrEmpty(sid);
        _allowedSids[sid] = NoExpiry;
    }

    /// <summary>
    /// 动态授权 SID 并绑定过期时间（ADR-002：登录会话建立时授予，TTL 上限 8 小时）。
    /// </summary>
    /// <param name="sid">发送方 SID。</param>
    /// <param name="ttl">授权有效期（&gt;0，超出上限由调用方截断）。</param>
    public void AllowSid(string sid, TimeSpan ttl)
    {
        ArgumentException.ThrowIfNullOrEmpty(sid);
        if (ttl <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(ttl), "TTL must be positive.");
        }

        _allowedSids[sid] = _timeProvider.GetUtcNow().Add(ttl).ToUnixTimeMilliseconds();
    }

    /// <summary>
    /// 移除允许的 SID（例如会话注销后移除用户 SID）。
    /// </summary>
    public void RevokeSid(string sid)
    {
        ArgumentException.ThrowIfNullOrEmpty(sid);
        _allowedSids.TryRemove(sid, out _);
    }

    /// <summary>
    /// 获取当前允许的 SID 集合快照（不含已过期条目）。
    /// </summary>
    public IReadOnlyCollection<string> GetAllowedSids()
    {
        var now = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
        return _allowedSids
            .Where(kvp => kvp.Value == NoExpiry || kvp.Value > now)
            .Select(kvp => kvp.Key)
            .ToArray();
    }

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
