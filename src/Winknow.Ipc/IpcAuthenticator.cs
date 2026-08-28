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
/// 2. RequestId 必须大于上次收到的值（防重放）
/// 3. Nonce 在 5 分钟内不得重复（防重放）
/// 4. SenderSid 必须属于允许的 SID 集合（身份验证）
/// 5. DeviceId 必须与本机匹配（设备绑定）
/// </summary>
public sealed class IpcAuthenticator : IDisposable
{
    private readonly ConcurrentDictionary<string, long> _nonceCache = new();
    private readonly ConcurrentDictionary<string, uint> _lastRequestIdPerSid = new();
    private readonly HashSet<string> _allowedSids;
    private readonly string _expectedDeviceId;
    private readonly TimeProvider _timeProvider;
    private readonly object _cleanupLock = new();
    private long _lastCleanupTime;

    /// <summary>
    /// 创建 IPC 身份验证器。
    /// </summary>
    /// <param name="allowedSids">允许的发送方 SID 集合（SYSTEM、Administrators、当前会话用户）。</param>
    /// <param name="expectedDeviceId">本机设备 ID。</param>
    /// <param name="timeProvider">时间提供者（便于测试）。</param>
    public IpcAuthenticator(IEnumerable<string> allowedSids, string expectedDeviceId, TimeProvider? timeProvider = null)
    {
        _allowedSids = new HashSet<string>(allowedSids, StringComparer.Ordinal);
        _expectedDeviceId = expectedDeviceId ?? throw new ArgumentNullException(nameof(expectedDeviceId));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _lastCleanupTime = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
    }

    /// <summary>
    /// 验证消息身份和防重放。
    /// </summary>
    public Result<IpcMessage> ValidateMessage(IpcMessage message, string? actualDeviceId = null)
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

        // 4. SenderSid 身份校验
        if (string.IsNullOrEmpty(message.SenderSid) || !_allowedSids.Contains(message.SenderSid))
        {
            return Result<IpcMessage>.Failure(ErrorCode.Unauthorized, "Sender SID not allowed.");
        }

        // 5. RequestId 单调递增校验（按 SID 分组）
        if (_lastRequestIdPerSid.TryGetValue(message.SenderSid, out var lastRequestId))
        {
            if (message.RequestId <= lastRequestId)
            {
                return Result<IpcMessage>.Failure(ErrorCode.IpcReplayDetected, "RequestId not monotonically increasing.");
            }
        }

        // 6. Nonce 重复校验（5 分钟内不得重复）
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
        _lastRequestIdPerSid[message.SenderSid] = message.RequestId;

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
        _lastRequestIdPerSid.TryRemove(sid, out _);
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
        _lastRequestIdPerSid.Clear();
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
