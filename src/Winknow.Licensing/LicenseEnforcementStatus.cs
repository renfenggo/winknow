namespace Winknow.Licensing;

/// <summary>
/// 授权执行状态：三态机。
/// </summary>
public enum LicenseEnforcementStatus
{
    /// <summary>在线授权正常。</summary>
    Online,

    /// <summary>断网宽限中（使用缓存的令牌）。</summary>
    GracePeriod,

    /// <summary>授权失败，需要锁定。</summary>
    Locked
}