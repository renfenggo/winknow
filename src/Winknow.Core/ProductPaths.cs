namespace Winknow.Core;

/// <summary>
/// 产品路径唯一可信源（ADR-001 / TD-02，v8 计划 PR-01）。
/// 生产代码禁止自行拼接 Winknow 目录；测试与工具可用 <see cref="UseTestRoot"/> 注入临时根目录。
/// 生效策略独立于部署槽位存放，其版本切换由更新事务管理（v8 计划 P6-03 第 8 条）。
/// </summary>
public static class ProductPaths
{
    private static string? _dataRootOverride;

    /// <summary>ProgramData 数据根：%ProgramData%\Winknow。</summary>
    public static string DataRoot => _dataRootOverride ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Constants.ProductName);

    /// <summary>部署根：DataRoot\deploy（A/B 槽位与 Recovery Vault 所在）。</summary>
    public static string DeployRoot => Path.Combine(DataRoot, "deploy");

    /// <summary>Current 槽位（当前运行版本）。</summary>
    public static string CurrentSlotDir => Path.Combine(DeployRoot, "Current");

    /// <summary>Previous 槽位（可回滚版本）。</summary>
    public static string PreviousSlotDir => Path.Combine(DeployRoot, "Previous");

    /// <summary>Staging 槽位（更新暂存）。</summary>
    public static string StagingSlotDir => Path.Combine(DeployRoot, "Staging");

    /// <summary>Recovery 槽位（可信恢复库）。</summary>
    public static string RecoverySlotDir => Path.Combine(DeployRoot, "Recovery");

    /// <summary>SessionAgent 部署目录（随 Current 槽切换，由 ControlService 拉起）。</summary>
    public static string CurrentAgentDir => Path.Combine(CurrentSlotDir, "agent");

    /// <summary>策略目录。</summary>
    public static string PoliciesDir => Path.Combine(DataRoot, "policies");

    /// <summary>生效策略文件（更新事务管理其版本切换）。</summary>
    public static string ActivePolicyPath => Path.Combine(PoliciesDir, "active_policy.json");

    /// <summary>日志目录。</summary>
    public static string LogsDir => Path.Combine(DataRoot, "logs");

    /// <summary>设备密钥目录。</summary>
    public static string KeysDir => Path.Combine(DataRoot, "keys");

    /// <summary>维护模式配置目录。</summary>
    public static string MaintainDir => Path.Combine(DataRoot, "maintain");

    /// <summary>设备安全数据目录。</summary>
    public static string DeviceSecurityDir => Path.Combine(DataRoot, Constants.DeviceSecurity.DataDirName);

    /// <summary>更新验签公钥（TrustedUpdater apply 默认读取处）。</summary>
    public static string UpdatePublicKeyPath => Path.Combine(DeployRoot, "publickey.pem");

    /// <summary>心跳租约文件。</summary>
    public static string HeartbeatLeasePath => Path.Combine(DataRoot, Constants.Guard.HeartbeatFileName);

    /// <summary>
    /// 注入测试根目录；返回对象 Dispose 时恢复之前的根。仅测试与工具使用，生产代码不得调用。
    /// </summary>
    public static IDisposable UseTestRoot(string root)
    {
        var previous = _dataRootOverride;
        _dataRootOverride = root;
        return new RestoreRoot(() => _dataRootOverride = previous);
    }

    private sealed class RestoreRoot(Action restore) : IDisposable
    {
        public void Dispose() => restore();
    }
}
