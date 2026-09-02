namespace Winknow.Core;

/// <summary>
/// 服务标识唯一可信源（ADR-001 / TD-01，v8 计划 PR-01）。
/// SCM 内部名不带空格，用于 sc.exe / ServiceController / OpenService / 服务注册表路径；
/// 显示名仅供安装器 DisplayName、UI 与日志展示。
/// 生产代码禁止出现服务名字符串字面量（由架构测试强制）。
/// </summary>
public static class ServiceNames
{
    /// <summary>ControlService 的 SCM 内部名。</summary>
    public const string ControlService = "WinknowControl";

    /// <summary>GuardService 的 SCM 内部名。</summary>
    public const string GuardService = "WinknowGuard";

    /// <summary>ControlService 显示名（仅安装器 DisplayName 与 UI/日志）。</summary>
    public const string ControlServiceDisplayName = "Winknow Control Service";

    /// <summary>GuardService 显示名（仅安装器 DisplayName 与 UI/日志）。</summary>
    public const string GuardServiceDisplayName = "Winknow Guard Service";

    /// <summary>受管服务内部名列表（停启/健康检查遍历用）。</summary>
    public static readonly string[] Managed = [ControlService, GuardService];
}
