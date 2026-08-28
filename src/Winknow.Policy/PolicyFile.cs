using System.Text.Json.Serialization;

namespace Winknow.Policy;

/// <summary>
/// V7.0 策略文件数据模型。
/// </summary>
public sealed class PolicyFile
{
    /// <summary>策略版本。</summary>
    public string Version { get; init; } = string.Empty;

    /// <summary>策略唯一标识。</summary>
    public string PolicyId { get; init; } = string.Empty;

    /// <summary>创建时间（ISO 8601）。</summary>
    public DateTime CreatedAt { get; init; }

    /// <summary>策略描述。</summary>
    public string Description { get; init; } = string.Empty;

    /// <summary>软件管控配置。</summary>
    public SoftwareControlSection SoftwareControl { get; init; } = new();

    /// <summary>网络管控配置。</summary>
    public NetworkControlSection NetworkControl { get; init; } = new();

    /// <summary>USB 管控配置。</summary>
    public UsbControlSection UsbControl { get; init; } = new();
}

/// <summary>
/// 软件管控配置。
/// </summary>
public sealed class SoftwareControlSection
{
    /// <summary>软件白名单。</summary>
    public SoftwareWhitelist Whitelist { get; init; } = new();

    /// <summary>学生编译产物输出目录配置。</summary>
    public StudentOutputSection StudentOutput { get; init; } = new();

    /// <summary>高风险解释器黑名单。</summary>
    public HighRiskInterpretersSection HighRiskInterpreters { get; init; } = new();
}

/// <summary>
/// 软件白名单配置。
/// </summary>
public sealed class SoftwareWhitelist
{
    /// <summary>按发布者名称白名单。</summary>
    public List<string> ByPublisher { get; init; } = new();

    /// <summary>按路径白名单。</summary>
    public List<PathRule> ByPath { get; init; } = new();

    /// <summary>按 Hash 白名单。</summary>
    public List<HashRule> ByHash { get; init; } = new();
}

/// <summary>
/// 路径白名单规则。
/// </summary>
public sealed class PathRule
{
    /// <summary>路径模式。</summary>
    public string Path { get; init; } = string.Empty;

    /// <summary>期望的文件 Hash（空表示不校验）。</summary>
    public string Hash { get; init; } = string.Empty;

    /// <summary>规则描述。</summary>
    public string Description { get; init; } = string.Empty;
}

/// <summary>
/// Hash 白名单规则。
/// </summary>
public sealed class HashRule
{
    /// <summary>SHA-256 哈希值。</summary>
    public string Hash { get; init; } = string.Empty;

    /// <summary>规则描述。</summary>
    public string Description { get; init; } = string.Empty;
}

/// <summary>
/// 学生编译产物配置。
/// </summary>
public sealed class StudentOutputSection
{
    /// <summary>允许的学生输出目录列表。</summary>
    public List<string> AllowedDirectories { get; init; } = new();

    /// <summary>编译产物最大有效时长（小时）。</summary>
    public int MaxValidityHours { get; init; } = 2;

    /// <summary>单文件最大大小（MB）。</summary>
    public int MaxFileSizeMB { get; init; } = 50;
}

/// <summary>
/// 高风险解释器配置。
/// </summary>
public sealed class HighRiskInterpretersSection
{
    /// <summary>阻止运行的解释器列表。</summary>
    public List<string> Blocked { get; init; } = new();
}

/// <summary>
/// 网络管控配置。
/// </summary>
public sealed class NetworkControlSection
{
    /// <summary>网站白名单。</summary>
    public WebsiteWhitelistSection WebsiteWhitelist { get; init; } = new();

    /// <summary>代理配置。</summary>
    public ProxySection Proxy { get; init; } = new();
}

/// <summary>
/// 网站白名单配置。
/// </summary>
public sealed class WebsiteWhitelistSection
{
    /// <summary>允许的域名列表（支持 * 通配符）。</summary>
    public List<string> Domains { get; init; } = new();
}

/// <summary>
/// 代理配置。
/// </summary>
public sealed class ProxySection
{
    /// <summary>是否允许自定义代理。</summary>
    public bool Allowed { get; init; } = false;

    /// <summary>是否强制使用系统代理。</summary>
    public bool ForceSystemProxy { get; init; } = true;
}

/// <summary>
/// USB 管控配置。
/// </summary>
public sealed class UsbControlSection
{
    /// <summary>Mass Storage 管控。</summary>
    public MassStorageSection MassStorage { get; init; } = new();

    /// <summary>HID 设备管控。</summary>
    public HidDevicesSection HidDevices { get; init; } = new();
}

/// <summary>
/// Mass Storage 管控配置。
/// </summary>
public sealed class MassStorageSection
{
    /// <summary>是否允许使用 USB 存储设备。</summary>
    public bool Enabled { get; init; } = false;

    /// <summary>管理员是否可覆盖。</summary>
    public bool AdminOverride { get; init; } = true;
}

/// <summary>
/// HID 设备管控配置。
/// </summary>
public sealed class HidDevicesSection
{
    /// <summary>是否允许使用 HID 设备（键盘、鼠标）。</summary>
    public bool Enabled { get; init; } = true;
}
