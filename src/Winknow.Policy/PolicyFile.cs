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

    /// <summary>DNS 管控配置。</summary>
    public DnsSection Dns { get; init; } = new();

    /// <summary>浏览器企业策略配置。</summary>
    public BrowserPolicySection BrowserPolicy { get; init; } = new();

    /// <summary>VPN/TUN 检测配置。</summary>
    public VpnDetectionSection VpnDetection { get; init; } = new();

    /// <summary>网站健康检测配置。</summary>
    public WebsiteHealthSection WebsiteHealth { get; init; } = new();
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

    /// <summary>PAC 配置。</summary>
    public PacSection Pac { get; init; } = new();

    /// <summary>失败模式：strict（失败阻断，不静默放行）或 lenient（宽松，失败放行）。</summary>
    public string FailMode { get; init; } = "strict";
}

/// <summary>
/// PAC（代理自动配置）策略。
/// </summary>
public sealed class PacSection
{
    /// <summary>是否允许使用 PAC。</summary>
    public bool Allowed { get; init; } = false;

    /// <summary>允许的 PAC AutoConfigURL（空表示禁止任何 PAC）。</summary>
    public string AutoConfigUrl { get; init; } = string.Empty;
}

/// <summary>
/// DNS 管控配置。
/// </summary>
public sealed class DnsSection
{
    /// <summary>允许的 DNS 服务器列表（IPv4/IPv6）。空表示不校验。</summary>
    public List<string> AllowedServers { get; init; } = new();

    /// <summary>禁止的公共 DNS 服务器列表（如 8.8.8.8、1.1.1.1）。</summary>
    public List<string> BlockedServers { get; init; } = new();

    /// <summary>是否检测 DoH（DNS over HTTPS）。</summary>
    public bool BlockDoh { get; init; } = true;
}

/// <summary>
/// 浏览器企业策略配置。
/// </summary>
public sealed class BrowserPolicySection
{
    /// <summary>Chrome 企业策略。</summary>
    public BrowserPolicyTarget Chrome { get; init; } = new();

    /// <summary>Edge 企业策略。</summary>
    public BrowserPolicyTarget Edge { get; init; } = new();
}

/// <summary>
/// 单个浏览器的企业策略目标。
/// </summary>
public sealed class BrowserPolicyTarget
{
    /// <summary>是否禁用浏览器自定义代理设置。</summary>
    public bool DisableCustomProxy { get; init; } = true;

    /// <summary>是否禁用 DoH（DNS over HTTPS）。</summary>
    public bool DisableDoh { get; init; } = true;

    /// <summary>是否禁用安全 DNS。</summary>
    public bool DisableSecureDns { get; init; } = true;
}

/// <summary>
/// VPN/TUN 检测配置。
/// </summary>
public sealed class VpnDetectionSection
{
    /// <summary>已知 VPN 客户端进程名黑名单。</summary>
    public List<string> BlockedProcesses { get; init; } = new();

    /// <summary>已知 VPN 服务名黑名单。</summary>
    public List<string> BlockedServices { get; init; } = new();

    /// <summary>是否检测虚拟网卡（TUN/TAP）。</summary>
    public bool DetectVirtualAdapters { get; init; } = true;
}

/// <summary>
/// 网站健康检测配置。
/// </summary>
public sealed class WebsiteHealthSection
{
    /// <summary>需检测的端点列表（URL + 名称）。</summary>
    public List<HealthEndpoint> Endpoints { get; init; } = new();

    /// <summary>检测超时（秒）。</summary>
    public int TimeoutSeconds { get; init; } = 5;

    /// <summary>检测间隔（秒）。</summary>
    public int IntervalSeconds { get; init; } = 60;
}

/// <summary>
/// 健康检测端点。
/// </summary>
public sealed class HealthEndpoint
{
    /// <summary>端点名称。</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>完整 URL。</summary>
    public string Url { get; init; } = string.Empty;

    /// <summary>期望的 HTTP 状态码（0 表示不校验，仅校验可达）。</summary>
    public int ExpectedStatus { get; init; } = 200;
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
