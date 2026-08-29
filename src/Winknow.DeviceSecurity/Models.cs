using System.Text.Json.Serialization;

namespace Winknow.DeviceSecurity;

/// <summary>
/// 设备启动安全模型（V7.0 第 11 周）。
///
/// 设计原则（对应验收项）：
/// - 每个检查项是独立实体（Id/权重/状态/详情/整改建议）——评分可追溯到原始检查项；
/// - 无法自动检测的项目状态为 <see cref="CheckStatus.Pending"/>（"需人工核验"），
///   永不映射为 Pass——不显示为通过；
/// - 固件指纹（BIOS 版本+发布日期+主板序列号）驱动核验记录的变化失效。
///
/// BitLocker 边界（V7.0 验收项）：
/// 本模块**不做** BitLocker/TPM 检测与加密管理——V7.0 的启动安全防线是
/// "Secure Boot + USB/PXE 禁用 + 进程管控"，全盘加密属学校镜像管理范畴；
/// 系统若已启用 BitLocker 与本模块正交，互不干预、互不依赖。
/// </summary>
    /// <summary>检查项状态。</summary>
    public enum CheckStatus
    {
        /// <summary>通过（自动检测或人工确认）。</summary>
        Pass = 0,

        /// <summary>未通过（检测到风险或人工确认不合规）。</summary>
        Fail = 1,

        /// <summary>需人工核验：无法自动检测且尚未人工确认——不视为通过。</summary>
        Pending = 2,

        /// <summary>不适用（如 Legacy 模式下无 Secure Boot 项——本身即风险，由依赖项表达）。</summary>
        NotApplicable = 3
    }

    /// <summary>设备安全等级。</summary>
    public enum SecurityGrade
    {
        /// <summary>安全：全部核验通过。</summary>
        Secure = 0,

        /// <summary>需关注：存在低权重未通过项。</summary>
        Attention = 1,

        /// <summary>高风险：高权重项未通过。</summary>
        HighRisk = 2,

        /// <summary>需人工核验：存在未核验项——评分不完整，不得视为通过。</summary>
        NeedsManualReview = 3
    }

    /// <summary>单个检查项（评分的可追溯原子）。</summary>
    public sealed class CheckItem
    {
        /// <summary>检查项唯一 Id（如 secure-boot、usb-boot）。</summary>
        [JsonPropertyName("id")] public string Id { get; set; } = string.Empty;

        /// <summary>标题（中文，供报告与 UI 展示）。</summary>
        [JsonPropertyName("title")] public string Title { get; set; } = string.Empty;

        /// <summary>类别：auto（自动检测）/ manual（人工核验）。</summary>
        [JsonPropertyName("category")] public string Category { get; set; } = "auto";

        /// <summary>权重（0-100，全部检查项权重之和为 100）。</summary>
        [JsonPropertyName("weight")] public int Weight { get; set; }

        /// <summary>当前状态。</summary>
        [JsonPropertyName("status")] public CheckStatus Status { get; set; } = CheckStatus.Pending;

        /// <summary>状态详情（自动检测的证据或人工备注）。</summary>
        [JsonPropertyName("detail")] public string Detail { get; set; } = string.Empty;

        /// <summary>整改建议（未通过时非空）。</summary>
        [JsonPropertyName("remediation")] public string Remediation { get; set; } = string.Empty;
    }

    /// <summary>固件信息（Win32_BIOS / Win32_BaseBoard / Win32_ComputerSystem 聚合）。</summary>
    public sealed class FirmwareInfo
    {
        /// <summary>BIOS 厂商。</summary>
        [JsonPropertyName("biosVendor")] public string BiosVendor { get; set; } = "Unknown";

        /// <summary>BIOS 版本（SMBIOSBIOSVersion）。</summary>
        [JsonPropertyName("biosVersion")] public string BiosVersion { get; set; } = "Unknown";

        /// <summary>BIOS 发布日期（WMI DMTF 格式原样或 ISO）。</summary>
        [JsonPropertyName("biosReleaseDate")] public string BiosReleaseDate { get; set; } = "Unknown";

        /// <summary>主板厂商。</summary>
        [JsonPropertyName("boardVendor")] public string BoardVendor { get; set; } = "Unknown";

        /// <summary>主板型号。</summary>
        [JsonPropertyName("boardModel")] public string BoardModel { get; set; } = "Unknown";

        /// <summary>主板序列号（变化失效指纹的组成部分）。</summary>
        [JsonPropertyName("boardSerial")] public string BoardSerial { get; set; } = "Unknown";

        /// <summary>整机厂商。</summary>
        [JsonPropertyName("systemVendor")] public string SystemVendor { get; set; } = "Unknown";

        /// <summary>整机型号。</summary>
        [JsonPropertyName("systemModel")] public string SystemModel { get; set; } = "Unknown";

        /// <summary>固件类型：UEFI 或 Legacy（Bios/Legacy PC）。</summary>
        [JsonPropertyName("firmwareType")] public string FirmwareType { get; set; } = "Unknown";

        /// <summary>采集时间（ISO 8601 UTC）。</summary>
        [JsonPropertyName("collectedAt")] public string CollectedAt { get; set; } = string.Empty;
    }

    /// <summary>启动配置采集结果。</summary>
    public sealed class BootConfigInfo
    {
        /// <summary>系统盘设备 ID（Win32_DiskPartition.DiskIndex）。</summary>
        [JsonPropertyName("systemDiskIndex")] public int? SystemDiskIndex { get; set; }

        /// <summary>系统分区表类型推断：GPT / MBR / Unknown。</summary>
        [JsonPropertyName("partitionStyle")] public string PartitionStyle { get; set; } = "Unknown";

        /// <summary>系统分区描述（如 GPT: System / Installable File System）。</summary>
        [JsonPropertyName("systemPartitionType")] public string SystemPartitionType { get; set; } = "Unknown";

        /// <summary>启动分区列表摘要（diskIndex:descrition 列表）。</summary>
        [JsonPropertyName("partitions")] public List<string> Partitions { get; set; } = new();

        /// <summary>BCD 启动项是否可读（bcdedit 权限）。</summary>
        [JsonPropertyName("bcdReadable")] public bool? BcdReadable { get; set; }

        /// <summary>采集时间（ISO 8601 UTC）。</summary>
        [JsonPropertyName("collectedAt")] public string CollectedAt { get; set; } = string.Empty;
    }

    /// <summary>人工核验记录条目。</summary>
    public sealed class ManualCheckResult
    {
        /// <summary>检查项 Id（ManualChecklist 中定义）。</summary>
        [JsonPropertyName("checkId")] public string CheckId { get; set; } = string.Empty;

        /// <summary>核验结果。</summary>
        [JsonPropertyName("status")] public CheckStatus Status { get; set; } = CheckStatus.Pending;

        /// <summary>核验备注（现场情况描述）。</summary>
        [JsonPropertyName("note")] public string Note { get; set; } = string.Empty;

        /// <summary>核验管理员。</summary>
        [JsonPropertyName("verifiedBy")] public string VerifiedBy { get; set; } = string.Empty;

        /// <summary>核验时间（ISO 8601 UTC）。</summary>
        [JsonPropertyName("verifiedAt")] public string VerifiedAt { get; set; } = string.Empty;
    }

    /// <summary>设备核验记录（持久化 JSON 顶层）。</summary>
    public sealed class VerificationRecord
    {
        /// <summary>设备 ID（Core.DeviceId）。</summary>
        [JsonPropertyName("deviceId")] public string DeviceId { get; set; } = string.Empty;

        /// <summary>核验时固件指纹（版本+日期+主板序列号，SHA256 前 16 字节 Hex）。</summary>
        [JsonPropertyName("firmwareFingerprint")] public string FirmwareFingerprint { get; set; } = string.Empty;

        /// <summary>核验时 BIOS 版本（报告展示用）。</summary>
        [JsonPropertyName("firmwareVersion")] public string FirmwareVersion { get; set; } = string.Empty;

        /// <summary>核验管理员。</summary>
        [JsonPropertyName("adminName")] public string AdminName { get; set; } = string.Empty;

        /// <summary>核验时间（ISO 8601 UTC）。</summary>
        [JsonPropertyName("verifiedAt")] public string VerifiedAt { get; set; } = string.Empty;

        /// <summary>备注。</summary>
        [JsonPropertyName("notes")] public string Notes { get; set; } = string.Empty;

        /// <summary>人工核验明细。</summary>
        [JsonPropertyName("checklist")] public List<ManualCheckResult> Checklist { get; set; } = new();
    }

    /// <summary>设备安全完整报告（评估门面输出）。</summary>
    public sealed class DeviceSecurityReport
    {
        /// <summary>设备 ID。</summary>
        [JsonPropertyName("deviceId")] public string DeviceId { get; set; } = string.Empty;

        /// <summary>固件信息。</summary>
        [JsonPropertyName("firmware")] public FirmwareInfo Firmware { get; set; } = new();

        /// <summary>Secure Boot 状态描述（Enabled/Disabled/Unknown/NotSupported）。</summary>
        [JsonPropertyName("secureBootState")] public string SecureBootState { get; set; } = "Unknown";

        /// <summary>启动配置。</summary>
        [JsonPropertyName("bootConfig")] public BootConfigInfo BootConfig { get; set; } = new();

        /// <summary>全部检查项（自动+人工）。</summary>
        [JsonPropertyName("checks")] public List<CheckItem> Checks { get; set; } = new();

        /// <summary>评分（0-100，通过项权重之和）。</summary>
        [JsonPropertyName("score")] public int Score { get; set; }

        /// <summary>等级（存在 Pending 时恒为 NeedsManualReview）。</summary>
        [JsonPropertyName("grade")] public SecurityGrade Grade { get; set; } = SecurityGrade.NeedsManualReview;

        /// <summary>既有核验记录是否与当前固件匹配（变化失效判定结果）。</summary>
        [JsonPropertyName("verificationCurrent")] public bool? VerificationCurrent { get; set; }

        /// <summary>报告生成时间（ISO 8601 UTC）。</summary>
        [JsonPropertyName("generatedAt")] public string GeneratedAt { get; set; } = string.Empty;
    }