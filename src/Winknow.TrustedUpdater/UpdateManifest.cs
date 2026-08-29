using System.Text.Json;
using System.Text.Json.Serialization;

namespace Winknow.TrustedUpdater;

/// <summary>
/// 更新包清单（manifest.json）。
///
/// 用途：V7.0 第 7 周"TrustedUpdater 验证签名、产品标识、目标版本和文件 Hash"。
/// 包含产品标识、目标版本、最低兼容版本、降级黑名单、组件版本一致性声明、文件 Hash 清单。
/// 签名字段（Signature）为 RSA-SHA256 对"不含签名的清单规范 JSON"的签名（base64）。
/// </summary>
public sealed class UpdateManifest
{
    /// <summary>产品标识，必须与本机已安装产品一致（防跨产品安装）。</summary>
    public string ProductId { get; set; } = string.Empty;

    /// <summary>目标版本（如 7.0.1）。</summary>
    public string Version { get; set; } = string.Empty;

    /// <summary>最低兼容版本：低于此版本的当前安装不允许直接跳升到此版本。</summary>
    public string MinCompatibleVersion { get; set; } = string.Empty;

    /// <summary>降级黑名单：已知不安全版本，禁止回滚到此清单中的版本。</summary>
    public List<string> RollbackBlacklist { get; set; } = new();

    /// <summary>组件版本声明（ControlService/GuardService/SessionAgent），用于版本一致性校验。</summary>
    public Dictionary<string, string> Components { get; set; } = new();

    /// <summary>文件清单（相对路径 + SHA256）。</summary>
    public List<FileEntry> Files { get; set; } = new();

    /// <summary>构建时间（ISO 8601）。</summary>
    public string BuildTime { get; set; } = string.Empty;

    /// <summary>RSA-SHA256 签名（base64），null 表示未签名。</summary>
    [JsonPropertyName("Signature")]
    public string? Signature { get; set; }

    /// <summary>
    /// 生成用于签名的规范 JSON（不含 Signature 字段，属性按固定顺序）。
    /// </summary>
    public string ToSignableJson()
    {
        var copy = new UpdateManifest
        {
            ProductId = ProductId,
            Version = Version,
            MinCompatibleVersion = MinCompatibleVersion,
            RollbackBlacklist = RollbackBlacklist,
            Components = Components,
            Files = Files,
            BuildTime = BuildTime,
            Signature = null
        };
        return JsonSerializer.Serialize(copy, SignableJsonOptions);
    }

    /// <summary>
    /// 从 JSON 解析清单。
    /// </summary>
    /// <param name="json">manifest.json 内容。</param>
    /// <returns>清单对象。</returns>
    public static UpdateManifest Parse(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        return JsonSerializer.Deserialize<UpdateManifest>(json, SignableJsonOptions)
            ?? throw new InvalidDataException("清单解析失败");
    }

    private static readonly JsonSerializerOptions SignableJsonOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };
}

/// <summary>
/// 文件清单条目。
/// </summary>
public sealed class FileEntry
{
    /// <summary>相对路径（使用 / 分隔）。</summary>
    public string RelativePath { get; set; } = string.Empty;

    /// <summary>SHA256（小写 hex）。</summary>
    public string Sha256 { get; set; } = string.Empty;
}
