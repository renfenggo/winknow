using System.Text.Json;

namespace Winknow.Logging;

/// <summary>
/// 隐私说明：声明默认收集和不收集的字段。
/// 验收项：默认不记录网页正文和学生代码正文。
/// 验收项：密码、密钥、恢复码不进入普通日志。
/// </summary>
public sealed class PrivacyPolicy
{
    /// <summary>默认收集的字段（仅记录非敏感元数据）。</summary>
    public static readonly IReadOnlySet<string> CollectedFields = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        // 设备信息
        "DeviceId", "MachineName", "OSVersion",
        // 进程信息
        "ProcessName", "ProcessId", "ParentProcessName",
        // 时间戳
        "Timestamp", "EventTime",
        // 事件类型
        "EventType", "Action", "Result", "ErrorCode",
        // 维护信息
        "Actor", "MaintenanceReason", "SessionId",
        // 网络事件元数据
        "WebsiteDomain", "ProxySetting", "DnsServer",
        // 更新信息
        "UpdateVersion", "UpdateResult"
    };

    /// <summary>默认不收集的字段（即使请求也不记录）。</summary>
    public static readonly IReadOnlySet<string> ExcludedFields = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        // 网页正文
        "WebPageContent", "PageBody", "HtmlContent", "ResponseBody",
        // 学生代码正文
        "SourceCode", "StudentCode", "CodeContent", "CodeSubmission",
        // 凭据
        "Password", "PasswordHash", "OldPassword", "NewPassword",
        // 密钥
        "PrivateKey", "PublicKey", "AesKey", "HmacKey", "TotpSecret",
        // 恢复码
        "RecoveryCode", "RecoveryCodes",
        // 其他敏感
        "Token", "SessionToken", "AuthToken", "BearerToken"
    };

    /// <summary>
    /// 判断字段是否允许记录。
    /// 规则：ExcludedFields 中的字段永远不记录；其他字段允许记录。
    /// </summary>
    public static bool IsFieldAllowed(string fieldName)
    {
        if (string.IsNullOrWhiteSpace(fieldName)) return false;
        return !ExcludedFields.Contains(fieldName);
    }

    /// <summary>
    /// 判断字段是否在默认收集范围内。
    /// </summary>
    public static bool IsCollectedByDefault(string fieldName)
    {
        if (string.IsNullOrWhiteSpace(fieldName)) return false;
        return CollectedFields.Contains(fieldName);
    }

    /// <summary>
    /// 过滤日志字段：移除排除字段，返回允许记录的字段。
    /// </summary>
    public static Dictionary<string, string?> FilterFields(Dictionary<string, string?> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        var filtered = new Dictionary<string, string?>();
        foreach (var kv in fields)
        {
            if (IsFieldAllowed(kv.Key))
            {
                filtered[kv.Key] = kv.Value;
            }
        }
        return filtered;
    }

    /// <summary>
    /// 生成隐私声明摘要文本（用于展示给学生/教师）。
    /// </summary>
    public static string GetSummary()
    {
        var collected = string.Join(", ", CollectedFields.OrderBy(f => f));
        var excluded = string.Join(", ", ExcludedFields.OrderBy(f => f));
        return $@"
Winknow V7.0 隐私声明

默认收集的字段（仅元数据）：
{collected}

默认不收集的字段（即使请求也不记录）：
{excluded}

规则：
1. 网页正文、学生代码正文默认不记录。
2. 密码、密钥、恢复码、令牌等凭据不进入日志。
3. 日志数据保留期默认 {Winknow.Core.Constants.Logging.DefaultRetentionDays} 天，到期安全删除。
4. 敏感日志正文使用 AES-256-GCM 加密后存储。
5. 日志记录使用哈希链 + 检查点签名保证完整性，修改或截断可被检测。
".Trim();
    }
}
