using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Winknow.Security;

/// <summary>
/// 一次性恢复码存储（哈希持久化 + 用后失效）。
///
/// 用途：管理员遗忘维护密码/TOTP 时的紧急恢复通道（V7.0 第 6 周"一次性恢复码"）。
/// 满足验收"恢复码不能重复使用"：每个码 SHA256 哈希存储，验证通过即标记 Used。
///
/// 安全约束：
/// - 明文仅在生成时返回一次，持久化仅存哈希
/// - 比较使用 CryptographicOperations.FixedTimeEquals 防旁路
/// - 字符集排除易混淆字符（0/O/1/I）
/// </summary>
public sealed class RecoveryCodeStore
{
    private readonly string _storePath;
    private readonly ILogger? _logger;

    /// <summary>
    /// 构造恢复码存储。
    /// </summary>
    /// <param name="storePath">存储文件路径（JSON）。</param>
    /// <param name="logger">可选日志记录器。</param>
    public RecoveryCodeStore(string storePath, ILogger? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(storePath);
        _storePath = storePath;
        _logger = logger;
    }

    /// <summary>
    /// 生成一组恢复码，明文仅此一次返回，哈希持久化到磁盘。
    /// </summary>
    /// <param name="count">码数量，默认 10。</param>
    /// <returns>明文恢复码列表（4-4-4-4 分组）。</returns>
    public IReadOnlyList<string> GenerateCodes(int count = 10)
    {
        if (count is <= 0 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(count), "恢复码数量需在 1-100 之间");
        }

        var entries = new List<CodeEntry>(count);
        var plain = new List<string>(count);
        for (var i = 0; i < count; i++)
        {
            var code = GenerateCode();
            plain.Add(code);
            entries.Add(new CodeEntry { HashBase64 = Convert.ToBase64String(HashCode(code)), Used = false });
        }

        WriteStore(entries);
        _logger?.LogInformation("Generated {Count} recovery codes", count);
        return plain;
    }

    /// <summary>
    /// 验证并消费恢复码：匹配且未使用则标记失效，返回 true。
    /// 同一码第二次验证返回 false。
    /// </summary>
    /// <param name="code">用户输入的恢复码。</param>
    /// <returns>验证通过且未使用过返回 true。</returns>
    public bool VerifyAndConsume(string code)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        var normalized = Normalize(code);
        var inputHash = HashCode(normalized);

        var entries = ReadStore();
        for (var i = 0; i < entries.Count; i++)
        {
            if (entries[i].Used) continue;
            var storedHash = Convert.FromBase64String(entries[i].HashBase64);
            if (CryptographicOperations.FixedTimeEquals(inputHash, storedHash))
            {
                entries[i].Used = true;
                WriteStore(entries);
                _logger?.LogInformation("Recovery code consumed (index {Index})", i);
                return true;
            }
        }

        _logger?.LogWarning("Recovery code verification failed or already used");
        return false;
    }

    /// <summary>
    /// 返回尚未使用的恢复码数量。
    /// </summary>
    public int RemainingCount()
    {
        return ReadStore().Count(e => !e.Used);
    }

    private static string GenerateCode()
    {
        // 排除 0/O/1/I，避免抄写混淆
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        var bytes = RandomNumberGenerator.GetBytes(16);
        var sb = new StringBuilder(19);
        for (var i = 0; i < 16; i++)
        {
            if (i > 0 && i % 4 == 0) sb.Append('-');
            sb.Append(alphabet[bytes[i] % alphabet.Length]);
        }
        return sb.ToString();
    }

    private static string Normalize(string code) => code.Trim().ToUpperInvariant();

    private static byte[] HashCode(string code) => SHA256.HashData(Encoding.UTF8.GetBytes(code));

    private List<CodeEntry> ReadStore()
    {
        if (!File.Exists(_storePath)) return new List<CodeEntry>();
        var json = File.ReadAllText(_storePath);
        return JsonSerializer.Deserialize<List<CodeEntry>>(json) ?? new List<CodeEntry>();
    }

    private void WriteStore(List<CodeEntry> entries)
    {
        var dir = Path.GetDirectoryName(_storePath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }
        var json = JsonSerializer.Serialize(entries);
        File.WriteAllText(_storePath, json);
    }

    private sealed class CodeEntry
    {
        public string HashBase64 { get; set; } = string.Empty;
        public bool Used { get; set; }
    }
}
