using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Winknow.Core;
using Winknow.Core.Results;

namespace Winknow.Logging;

/// <summary>
/// 日志哈希链：每条记录的 Hash 包含前一条的 Hash，形成链式结构。
/// 验收项：修改或截断日志可被检测（任意中间记录被篡改会导致后续 Hash 不匹配）。
/// </summary>
public sealed class HashChain
{
    private readonly ILogger<HashChain>? _logger;
    private string _previousHash;

    /// <summary>创世记录的初始 Hash（空字符串的 SHA-256）。</summary>
    public static readonly string GenesisHash = ComputeHash("genesis");

    /// <summary>创建哈希链，指定前一条 Hash（续链时使用）。</summary>
    public HashChain(string? previousHash = null, ILogger<HashChain>? logger = null)
    {
        _logger = logger;
        _previousHash = string.IsNullOrEmpty(previousHash) ? GenesisHash : previousHash;
    }

    /// <summary>当前链尾 Hash（最后一条记录的 Hash）。</summary>
    public string CurrentHash => _previousHash;

    /// <summary>
    /// 为一条日志记录计算链式 Hash。
    /// Hash = SHA256(previousHash || recordHash)
    /// </summary>
    /// <param name="record">日志记录内容（序列化后的 JSON）。</param>
    /// <returns>链式 Hash（小写 hex）。</returns>
    public string ComputeChainHash(string record)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(record);
        var combined = _previousHash + "|" + record;
        var hash = ComputeHash(combined);
        _previousHash = hash;
        return hash;
    }

    /// <summary>
    /// 验证一条记录的链式 Hash 是否正确。
    /// </summary>
    /// <param name="record">记录内容。</param>
    /// <param name="expectedPreviousHash">预期的前一条 Hash。</param>
    /// <param name="actualHash">记录中存储的 Hash。</param>
    /// <returns>验证通过返回 true。</returns>
    public static bool VerifyChainLink(string record, string expectedPreviousHash, string actualHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(record);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedPreviousHash);
        ArgumentException.ThrowIfNullOrWhiteSpace(actualHash);

        var combined = expectedPreviousHash + "|" + record;
        var expected = ComputeHash(combined);
        return string.Equals(expected, actualHash, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 验证一组记录的哈希链连续性。
    /// 验收项：修改或截断日志可被检测。
    /// </summary>
    /// <param name="entries">按顺序排列的日志条目（含 PreviousHash 和 Hash）。</param>
    /// <returns>验证结果（首个断裂点的索引，-1 表示全部通过）。</returns>
    public static Result<int> VerifyChain(IReadOnlyList<HashChainEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        if (entries.Count == 0) return Result<int>.Success(-1);  // 空链视为通过

        var previousHash = entries[0].PreviousHash;
        if (string.IsNullOrEmpty(previousHash)) previousHash = GenesisHash;

        for (var i = 0; i < entries.Count; i++)
        {
            var entry = entries[i];
            if (!VerifyChainLink(entry.Record, previousHash, entry.Hash))
            {
                return Result<int>.Failure(ErrorCode.HashMismatch,
                    $"哈希链在第 {i} 条记录断裂（可能被篡改或截断）");
            }
            previousHash = entry.Hash;
        }

        return Result<int>.Success(-1);  // 全部通过
    }

    /// <summary>
    /// 重置链尾 Hash（用于续链或测试）。
    /// </summary>
    public void Reset(string? previousHash = null)
    {
        _previousHash = string.IsNullOrEmpty(previousHash) ? GenesisHash : previousHash;
    }

    /// <summary>
    /// 计算字符串的 SHA-256 Hash（小写 hex）。
    /// </summary>
    public static string ComputeHash(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }
}

/// <summary>
/// 哈希链条目（不可变）。
/// </summary>
public sealed class HashChainEntry
{
    /// <summary>记录内容（序列化后的 JSON）。</summary>
    public required string Record { get; init; }

    /// <summary>前一条记录的 Hash。</summary>
    public required string PreviousHash { get; init; }

    /// <summary>本条记录的 Hash。</summary>
    public required string Hash { get; init; }
}
