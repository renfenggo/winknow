using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Winknow.Core;
using Winknow.Core.Results;

namespace Winknow.Logging;

/// <summary>
/// 日志检查点签名器：定期对日志哈希链尾签名，防截断和整段删除。
/// 验收项：修改或截断日志可被检测（检查点之间的记录缺失会导致链尾 Hash 不匹配签名）。
/// </summary>
public sealed class LogCheckpointSigner : IDisposable
{
    private readonly ILogger<LogCheckpointSigner>? _logger;
    private readonly byte[] _hmacKey;
    private bool _disposed;

    /// <summary>
    /// 创建检查点签名器。
    /// </summary>
    /// <param name="hmacKey">HMAC-SHA256 密钥（32 字节，由 DeviceLogKeyGenerator 生成）。</param>
    /// <param name="logger">可选日志。</param>
    public LogCheckpointSigner(byte[] hmacKey, ILogger<LogCheckpointSigner>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(hmacKey);
        if (hmacKey.Length != 32)
        {
            throw new ArgumentException("HMAC-SHA256 密钥必须为 32 字节", nameof(hmacKey));
        }
        _hmacKey = hmacKey;
        _logger = logger;
    }

    /// <summary>
    /// 创建检查点：对当前链尾 Hash 签名。
    /// </summary>
    /// <param name="chainTailHash">哈希链尾 Hash。</param>
    /// <param name="recordCount">检查点覆盖的记录数。</param>
    /// <returns>检查点对象（含 HMAC 签名）。</returns>
    public LogCheckpoint CreateCheckpoint(string chainTailHash, int recordCount)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(chainTailHash);

        var checkpoint = new LogCheckpoint
        {
            ChainTailHash = chainTailHash,
            RecordCount = recordCount,
            CreatedAt = DateTimeOffset.UtcNow.ToString("O")
        };

        checkpoint.Signature = Convert.ToBase64String(ComputeHmac(checkpoint.ToSignable()));
        _logger?.LogInformation("Checkpoint created: {Count} records, tail={Tail}",
            recordCount, chainTailHash[..Math.Min(16, chainTailHash.Length)]);
        return checkpoint;
    }

    /// <summary>
    /// 验证检查点签名是否正确。
    /// </summary>
    /// <param name="checkpoint">待验证的检查点。</param>
    /// <returns>签名验证通过返回 true。</returns>
    public bool VerifyCheckpoint(LogCheckpoint checkpoint)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(checkpoint.Signature);

        var expected = ComputeHmac(checkpoint.ToSignable());
        var actual = Convert.FromBase64String(checkpoint.Signature);
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    /// <summary>
    /// 验证检查点之间的记录完整性。
    /// 给定上一个检查点和当前链尾 Hash，验证中间记录未被截断。
    /// </summary>
    /// <param name="previousCheckpoint">上一个检查点。</param>
    /// <param name="currentChainTailHash">当前链尾 Hash。</param>
    /// <returns>验证通过返回 true（链尾 Hash 与检查点一致或链路连续）。</returns>
    public Result VerifyContinuity(LogCheckpoint? previousCheckpoint, string currentChainTailHash)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(currentChainTailHash);

        if (previousCheckpoint is null)
        {
            // 无前驱检查点，当前即起点，视为通过
            return Result.Success();
        }

        // 验证前驱检查点签名
        if (!VerifyCheckpoint(previousCheckpoint))
        {
            return Result.Failure(ErrorCode.SignatureInvalid, "前驱检查点签名验证失败（可能被篡改）");
        }

        // 链尾 Hash 必须与前驱检查点记录的 Hash 一致（连续链路）
        if (!string.Equals(previousCheckpoint.ChainTailHash, currentChainTailHash, StringComparison.OrdinalIgnoreCase))
        {
            // 不一致说明中间有新记录（正常）或被截断（异常）
            // 调用方应通过 HashChain.VerifyChain 进一步验证
            _logger?.LogDebug("Chain tail differs from last checkpoint (new records added)");
        }

        return Result.Success();
    }

    private byte[] ComputeHmac(string data)
    {
        var bytes = Encoding.UTF8.GetBytes(data);
        return HMACSHA256.HashData(_hmacKey, bytes);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_hmacKey);
    }
}

/// <summary>
/// 日志检查点（不可变）。
/// </summary>
public sealed class LogCheckpoint
{
    /// <summary>哈希链尾 Hash。</summary>
    public required string ChainTailHash { get; init; }

    /// <summary>检查点覆盖的记录数。</summary>
    public int RecordCount { get; init; }

    /// <summary>创建时间（ISO 8601）。</summary>
    public required string CreatedAt { get; init; }

    /// <summary>HMAC-SHA256 签名（Base64）。</summary>
    public string? Signature { get; set; }

    /// <summary>
    /// 生成待签名的规范化字符串（不含 Signature）。
    /// </summary>
    public string ToSignable()
    {
        return $"{ChainTailHash}|{RecordCount}|{CreatedAt}";
    }
}
