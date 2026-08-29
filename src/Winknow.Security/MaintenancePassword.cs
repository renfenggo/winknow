using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Winknow.Security;

/// <summary>
/// 维护模式密码哈希（Argon2id）。
///
/// 用途：维护模式密码以 Argon2id 哈希存储，禁止明文。
/// 满足 V7.0 第 6 周"维护模式权限验证"与威胁模型对凭据存储的要求。
///
/// 安全约束（项目约定）：
/// - 不使用 SecureString；密码字节用后 CryptographicOperations.ZeroMemory 清零。
/// - 存储格式：v1:base64(salt):base64(hash):iterations:memory:parallelism
/// </summary>
public static class MaintenancePassword
{
    private const int SaltSize = 16;
    private const int HashSize = 32;

    // Argon2id 参数（按 OWASP 2023 建议的最低安全档，兼顾课堂环境性能）
    private const int DefaultIterations = 3;
    private const int DefaultMemorySize = 16384; // 16 MB
    private const int DefaultDegreeOfParallelism = 2;

    /// <summary>
    /// 对明文密码计算 Argon2id 哈希，返回可存储的字符串。
    /// </summary>
    /// <param name="password">明文密码。</param>
    /// <param name="logger">可选日志记录器。</param>
    /// <returns>可持久化存储的哈希字符串。</returns>
    public static string Hash(string password, ILogger? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = ComputeArgon2id(password, salt, DefaultIterations, DefaultMemorySize, DefaultDegreeOfParallelism);
        try
        {
            return $"v1:{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}:{DefaultIterations}:{DefaultMemorySize}:{DefaultDegreeOfParallelism}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
            CryptographicOperations.ZeroMemory(salt);
        }
    }

    /// <summary>
    /// 验证明文密码是否匹配存储的哈希。常量时间比较，防旁路。
    /// </summary>
    /// <param name="password">用户输入的明文密码。</param>
    /// <param name="storedHash">Hash 返回的存储字符串。</param>
    /// <param name="logger">可选日志记录器。</param>
    /// <returns>匹配返回 true。</returns>
    public static bool Verify(string password, string storedHash, ILogger? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        ArgumentException.ThrowIfNullOrWhiteSpace(storedHash);

        var parts = storedHash.Split(':');
        if (parts.Length != 6 || parts[0] != "v1")
        {
            logger?.LogError("Invalid password hash format");
            return false;
        }

        if (!int.TryParse(parts[3], out var iter) ||
            !int.TryParse(parts[4], out var mem) ||
            !int.TryParse(parts[5], out var par))
        {
            logger?.LogError("Invalid password hash parameters");
            return false;
        }

        byte[] salt;
        byte[] expected;
        try
        {
            salt = Convert.FromBase64String(parts[1]);
            expected = Convert.FromBase64String(parts[2]);
        }
        catch (FormatException)
        {
            logger?.LogError("Invalid base64 in password hash");
            return false;
        }

        byte[] actual = Array.Empty<byte>();
        try
        {
            actual = ComputeArgon2id(password, salt, iter, mem, par);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(salt);
        }
    }

    private static byte[] ComputeArgon2id(string password, byte[] salt, int iterations, int memorySize, int degreeOfParallelism)
    {
        var pwBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            var argon2 = new Argon2id(pwBytes)
            {
                Salt = salt,
                Iterations = iterations,
                MemorySize = memorySize,
                DegreeOfParallelism = degreeOfParallelism
            };
            return argon2.GetBytes(HashSize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwBytes);
        }
    }
}
