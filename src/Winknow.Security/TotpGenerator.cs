using System.Security.Cryptography;
using System.Text;

namespace Winknow.Security;

/// <summary>
/// 离线 TOTP（RFC 6238）生成与验证。
///
/// 用途：维护模式二次验证，管理员输入 Authenticator App 显示的 6 位动态码。
/// 完全离线计算，不依赖云端后台（满足 V7.0 第 6 周"离线 TOTP"要求）。
///
/// 参数：
/// - 算法：HMAC-SHA1（与 Google Authenticator / Microsoft Authenticator 兼容）
/// - 时间步：30 秒
/// - 位数：6
/// - 容差窗口：验证默认允许前后各 1 个时间步（共 ±30s）
/// </summary>
public static class TotpGenerator
{
    private const int StepSeconds = 30;
    private const int Digits = 6;
    private const int DefaultWindow = 1;

    /// <summary>
    /// 按当前时间（或指定时间）生成 6 位 TOTP。
    /// </summary>
    /// <param name="secret">共享密钥原始字节（可用 Base32Decode 转换）。</param>
    /// <param name="now">可选时间，默认 UtcNow（测试可注入）。</param>
    /// <returns>6 位数字字符串。</returns>
    public static string GenerateCode(byte[] secret, DateTimeOffset? now = null)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length == 0) throw new ArgumentException("密钥不能为空", nameof(secret));

        var time = now ?? DateTimeOffset.UtcNow;
        var counter = (ulong)(time.ToUnixTimeSeconds() / StepSeconds);
        return ComputeTotp(secret, counter);
    }

    /// <summary>
    /// 验证输入的 TOTP 是否在容差窗口内有效。
    /// </summary>
    /// <param name="secret">共享密钥原始字节。</param>
    /// <param name="code">用户输入的 6 位码。</param>
    /// <param name="now">可选时间。</param>
    /// <param name="window">容差步数，默认 1（前后各 30s）。</param>
    /// <returns>验证通过返回 true。</returns>
    public static bool Verify(byte[] secret, string code, DateTimeOffset? now = null, int window = DefaultWindow)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentException.ThrowIfNullOrWhiteSpace(code);

        var time = now ?? DateTimeOffset.UtcNow;
        var baseCounter = time.ToUnixTimeSeconds() / StepSeconds;
        var expected = code.Trim();
        if (expected.Length != Digits) return false;

        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        for (long offset = -window; offset <= window; offset++)
        {
            var candidate = baseCounter + offset;
            if (candidate < 0) continue;
            var candidateBytes = Encoding.UTF8.GetBytes(ComputeTotp(secret, (ulong)candidate));
            if (CryptographicOperations.FixedTimeEquals(candidateBytes, expectedBytes))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// 解码 Base32 字符串（RFC 4648，无 padding）为字节，兼容 Authenticator 密钥串。
    /// </summary>
    /// <param name="input">Base32 字符串。</param>
    /// <returns>原始字节。</returns>
    public static byte[] Base32Decode(string input)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(input);
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var normalized = input.TrimEnd('=').ToUpperInvariant().Replace(" ", "");
        var bytes = new List<byte>(normalized.Length * 5 / 8 + 1);
        int buffer = 0, bitsLeft = 0;
        foreach (var c in normalized)
        {
            var val = alphabet.IndexOf(c);
            if (val < 0) continue; // 跳过非法字符
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                bytes.Add((byte)((buffer >> bitsLeft) & 0xff));
            }
        }
        return bytes.ToArray();
    }

    private static string ComputeTotp(byte[] secret, ulong counter)
    {
        // counter → 8 字节大端
        var counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian) Array.Reverse(counterBytes);

        using var hmac = new HMACSHA1(secret);
        var hash = hmac.ComputeHash(counterBytes);

        // 动态截断（RFC 4226）
        var offset = hash[hash.Length - 1] & 0x0f;
        var binary = ((hash[offset] & 0x7f) << 24)
                    | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8)
                    | (hash[offset + 3] & 0xff);

        var code = binary % (int)Math.Pow(10, Digits);
        return code.ToString($"D{Digits}");
    }
}
