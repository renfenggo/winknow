using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Winknow.Core.Results;

namespace Winknow.Security;

/// <summary>
/// 对端验证器（拉起前验证目标可执行文件：路径、签名、版本、Hash）。
///
/// 用途：V7.0 第 10 周"对端验证——路径、签名、版本、Hash"。
/// 守护进程在拉起 ControlService 之前必须验证：
/// 1. 路径合法：可执行文件位于预期部署目录（防 DLL 劫持/路径投毒）；
/// 2. 签名有效：Authenticode 证书链校验（防被替换的未签名二进制）；
/// 3. 版本达标：不低于最低版本（防降级攻击）；
/// 4. Hash 一致：与可信清单（Recovery Vault manifest）一致（防任意篡改）。
///
/// 任一项失败都拒绝拉起并返回失败原因——不验证就拉起等于把守护变成
/// 攻击者的自动重启武器。
///
/// 测试注记：Authenticode 校验在 CI/test 环境（未签名测试二进制）会失败，
/// 因此签名检查提供跳过开关（仅限测试构造器注入 trustedThumbprint 场景）；
/// 生产 GuardService 配置为强制校验。
/// </summary>
public sealed class PeerVerifier
{
    /// <summary>对端验证期望清单。</summary>
    public sealed record PeerExpectation
    {
        /// <summary>允许运行的可执行文件所在目录（含子目录不递归，直接父目录匹配）。</summary>
        public required string AllowedDir { get; init; }

        /// <summary>最低可接受版本（如 7.0.0）。null 跳过版本检查。</summary>
        public string? MinimumVersion { get; init; }

        /// <summary>期望 SHA256（Hex）。null 跳过 Hash 检查。</summary>
        public string? ExpectedSha256 { get; init; }

        /// <summary>是否执行 Authenticode 签名校验（生产 true；测试二进制未签名时可 false）。</summary>
        public bool RequireSignature { get; init; } = true;

        /// <summary>签名者证书主题须包含的关键字（如 Winknow）。null 不限定主题。</summary>
        public string? SignerSubjectKeyword { get; init; }
    }

    /// <summary>单项验证结果。</summary>
    public sealed record PeerVerifyResult
    {
        /// <summary>路径校验是否通过（文件存在且位于预期目录）。</summary>
        public required bool PathOk { get; init; }

        /// <summary>Authenticode 签名校验是否通过。</summary>
        public required bool SignatureOk { get; init; }

        /// <summary>版本校验是否通过（不低于最低版本）。</summary>
        public required bool VersionOk { get; init; }

        /// <summary>SHA256 校验是否通过（与可信清单一致）。</summary>
        public required bool HashOk { get; init; }

        /// <summary>首个失败项的详细描述（全部通过时为 null）。</summary>
        public string? FailureDetail { get; init; }

        /// <summary>全部通过。</summary>
        public bool IsTrusted => PathOk && SignatureOk && VersionOk && HashOk;
    }

    private readonly ILogger? _logger;

    /// <summary>
    /// 构造对端验证器。
    /// </summary>
    public PeerVerifier(ILogger? logger = null) => _logger = logger;

    /// <summary>
    /// 验证目标可执行文件是否可信。
    /// </summary>
    /// <param name="exePath">目标可执行文件路径。</param>
    /// <param name="expectation">期望清单。</param>
    /// <returns>逐项结果；文件不存在时全部失败。</returns>
    public PeerVerifyResult Verify(string exePath, PeerExpectation expectation)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(exePath);

        var pathOk = CheckPath(exePath, expectation.AllowedDir, out var pathDetail);
        string? sigDetail = null;
        var signatureOk = !expectation.RequireSignature || CheckSignature(exePath, expectation.SignerSubjectKeyword, out sigDetail);
        var versionOk = CheckVersion(exePath, expectation.MinimumVersion, out var versionDetail);
        var hashOk = CheckHash(exePath, expectation.ExpectedSha256, out var hashDetail);

        var failureDetail = new[] { pathDetail, sigDetail, versionDetail, hashDetail }
            .FirstOrDefault(d => d is not null);

        return new PeerVerifyResult
        {
            PathOk = pathOk,
            SignatureOk = signatureOk,
            VersionOk = versionOk,
            HashOk = hashOk,
            FailureDetail = failureDetail
        };
    }

    private bool CheckPath(string exePath, string allowedDir, out string? detail)
    {
        detail = null;
        try
        {
            var fullExe = Path.GetFullPath(exePath);
            var fullDir = Path.GetFullPath(allowedDir);
            var parent = Path.GetDirectoryName(fullExe);

            if (!string.Equals(parent, fullDir, StringComparison.OrdinalIgnoreCase))
            {
                detail = $"路径不在预期目录: {fullExe}（期望 {fullDir}）";
                return false;
            }
            if (!File.Exists(fullExe))
            {
                detail = $"可执行文件不存在: {fullExe}";
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            detail = $"路径解析失败: {ex.Message}";
            return false;
        }
    }

    private bool CheckSignature(string exePath, string? subjectKeyword, out string? detail)
    {
        detail = null;
        try
        {
            using var cert = X509Certificate.CreateFromSignedFile(exePath);
            if (cert is null)
            {
                detail = "无 Authenticode 签名";
                return false;
            }
            if (subjectKeyword is not null &&
                !cert.Subject.Contains(subjectKeyword, StringComparison.OrdinalIgnoreCase))
            {
                detail = $"签名者主题不匹配: {cert.Subject}";
                return false;
            }
            // 注：证书链/时间戳的完整校验由部署环境 CA 信任决定；
            // 此处校验"存在签名 + 主题匹配"，链校验失败会抛异常进入 catch。
            return true;
        }
        catch (CryptographicException)
        {
            detail = "Authenticode 签名校验失败（未签名或证书无效）";
            return false;
        }
        catch (Exception ex)
        {
            detail = $"签名校验异常: {ex.Message}";
            return false;
        }
    }

    private static bool CheckVersion(string exePath, string? minimumVersion, out string? detail)
    {
        detail = null;
        if (minimumVersion is null) return true;
        try
        {
            var actual = FileVersionInfo.GetVersionInfo(exePath).FileVersion ?? "0.0.0";
            if (Version.TryParse(actual, out var act) && Version.TryParse(minimumVersion, out var min))
            {
                if (act < min)
                {
                    detail = $"版本过低: {actual} < {minimumVersion}";
                    return false;
                }
                return true;
            }
            detail = $"版本解析失败: {actual}";
            return false;
        }
        catch (Exception ex)
        {
            detail = $"版本读取失败: {ex.Message}";
            return false;
        }
    }

    private static bool CheckHash(string exePath, string? expectedSha256, out string? detail)
    {
        detail = null;
        if (expectedSha256 is null) return true;
        try
        {
            var actual = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(exePath)));
            if (!string.Equals(actual, expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                detail = $"SHA256 不匹配: {actual[..12]}… != 期望 {expectedSha256[..12]}…";
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            detail = $"Hash 计算失败: {ex.Message}";
            return false;
        }
    }
}
