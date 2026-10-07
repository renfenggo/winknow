using System.Security.Cryptography;
using System.Text;
using Winknow.Core.Results;

namespace Winknow.Policy;

/// <summary>
/// 策略签名/验签（R04，审查 2026-10-07）。
///
/// 签名方案与 TrustedUpdater 更新包一致：RSA-SHA256 + PKCS#1 v1.5，
/// 对 PolicyFile.ToSignableJson()（不含 Signature 的规范 JSON）的
/// UTF-8 字节签名，base64 存储。验签失败一律 PolicySignatureInvalid。
/// </summary>
public static class PolicySigner
{
    /// <summary>
    /// 用私钥对策略内容签名，返回 base64 签名（调用方负责写入 Signature 字段）。
    /// </summary>
    public static string Sign(PolicyFile policy, RSA privateKey)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(privateKey);
        var data = Encoding.UTF8.GetBytes(policy.ToSignableJson());
        var signature = privateKey.SignData(
            data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(signature);
    }

    /// <summary>
    /// 验证策略签名：未签名、非法 base64、内容被篡改、公钥不匹配均失败。
    /// </summary>
    public static Result VerifySignature(PolicyFile policy, RSA publicKey)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(publicKey);

        if (string.IsNullOrEmpty(policy.Signature))
        {
            return Result.Failure(
                ErrorCode.PolicySignatureInvalid, "policy is not signed");
        }

        byte[] signatureBytes;
        try
        {
            signatureBytes = Convert.FromBase64String(policy.Signature);
        }
        catch (FormatException)
        {
            return Result.Failure(
                ErrorCode.PolicySignatureInvalid, "policy signature is not valid base64");
        }

        var data = Encoding.UTF8.GetBytes(policy.ToSignableJson());
        if (!publicKey.VerifyData(
                data, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
        {
            return Result.Failure(
                ErrorCode.PolicySignatureInvalid,
                "policy signature mismatch (content may be tampered or key mismatch)");
        }

        return Result.Success();
    }
}
