using System.Security.Cryptography;
using System.Text;
using Winknow.Core.Results;

namespace Winknow.TrustedUpdater;

/// <summary>
/// 更新包验证器（签名 + 产品标识 + 文件 Hash 综合校验）。
///
/// 用途：V7.0 第 7 周"TrustedUpdater 验证签名、产品标识、目标版本和文件 Hash"。
/// 满足验收"更新包签名验证失败时拒绝安装"：VerifySignature 不通过则后续步骤全部拒绝。
///
/// 签名方案：RSA-SHA256 + PKCS#1 v1.5，对 manifest.ToSignableJson() 的 UTF8 字节签名。
/// 生产环境公钥应来自 HSM/Token；开发与测试用本地 RSA 密钥对（由调用方注入 RSA 对象）。
/// </summary>
public static class PackageVerifier
{
    /// <summary>
    /// 验证清单签名。
    /// </summary>
    /// <param name="manifest">清单对象。</param>
    /// <param name="publicKey">RSA 公钥。</param>
    /// <returns>签名有效返回成功。</returns>
    public static Result VerifySignature(UpdateManifest manifest, RSA publicKey)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(publicKey);

        if (string.IsNullOrWhiteSpace(manifest.Signature))
        {
            return Result.Failure(ErrorCode.SignatureInvalid, "清单未签名");
        }

        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(manifest.Signature);
        }
        catch (FormatException)
        {
            return Result.Failure(ErrorCode.SignatureInvalid, "签名不是合法 base64");
        }

        var data = Encoding.UTF8.GetBytes(manifest.ToSignableJson());
        if (!publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
        {
            return Result.Failure(ErrorCode.SignatureInvalid, "签名验证失败（数据被篡改或公钥不匹配）");
        }

        return Result.Success();
    }

    /// <summary>
    /// 验证产品标识匹配（防跨产品安装）。
    /// </summary>
    /// <param name="manifest">清单对象。</param>
    /// <param name="expectedProductId">本机已安装产品标识。</param>
    /// <returns>匹配返回成功。</returns>
    public static Result VerifyProduct(UpdateManifest manifest, string expectedProductId)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedProductId);

        if (!string.Equals(manifest.ProductId, expectedProductId, StringComparison.OrdinalIgnoreCase))
        {
            return Result.Failure(ErrorCode.InvalidArgument,
                $"产品标识不匹配：期望 {expectedProductId}，实际 {manifest.ProductId}");
        }

        return Result.Success();
    }

    /// <summary>
    /// 综合校验：签名 + 产品标识 + 文件 Hash。
    /// 任何一项失败立即返回，不继续后续步骤。
    /// </summary>
    /// <param name="manifest">清单对象。</param>
    /// <param name="extractedDir">解包目录。</param>
    /// <param name="expectedProductId">期望产品标识。</param>
    /// <param name="publicKey">RSA 公钥。</param>
    /// <returns>全部通过返回成功。</returns>
    public static Result VerifyAll(UpdateManifest manifest, string extractedDir, string expectedProductId, RSA publicKey)
    {
        var sig = VerifySignature(manifest, publicKey);
        if (!sig.IsSuccess) return sig;

        var product = VerifyProduct(manifest, expectedProductId);
        if (!product.IsSuccess) return product;

        return UpdatePackage.VerifyFileHashes(extractedDir, manifest);
    }
}
