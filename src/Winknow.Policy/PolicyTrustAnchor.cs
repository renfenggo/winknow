using System.Security.Cryptography;

namespace Winknow.Policy;

/// <summary>
/// 策略信任锚（R04）：验签公钥的唯一入口。
///
/// - 内置 dev 公钥与 tools/policy-signing/dev_private_key.xml 成对，
///   仅用于开发/测试与默认策略签名（私钥入库仅为 dev 对，生产必须换钥）。
/// - 生产部署通过环境变量 WINKNOW_POLICY_PUBLIC_KEY_XML 注入正式公钥
///   （XML 格式，与 RSA.ToXmlString(false) 输出一致）。
/// </summary>
public static class PolicyTrustAnchor
{
    /// <summary>dev 公钥（与 tools/policy-signing/dev_private_key.xml 成对）。</summary>
    public const string DevPublicKeyXml =
        "<RSAKeyValue><Modulus>th5FoBI70InVp/FQrXJBrnO741G3u5lF7DtXb/Xtv9CmuzVGJ0JAK993zUZV9X4IihZi0OI0vRP2ftg0jxIYwjvZYY4k5Ww8Uh10f3ntZJgWipEqspOzlBvbvmujuWiTYpAeuOGzBn5T2eDihT3gklhUmjcjeCoIRX+0GOs0s39LKJ+Q3ux3TAfioilwhJtDcNPUtYI7L2GWUdSGO8ub9uzQh1Ls9vEd/2ZSHcyTWDouPF1nX7F9Mli1wyhvyitIdP+Ch2jmF/HQZ+kAF1TYXjkNcmg8zNgLHDGu77p9WfvTD9RQ74a1DUcGHlNWfQ+qf+u4eHlgXS0jTJaFlG9pqQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

    /// <summary>生产注入正式公钥的环境变量名。</summary>
    public const string PublicKeyXmlEnvVar = "WINKNOW_POLICY_PUBLIC_KEY_XML";

    /// <summary>
    /// 构建验签公钥：显式 XML 优先，其次环境变量，最后回落 dev 公钥。
    /// </summary>
    /// <param name="publicKeyXml">显式公钥 XML（可为 null）。</param>
    /// <returns>RSA 公钥实例（调用方负责释放）。</returns>
    public static RSA CreatePublicKey(string? publicKeyXml = null)
    {
        var xml = !string.IsNullOrWhiteSpace(publicKeyXml)
            ? publicKeyXml
            : Environment.GetEnvironmentVariable(PublicKeyXmlEnvVar) is { Length: > 0 } fromEnv
                ? fromEnv
                : DevPublicKeyXml;
        var rsa = RSA.Create();
        rsa.FromXmlString(xml);
        return rsa;
    }
}
