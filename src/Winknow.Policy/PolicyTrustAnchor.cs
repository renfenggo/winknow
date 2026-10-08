using System.Security.Cryptography;

namespace Winknow.Policy;

/// <summary>
/// 策略信任锚（R04）：验签公钥的唯一入口。
///
/// - 内置 dev 公钥与 tools/policy-signing/dev_private_key.xml 成对，
///   仅用于开发/测试与默认策略签名（私钥入库仅为 dev 对，生产必须换钥）。
/// - 生产部署通过环境变量 WINKNOW_POLICY_PUBLIC_KEY_XML 或配置
///   Policy:PublicKeyXml 注入正式公钥（XML 格式，RSA.ToXmlString(false)）。
/// - 生产收紧（P0，2026-10-07）：allowDevKeyFallback=false 时禁止回落
///   dev 公钥——缺少正式公钥直接抛异常（fail-closed），由 Worker 转为
///   "拒绝启用管控"，杜绝生产环境用开发钥签名的策略通过验签。
/// </summary>
public static class PolicyTrustAnchor
{
    /// <summary>dev 公钥（与 tools/policy-signing/dev_private_key.xml 成对）。</summary>
    public const string DevPublicKeyXml =
        "<RSAKeyValue><Modulus>th5FoBI70InVp/FQrXJBrnO741G3u5lF7DtXb/Xtv9CmuzVGJ0JAK993zUZV9X4IihZi0OI0vRP2ftg0jxIYwjvZYY4k5Ww8Uh10f3ntZJgWipEqspOzlBvbvmujuWiTYpAeuOGzBn5T2eDihT3gklhUmjcjeCoIRX+0GOs0s39LKJ+Q3ux3TAfioilwhJtDcNPUtYI7L2GWUdSGO8ub9uzQh1Ls9vEd/2ZSHcyTWDouPF1nX7F9Mli1wyhvyitIdP+Ch2jmF/HQZ+kAF1TYXjkNcmg8zNgLHDGu77p9WfvTD9RQ74a1DUcGHlNWfQ+qf+u4eHlgXS0jTJaFlG9pqQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

    /// <summary>生产注入正式公钥的环境变量名。</summary>
    public const string PublicKeyXmlEnvVar = "WINKNOW_POLICY_PUBLIC_KEY_XML";

    /// <summary>
    /// 构建验签公钥：显式 XML 优先，其次环境变量；
    /// 两者皆缺时按 <paramref name="allowDevKeyFallback"/> 决定是否回落 dev 公钥
    /// （生产必须传 false——缺正式公钥即抛异常，不静默降级）。
    /// </summary>
    /// <param name="publicKeyXml">显式公钥 XML（可为 null）。</param>
    /// <param name="allowDevKeyFallback">是否允许回落内置 dev 公钥（仅开发环境）。</param>
    /// <returns>RSA 公钥实例（调用方负责释放）。</returns>
    /// <exception cref="InvalidOperationException">
    /// allowDevKeyFallback=false 且未提供任何正式公钥（显式 XML 与环境变量均缺）。
    /// </exception>
    public static RSA CreatePublicKey(string? publicKeyXml = null, bool allowDevKeyFallback = true)
    {
        var fromEnv = Environment.GetEnvironmentVariable(PublicKeyXmlEnvVar);
        var xml = !string.IsNullOrWhiteSpace(publicKeyXml)
            ? publicKeyXml
            : !string.IsNullOrWhiteSpace(fromEnv)
                ? fromEnv
                : null;
        if (xml is null)
        {
            if (!allowDevKeyFallback)
            {
                throw new InvalidOperationException(
                    $"production policy verification requires an official public key: " +
                    $"set Policy:PublicKeyXml or {PublicKeyXmlEnvVar}; dev fallback is disabled");
            }
            xml = DevPublicKeyXml;
        }
        var rsa = RSA.Create();
        rsa.FromXmlString(xml);
        return rsa;
    }
}
