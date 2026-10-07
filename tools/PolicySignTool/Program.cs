using System.Security.Cryptography;
using System.Text.Json;
using Winknow.Policy;

// R04 策略签名工具：对策略 JSON 内嵌 RSA-SHA256 签名（Signature 字段）。
// 用法：dotnet run --project tools/PolicySignTool -- sign <policy.json> [--key <private-key.xml>]
// 默认私钥：tools/policy-signing/dev_private_key.xml（dev 对，生产必须换钥）。

if (args.Length < 2 || args[0] != "sign")
{
    Console.Error.WriteLine("usage: PolicySignTool sign <policy.json> [--key <private-key.xml>]");
    return 2;
}

var policyPath = args[1];
var keyPath = args.Length >= 4 && args[2] == "--key"
    ? args[3]
    : Path.Combine("tools", "policy-signing", "dev_private_key.xml");

if (!File.Exists(policyPath))
{
    Console.Error.WriteLine($"policy file not found: {policyPath}");
    return 2;
}
if (!File.Exists(keyPath))
{
    Console.Error.WriteLine($"private key not found: {keyPath}");
    return 2;
}

var options = new JsonSerializerOptions
{
    PropertyNameCaseInsensitive = true,
    ReadCommentHandling = JsonCommentHandling.Skip,
    WriteIndented = true,
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
};

// 关键：签名与验签都基于"从文件反序列化出的对象"的规范 JSON，
// 因此这里必须先反序列化再签名，禁止对未读回的对象直接签名。
var policy = JsonSerializer.Deserialize<PolicyFile>(
    await File.ReadAllTextAsync(policyPath), options);
if (policy is null)
{
    Console.Error.WriteLine("failed to parse policy JSON");
    return 1;
}

using var privateKey = RSA.Create();
privateKey.FromXmlString(await File.ReadAllTextAsync(keyPath));

var signature = PolicySigner.Sign(policy, privateKey);
var signed = new PolicyFile
{
    Version = policy.Version,
    PolicyId = policy.PolicyId,
    CreatedAt = policy.CreatedAt,
    Description = policy.Description,
    SoftwareControl = policy.SoftwareControl,
    NetworkControl = policy.NetworkControl,
    UsbControl = policy.UsbControl,
    Signature = signature,
};

await File.WriteAllTextAsync(policyPath, JsonSerializer.Serialize(signed, options));
Console.WriteLine($"signed {policyPath}: {policy.PolicyId} v{policy.Version}");
return 0;
