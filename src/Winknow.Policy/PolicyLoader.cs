using System.Text.Json;
using Microsoft.Extensions.Logging;
using Winknow.Core.Results;

namespace Winknow.Policy;

/// <summary>
/// 策略文件加载器：加载 + 验证 + 签名校验。
/// </summary>
public sealed class PolicyLoader
{
    private readonly ILogger<PolicyLoader>? _logger;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip
    };

    /// <summary>创建策略加载器。</summary>
    /// <param name="logger">可选的日志记录器。</param>
    public PolicyLoader(ILogger<PolicyLoader>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// 从 JSON 文件加载策略（不验签）。
    /// </summary>
    /// <param name="filePath">策略文件路径。</param>
    /// <param name="validateSignature">是否验证签名（兼容旧调用，默认 false）。</param>
    /// <returns>成功返回策略文件，失败返回错误码。</returns>
    public Result<PolicyFile> Load(string filePath, bool validateSignature = false)
        => Load(filePath, validateSignature, publicKey: null);

    /// <summary>
    /// 从 JSON 文件加载策略（R04：支持真实验签，fail-closed）。
    /// </summary>
    /// <param name="filePath">策略文件路径。</param>
    /// <param name="validateSignature">是否验证签名。</param>
    /// <param name="publicKey">可信公钥（validateSignature=true 时必填，缺失即拒绝）。</param>
    /// <returns>成功返回策略文件，失败返回错误码（验签失败为 PolicySignatureInvalid）。</returns>
    public Result<PolicyFile> Load(string filePath, bool validateSignature, System.Security.Cryptography.RSA? publicKey)
    {
        if (!File.Exists(filePath))
        {
            _logger?.LogError("Policy file not found: {Path}", filePath);
            return Result<PolicyFile>.Failure(ErrorCode.PathNotFound, $"Policy file not found: {filePath}");
        }

        try
        {
            var json = File.ReadAllText(filePath);
            PolicyFile? policy;

            // 尝试直接解析JSON（标准格式）
            policy = JsonSerializer.Deserialize<PolicyFile>(json, JsonOptions);

            // 如果直接解析失败，尝试Base64编码格式
            if (policy is null)
            {
                policy = PolicyFile.FromEncodedJson(json);
            }

            if (policy is null)
            {
                return Result<PolicyFile>.Failure(ErrorCode.PolicyInvalid, "Failed to deserialize policy");
            }

            // 基本验证
            var validationResult = Validate(policy);
            if (!validationResult.IsSuccess)
            {
                return Result<PolicyFile>.Failure(validationResult.ErrorCode, validationResult.ErrorMessage);
            }

            // R04：真实签名验证（fail-closed：未签名/伪签名/公钥缺失或错误一律拒绝）
            if (validateSignature)
            {
                if (publicKey is null)
                {
                    _logger?.LogError(
                        "Policy signature validation requested but no trusted public key was provided: {Path}",
                        filePath);
                    return Result<PolicyFile>.Failure(
                        ErrorCode.PolicySignatureInvalid,
                        "Signature validation requested but no trusted public key was provided");
                }

                var signatureResult = PolicySigner.VerifySignature(policy, publicKey);
                if (!signatureResult.IsSuccess)
                {
                    _logger?.LogError(
                        "Policy signature verification failed: {Path}: {Error}",
                        filePath, signatureResult.ErrorMessage);
                    return Result<PolicyFile>.Failure(
                        ErrorCode.PolicySignatureInvalid, signatureResult.ErrorMessage ?? "policy signature invalid");
                }

                _logger?.LogInformation("Policy signature verified: {PolicyId} v{Version}",
                    policy.PolicyId, policy.Version);
            }

            _logger?.LogInformation("Policy loaded: {PolicyId} v{Version}", policy.PolicyId, policy.Version);
            return Result<PolicyFile>.Success(policy);
        }
        catch (JsonException ex)
        {
            _logger?.LogError(ex, "Failed to parse policy JSON: {Path}", filePath);
            return Result<PolicyFile>.Failure(ErrorCode.PolicyInvalid, $"JSON parse error: {ex.Message}");
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to load policy: {Path}", filePath);
            return Result<PolicyFile>.Failure(ErrorCode.Unknown, ex.Message);
        }
    }

    /// <summary>
    /// 验证策略文件基本完整性。
    /// </summary>
    private Result<PolicyFile> Validate(PolicyFile policy)
    {
        if (string.IsNullOrEmpty(policy.Version))
        {
            return Result<PolicyFile>.Failure(ErrorCode.PolicyInvalid, "Version is required");
        }

        if (string.IsNullOrEmpty(policy.PolicyId))
        {
            return Result<PolicyFile>.Failure(ErrorCode.PolicyInvalid, "PolicyId is required");
        }

        if (!policy.Version.StartsWith("7."))
        {
            return Result<PolicyFile>.Failure(
                ErrorCode.PolicyVersionMismatch,
                $"Policy version {policy.Version} is not compatible with V7.0");
        }

        return Result<PolicyFile>.Success(policy);
    }
}
