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
    /// 从 JSON 文件加载策略。
    /// </summary>
    /// <param name="filePath">策略文件路径。</param>
    /// <param name="validateSignature">是否验证签名（第7周前默认 false）。</param>
    /// <returns>成功返回策略文件，失败返回错误码。</returns>
    public Result<PolicyFile> Load(string filePath, bool validateSignature = false)
    {
        if (!File.Exists(filePath))
        {
            _logger?.LogError("Policy file not found: {Path}", filePath);
            return Result<PolicyFile>.Failure(ErrorCode.PathNotFound, $"Policy file not found: {filePath}");
        }

        try
        {
            var json = File.ReadAllText(filePath);
            var policy = JsonSerializer.Deserialize<PolicyFile>(json, JsonOptions);

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

            // 签名验证（第7周前跳过）
            if (validateSignature)
            {
                // TODO 第7周：实现策略签名验证
                _logger?.LogWarning("Policy signature validation not yet implemented (Week 7)");
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
