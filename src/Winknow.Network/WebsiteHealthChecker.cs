using System.Net.Http;
using Microsoft.Extensions.Logging;
using Winknow.Core.Results;
using Winknow.Policy;

namespace Winknow.Network;

/// <summary>
/// 网站包健康检测器：检测洛谷页面、图片、登录、提交端点可达性。
/// 验收项：洛谷完整功能正常（端点可达性检测）。
/// </summary>
public sealed class WebsiteHealthChecker : IDisposable
{
    private readonly ILogger<WebsiteHealthChecker>? _logger;
    private readonly HttpClient _httpClient;
    private readonly WebsiteHealthSection _section;
    private Timer? _periodicTimer;
    private bool _disposed;

    /// <summary>检测完成时触发（参数：各端点检测结果）。</summary>
    public event Action<IReadOnlyList<HealthCheckResult>>? CheckCompleted;

    /// <summary>检测到端点异常时触发（参数：异常端点列表）。</summary>
    public event Action<IReadOnlyList<HealthCheckResult>>? UnhealthyDetected;

    /// <summary>创建网站健康检测器。</summary>
    public WebsiteHealthChecker(WebsiteHealthSection section, ILogger<WebsiteHealthChecker>? logger = null)
    {
        _section = section;
        _logger = logger;
        _httpClient = new HttpClient(new HttpClientHandler
        {
            // 不跟随重定向以准确判断端点状态
            AllowAutoRedirect = false,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true  // 教学环境自签证书容错
        })
        {
            Timeout = TimeSpan.FromSeconds(section.TimeoutSeconds > 0 ? section.TimeoutSeconds : 5)
        };
    }

    /// <summary>
    /// 启动周期健康检测。
    /// </summary>
    public void StartMonitoring()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var interval = _section.IntervalSeconds > 0 ? _section.IntervalSeconds : 60;
        _periodicTimer = new Timer(_ => CheckAllAsync().GetAwaiter().GetResult(), null, TimeSpan.Zero, TimeSpan.FromSeconds(interval));
        _logger?.LogInformation("Website health check started (interval: {Interval}s)", interval);
    }

    /// <summary>
    /// 执行一次完整健康检测。
    /// </summary>
    public async Task<IReadOnlyList<HealthCheckResult>> CheckAllAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var results = new List<HealthCheckResult>();

        foreach (var endpoint in _section.Endpoints)
        {
            var r = await CheckEndpointAsync(endpoint);
            results.Add(r);
        }

        CheckCompleted?.Invoke(results);

        var unhealthy = results.Where(r => !r.IsHealthy).ToList();
        if (unhealthy.Count > 0)
        {
            UnhealthyDetected?.Invoke(unhealthy);
            _logger?.LogWarning("Website health check: {Unhealthy}/{Total} endpoints unhealthy",
                unhealthy.Count, results.Count);
        }
        else
        {
            _logger?.LogInformation("Website health check: all {Total} endpoints healthy", results.Count);
        }

        return results;
    }

    /// <summary>
    /// 检测单个端点。
    /// </summary>
    public async Task<HealthCheckResult> CheckEndpointAsync(HealthEndpoint endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        try
        {
            var response = await _httpClient.GetAsync(endpoint.Url);
            var healthy = endpoint.ExpectedStatus == 0
                || (int)response.StatusCode == endpoint.ExpectedStatus;
            return new HealthCheckResult(
                endpoint.Name, endpoint.Url, (int)response.StatusCode, healthy, null);
        }
        catch (TaskCanceledException)
        {
            return new HealthCheckResult(endpoint.Name, endpoint.Url, 0, false, "请求超时");
        }
        catch (HttpRequestException ex)
        {
            return new HealthCheckResult(endpoint.Name, endpoint.Url, 0, false, ex.Message);
        }
        catch (Exception ex)
        {
            return new HealthCheckResult(endpoint.Name, endpoint.Url, 0, false, ex.Message);
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _periodicTimer?.Dispose();
        _httpClient.Dispose();
    }
}

/// <summary>
/// 健康检测结果（不可变）。
/// </summary>
public sealed record HealthCheckResult(
    string Name,
    string Url,
    int StatusCode,
    bool IsHealthy,
    string? ErrorMessage);
