using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Winknow.Telemetry;

/// <summary>
/// platform API 客户端（login / 心跳 / 事件批量上报）。
/// 语义：一切失败返回 false 并记日志，绝不抛出——遥测是尽力而为的旁路，
/// 管控功能不依赖云端可用性（403 = flag 灰度未开，属预期部署状态）。
/// </summary>
public sealed class PlatformApiClient
{
    private readonly HttpClient _http;
    private readonly TelemetryOptions _options;
    private readonly ILogger? _logger;

    private string? _token;

    /// <summary>构造客户端。</summary>
    /// <param name="http">已配 BaseAddress 的 HttpClient（测试注入 FakeHandler）。</param>
    /// <param name="options">遥测配置（凭据/端点）。</param>
    /// <param name="logger">可选日志。</param>
    public PlatformApiClient(HttpClient http, TelemetryOptions options, ILogger? logger = null)
    {
        _http = http;
        _options = options;
        _logger = logger;
    }

    /// <summary>当前持有令牌（测试观测用）。</summary>
    internal string? Token => _token;

    /// <summary>确保已登录（无令牌或令牌被判定失效时重登）。成功返回 true。</summary>
    public async Task<bool> EnsureTokenAsync(CancellationToken ct)
    {
        if (_token is not null)
        {
            return true;
        }

        try
        {
            var body = JsonSerializer.Serialize(
                new { username = _options.Username, password = _options.Password },
                TelemetryJson.Options);
            using var resp = await _http.PostAsync(
                "/v1/auth/login", new StringContent(body, Encoding.UTF8, "application/json"), ct)
                .ConfigureAwait(false);
            if (resp.StatusCode != HttpStatusCode.OK)
            {
                _logger?.LogWarning("Telemetry login failed: {Status} (检查账号/密码)", (int)resp.StatusCode);
                return false;
            }

            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            _token = doc.RootElement.TryGetProperty("access_token", out var token)
                && token.ValueKind == JsonValueKind.String
                ? token.GetString()
                : null;
            if (string.IsNullOrEmpty(_token))
            {
                _logger?.LogWarning("Telemetry login response missing access_token");
                return false;
            }

            return true;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            _logger?.LogDebug("Telemetry login network error: {Error}", ex.Message);
            return false;
        }
    }

    /// <summary>上报心跳（POST /v1/devices/heartbeat）。403=classroom_cloud 未开，静默。</summary>
    public async Task<bool> SendHeartbeatAsync(HeartbeatPayload payload, CancellationToken ct)
    {
        var body = JsonSerializer.Serialize(
            new
            {
                device_id = payload.DeviceId,
                display_name = payload.DisplayName,
                status = payload.Status,
                client_version = payload.ClientVersion,
                policy_version = payload.PolicyVersion,
            }, TelemetryJson.Options);
        var (ok, status) = await PostAsync("/v1/devices/heartbeat", body, reloginOnce: false, ct)
            .ConfigureAwait(false);
        if (!ok && status == (int)HttpStatusCode.Forbidden)
        {
            // 部署灰度：classroom_cloud flag 未开启。提示一次即可，不重试刷屏
            _logger?.LogDebug("Heartbeat rejected 403: classroom_cloud flag 未开启（管理端可开启）");
        }

        return ok;
    }

    /// <summary>批量上报事件（POST /v1/events；401 时重登一次重试）。</summary>
    public async Task<bool> SendEventsAsync(IReadOnlyList<TelemetryEvent> events, CancellationToken ct)
    {
        if (events.Count == 0)
        {
            return true;
        }

        var body = JsonSerializer.Serialize(new { events }, TelemetryJson.Options);
        var (ok, _) = await PostAsync("/v1/events", body, reloginOnce: true, ct).ConfigureAwait(false);
        return ok;
    }

    private async Task<(bool Ok, int Status)> PostAsync(
        string path, string json, bool reloginOnce, CancellationToken ct)
    {
        if (!await EnsureTokenAsync(ct).ConfigureAwait(false))
        {
            return (false, 0);
        }

        for (var attempt = 0; attempt <= (reloginOnce ? 1 : 0); attempt++)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, path)
                {
                    Content = new StringContent(json, Encoding.UTF8, "application/json"),
                };
                request.Headers.Authorization = new("Bearer", _token);
                using var resp = await _http.SendAsync(request, ct).ConfigureAwait(false);
                if (resp.StatusCode == HttpStatusCode.Unauthorized)
                {
                    // 令牌过期：清空重登一次
                    _token = null;
                    if (reloginOnce && attempt == 0 && await EnsureTokenAsync(ct).ConfigureAwait(false))
                    {
                        continue;
                    }

                    return (false, (int)resp.StatusCode);
                }

                if (resp.StatusCode != HttpStatusCode.OK)
                {
                    _logger?.LogDebug("Telemetry POST {Path} failed: {Status}", path, (int)resp.StatusCode);
                    return (false, (int)resp.StatusCode);
                }

                return (true, (int)resp.StatusCode);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                _logger?.LogDebug("Telemetry POST {Path} network error: {Error}", path, ex.Message);
                return (false, 0);
            }
        }

        return (false, 0);
    }
}
