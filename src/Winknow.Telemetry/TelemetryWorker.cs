using Microsoft.Extensions.Logging;

namespace Winknow.Telemetry;

/// <summary>
/// 遥测编排：周期 Tick = 确保登录 → 心跳 → 排空事件队列。
/// RunAsync 全吞异常（含 Tick 内部未预期异常）——云端不可用时静默降级，
/// 本地管控功能零依赖（指导书 10 可观测性：trace/事件尽力上报）。
/// </summary>
public sealed class TelemetryWorker
{
    private const int BatchSize = 200; // platform 契约单批上限

    private readonly PlatformApiClient _client;
    private readonly TelemetryCollector _collector;
    private readonly Func<HeartbeatPayload> _heartbeatFactory;
    private readonly TelemetryOptions _options;
    private readonly ILogger? _logger;

    /// <summary>构造编排器。</summary>
    /// <param name="client">platform 客户端（登录/心跳/事件）。</param>
    /// <param name="collector">事件队列（心跳外的事件缓冲）。</param>
    /// <param name="heartbeatFactory">心跳载荷工厂（每次 Tick 现取策略版本等实时值）。</param>
    /// <param name="options">遥测配置。</param>
    /// <param name="logger">可选日志。</param>
    public TelemetryWorker(
        PlatformApiClient client,
        TelemetryCollector collector,
        Func<HeartbeatPayload> heartbeatFactory,
        TelemetryOptions options,
        ILogger? logger = null)
    {
        _client = client;
        _collector = collector;
        _heartbeatFactory = heartbeatFactory;
        _options = options;
        _logger = logger;
    }

    /// <summary>主循环（间隔 HeartbeatIntervalSeconds；取消即退出）。</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        var interval = TimeSpan.FromSeconds(
            _options.HeartbeatIntervalSeconds > 0 ? _options.HeartbeatIntervalSeconds : 60);
        _logger?.LogInformation("Telemetry worker started (interval: {Interval}s)", (int)interval.TotalSeconds);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await TickAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                // 未预期异常也不允许终止循环（防御性：Tick 内部已全吞，此处兜底）
                _logger?.LogWarning("Telemetry tick unexpected failure: {Error}", ex.Message);
            }

            try
            {
                await Task.Delay(interval, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger?.LogInformation("Telemetry worker stopped");
    }

    /// <summary>单轮：登录 → 心跳 → 排空事件队列（公开以便单测）。</summary>
    public async Task TickAsync(CancellationToken ct)
    {
        if (!await _client.EnsureTokenAsync(ct).ConfigureAwait(false))
        {
            return; // 登录失败（网络/凭据）：本轮跳过，队列保留待下轮
        }

        _ = await _client.SendHeartbeatAsync(_heartbeatFactory(), ct).ConfigureAwait(false);

        while (true)
        {
            var batch = _collector.TakeBatch(BatchSize);
            if (batch.Count == 0)
            {
                return;
            }

            if (!await _client.SendEventsAsync(batch, ct).ConfigureAwait(false))
            {
                // 上报失败：本批丢弃（event_id 幂等使重放无意义），后续批次下轮再试
                return;
            }
        }
    }
}
