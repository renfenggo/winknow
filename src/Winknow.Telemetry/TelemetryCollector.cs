namespace Winknow.Telemetry;

/// <summary>
/// 线程安全事件队列（ITelemetrySink 实现）。
/// 上限保护：溢出丢最旧——管控路径的 Enqueue 永不阻塞、永不抛。
/// </summary>
/// <param name="maxQueueSize">队列上限（&lt;=0 时回退 1000）。</param>
public sealed class TelemetryCollector(int maxQueueSize = 1000) : ITelemetrySink
{
    /// <summary>队列上限（构造时归一化）。</summary>
    public int MaxQueueSize { get; } = maxQueueSize > 0 ? maxQueueSize : 1000;

    private readonly object _lock = new();
    private readonly Queue<TelemetryEvent> _queue = new();

    /// <summary>当前排队事件数。</summary>
    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _queue.Count;
            }
        }
    }

    /// <summary>事件入队（超上限丢最旧；永不阻塞/抛）。</summary>
    /// <param name="evt">待上报事件。</param>
    public void Enqueue(TelemetryEvent evt)
    {
        lock (_lock)
        {
            if (_queue.Count >= MaxQueueSize)
            {
                _queue.Dequeue(); // 丢最旧：近因优先
            }

            _queue.Enqueue(evt);
        }
    }

    /// <summary>取走至多 max 条（调用方负责上报成败；失败即弃——event_id 幂等防重放）。</summary>
    public IReadOnlyList<TelemetryEvent> TakeBatch(int max)
    {
        lock (_lock)
        {
            var take = Math.Min(max, _queue.Count);
            if (take <= 0)
            {
                return Array.Empty<TelemetryEvent>();
            }

            var batch = new List<TelemetryEvent>(take);
            while (batch.Count < take)
            {
                batch.Add(_queue.Dequeue());
            }

            return batch;
        }
    }
}
