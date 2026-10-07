using System.Net;
using System.Text;
using System.Text.Json;
using Winknow.Telemetry;

namespace Winknow.Telemetry.Tests;

/// <summary>
/// 可编程 HttpMessageHandler：按序返回预设响应并记录全部请求（方法/路径/请求体）。
/// </summary>
internal sealed class FakeHttpHandler : HttpMessageHandler
{
    private readonly Queue<HttpResponseMessage> _responses = new();
    public List<(string Method, string Path, string Body)> Requests { get; } = new();

    public bool ThrowNext { get; set; }

    public void Enqueue(HttpStatusCode status, string json = "{}")
    {
        _responses.Enqueue(new HttpResponseMessage(status)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        });
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null
            ? string.Empty
            : request.Content.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult();
        Requests.Add((
            request.Method.Method,
            request.RequestUri?.AbsolutePath ?? string.Empty,
            body));
        if (ThrowNext)
        {
            ThrowNext = false;
            throw new HttpRequestException("simulated network failure");
        }

        return Task.FromResult(_responses.Count > 0
            ? _responses.Dequeue()
            : new HttpResponseMessage(HttpStatusCode.OK));
    }
}

public class CollectorTests
{
    [Fact]
    public void Enqueue_超上限丢最旧()
    {
        var collector = new TelemetryCollector(maxQueueSize: 3);
        foreach (var id in new[] { "e1", "e2", "e3", "e4" })
        {
            collector.Enqueue(new TelemetryEvent { EventId = id, EventName = "runner.run_result" });
        }

        Assert.Equal(3, collector.Count);
        var batch = collector.TakeBatch(10);
        Assert.Equal(new[] { "e2", "e3", "e4" }, batch.Select(e => e.EventId));
    }

    [Fact]
    public void TakeBatch_空队列返回空()
    {
        var collector = new TelemetryCollector();
        Assert.Empty(collector.TakeBatch(10));
    }
}

public class EventsFactoryTests
{
    [Theory]
    [InlineData("device.policy_result")]
    [InlineData("runner.compile_result")]
    [InlineData("runner.run_result")]
    [InlineData("classroom.begin")]
    [InlineData("classroom.end")]
    public void 工厂事件名在platform白名单内(string expectedName)
    {
        var all = new[]
        {
            TelemetryEvents.PolicyResult("p1", "v7.0", true, null),
            TelemetryEvents.CompileResult("r1", "COMPILED_OK", 120, 0),
            TelemetryEvents.RunResult("r1", "RUN_OK", 80, 0),
            TelemetryEvents.ClassroomBegin("cls-1"),
            TelemetryEvents.ClassroomEnd("cls-1", 1800),
        };
        Assert.Contains(all, e => e.EventName == expectedName);
    }

    [Fact]
    public void 每次生成新event_id()
    {
        var a = TelemetryEvents.PolicyResult("p", "v", true, null);
        var b = TelemetryEvents.PolicyResult("p", "v", true, null);
        Assert.NotEqual(a.EventId, b.EventId);
        Assert.Equal(32, a.EventId.Length); // Guid N 格式
    }

    [Fact]
    public void 事件序列化为snake_case且null省略()
    {
        var evt = TelemetryEvents.CompileResult("req-9", "COMPILE_FAILED", 250, 1,
            deviceId: "DEV-X", appVersion: "7.0.1");
        var json = JsonSerializer.Serialize(evt, TelemetryJson.Options);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal("runner.compile_result", root.GetProperty("event_name").GetString());
        Assert.Equal("DEV-X", root.GetProperty("device_id").GetString());
        Assert.False(root.TryGetProperty("session_id", out _)); // null 省略
        var props = root.GetProperty("properties");
        Assert.Equal("req-9", props.GetProperty("request_id").GetString());
        Assert.Equal(250, props.GetProperty("elapsed_ms").GetInt64());
        Assert.Equal(1, props.GetProperty("compile_exit_code").GetInt32());
    }
}

public class PlatformApiClientTests
{
    private static (PlatformApiClient Client, FakeHttpHandler Handler, HttpContent _) Make()
    {
        var handler = new FakeHttpHandler();
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://platform.test/") };
        var client = new PlatformApiClient(http, new TelemetryOptions
        {
            BaseUrl = "https://platform.test/",
            Username = "tch-1",
            Password = "pw",
        });
        return (client, handler, null!);
    }

    [Fact]
    public async Task 登录成功后心跳携带令牌与契约字段()
    {
        var (client, handler, _) = Make();
        handler.Enqueue(HttpStatusCode.OK, """{"access_token":"tok-1"}""");
        handler.Enqueue(HttpStatusCode.OK, """{"device_id":"d1"}""");

        Assert.True(await client.EnsureTokenAsync(CancellationToken.None));
        Assert.True(await client.SendHeartbeatAsync(new HeartbeatPayload
        {
            DeviceId = "DEV-101",
            DisplayName = "ROOM-101",
            ClientVersion = "7.0.1",
            PolicyVersion = "v7.0",
            Status = "online",
        }, CancellationToken.None));

        Assert.Equal(2, handler.Requests.Count);
        var (method1, path1, loginBody) = handler.Requests[0];
        Assert.Equal("POST", method1);
        Assert.Equal("/v1/auth/login", path1);
        using var login = JsonDocument.Parse(loginBody);
        Assert.Equal("tch-1", login.RootElement.GetProperty("username").GetString());

        var (method2, path2, hbBody) = handler.Requests[1];
        Assert.Equal("POST", method2);
        Assert.Equal("/v1/devices/heartbeat", path2);
        using var hb = JsonDocument.Parse(hbBody);
        Assert.Equal("DEV-101", hb.RootElement.GetProperty("device_id").GetString());
        Assert.Equal("v7.0", hb.RootElement.GetProperty("policy_version").GetString());
    }

    [Fact]
    public async Task 登录失败_心跳端点不发送()
    {
        var (client, handler, _) = Make();
        handler.Enqueue(HttpStatusCode.Unauthorized, """{"code":"UNAUTHENTICATED"}""");

        Assert.False(await client.EnsureTokenAsync(CancellationToken.None));
        // 无令牌时 SendHeartbeatAsync 内部会再次尝试登录（PostAsync 前置确保），
        // 但绝不触达 /v1/devices/heartbeat
        Assert.False(await client.SendHeartbeatAsync(
            new HeartbeatPayload { DeviceId = "DEV-1" }, CancellationToken.None));
        Assert.All(handler.Requests, r => Assert.Equal("/v1/auth/login", r.Path));
        Assert.DoesNotContain(handler.Requests, r => r.Path != "/v1/auth/login");
    }

    [Fact]
    public async Task 心跳403不抛_灰度语义()
    {
        var (client, handler, _) = Make();
        handler.Enqueue(HttpStatusCode.OK, """{"access_token":"tok-1"}""");
        handler.Enqueue(HttpStatusCode.Forbidden, """{"code":"PERMISSION_DENIED"}""");

        Assert.True(await client.EnsureTokenAsync(CancellationToken.None));
        var ok = await client.SendHeartbeatAsync(
            new HeartbeatPayload { DeviceId = "DEV-1" }, CancellationToken.None);
        Assert.False(ok); // 403 = classroom_cloud 未开，静默
    }

    [Fact]
    public async Task 事件上报401时重登一次重试()
    {
        var (client, handler, _) = Make();
        handler.Enqueue(HttpStatusCode.OK, """{"access_token":"tok-1"}""");
        handler.Enqueue(HttpStatusCode.Unauthorized, """{"code":"UNAUTHENTICATED"}"""); // 旧令牌过期
        handler.Enqueue(HttpStatusCode.OK, """{"access_token":"tok-2"}""");            // 重登
        handler.Enqueue(HttpStatusCode.OK, """{"accepted":1,"duplicated":0}""");       // 重试成功

        Assert.True(await client.EnsureTokenAsync(CancellationToken.None));
        var evt = new TelemetryEvent { EventId = "e-1", EventName = "classroom.begin" };
        Assert.True(await client.SendEventsAsync(new[] { evt }, CancellationToken.None));
        Assert.Equal(4, handler.Requests.Count);
        Assert.Equal("/v1/auth/login", handler.Requests[2].Path);
        Assert.Equal("/v1/events", handler.Requests[3].Path);
    }

    [Fact]
    public async Task 网络异常吞为false()
    {
        var (client, handler, _) = Make();
        handler.ThrowNext = true;
        Assert.False(await client.EnsureTokenAsync(CancellationToken.None));
    }
}

public class TelemetryWorkerTests
{
    private static (TelemetryWorker Worker, FakeHttpHandler Handler, TelemetryCollector Collector) Make(
        int intervalSeconds = 60)
    {
        var handler = new FakeHttpHandler();
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://platform.test/") };
        var options = new TelemetryOptions
        {
            BaseUrl = "https://platform.test/",
            Username = "tch-1",
            Password = "pw",
            HeartbeatIntervalSeconds = intervalSeconds,
        };
        var client = new PlatformApiClient(http, options);
        var collector = new TelemetryCollector();
        var worker = new TelemetryWorker(
            client, collector,
            () => new HeartbeatPayload { DeviceId = "DEV-W", ClientVersion = "7.0.1" },
            options);
        return (worker, handler, collector);
    }

    [Fact]
    public async Task Tick_登录心跳加事件排空()
    {
        var (worker, handler, collector) = Make();
        collector.Enqueue(new TelemetryEvent { EventId = "e-1", EventName = "device.policy_result" });
        collector.Enqueue(new TelemetryEvent { EventId = "e-2", EventName = "runner.run_result" });
        handler.Enqueue(HttpStatusCode.OK, """{"access_token":"tok"}""");
        handler.Enqueue(HttpStatusCode.OK, "{}"); // heartbeat
        handler.Enqueue(HttpStatusCode.OK, """{"accepted":2,"duplicated":0}"""); // events

        await worker.TickAsync(CancellationToken.None);

        Assert.Equal(3, handler.Requests.Count);
        Assert.Equal("/v1/auth/login", handler.Requests[0].Path);
        Assert.Equal("/v1/devices/heartbeat", handler.Requests[1].Path);
        Assert.Equal("/v1/events", handler.Requests[2].Path);
        using var events = JsonDocument.Parse(handler.Requests[2].Body);
        Assert.Equal(2, events.RootElement.GetProperty("events").GetArrayLength());
        Assert.Equal(0, collector.Count);
    }

    [Fact]
    public async Task 登录失败时队列保留待下轮()
    {
        var (worker, handler, collector) = Make();
        collector.Enqueue(new TelemetryEvent { EventId = "e-1", EventName = "classroom.begin" });
        handler.Enqueue(HttpStatusCode.Unauthorized, "{}");

        await worker.TickAsync(CancellationToken.None);

        Assert.Single(handler.Requests);
        Assert.Equal(1, collector.Count); // 未丢弃
    }

    [Fact]
    public async Task 事件上报失败丢弃本批且不抛()
    {
        var (worker, handler, collector) = Make();
        collector.Enqueue(new TelemetryEvent { EventId = "e-1", EventName = "classroom.begin" });
        handler.Enqueue(HttpStatusCode.OK, """{"access_token":"tok"}""");
        handler.Enqueue(HttpStatusCode.OK, "{}");
        handler.Enqueue(HttpStatusCode.Forbidden, """{"code":"PERMISSION_DENIED"}"""); // telemetry 未开

        await worker.TickAsync(CancellationToken.None);

        Assert.Equal(0, collector.Count); // 失败批次已丢弃（幂等语义）
    }

    [Fact]
    public async Task RunAsync_未预期异常也不终止()
    {
        var (worker, handler, _) = Make(intervalSeconds: 0);
        handler.ThrowNext = true; // 每次 login 都网络异常

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        // interval=0 + 持续失败：循环空转直到取消；不抛即通过
        await worker.RunAsync(cts.Token);
    }
}
