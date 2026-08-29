using Winknow.Network;
using Winknow.Policy;

namespace Winknow.Network.Tests;

/// <summary>
/// 第 8 周"网站健康检测"测试。
/// 覆盖验收项："洛谷完整功能正常"（端点可达性检测）
/// </summary>
public class WebsiteHealthTests : IDisposable
{
    private readonly WebsiteHealthChecker _checker;

    public WebsiteHealthTests()
    {
        _checker = new WebsiteHealthChecker(new WebsiteHealthSection
        {
            Endpoints = new List<HealthEndpoint>(),
            TimeoutSeconds = 2,
            IntervalSeconds = 60
        });
    }

    public void Dispose() => _checker.Dispose();

    [Fact]
    public async Task CheckAll_NoEndpoints_ReturnsEmpty()
    {
        var results = await _checker.CheckAllAsync();
        Assert.Empty(results);
    }

    [Fact]
    public async Task CheckEndpoint_UnreachableUrl_ReturnsUnhealthy()
    {
        var endpoint = new HealthEndpoint
        {
            Name = "测试不可达",
            Url = "http://127.0.0.1:1/nonexistent",  // 确定不可达
            ExpectedStatus = 200
        };
        var r = await _checker.CheckEndpointAsync(endpoint);
        Assert.False(r.IsHealthy);
        Assert.False(string.IsNullOrEmpty(r.ErrorMessage));
    }

    [Fact]
    public async Task CheckEndpoint_StatusMismatch_ReturnsUnhealthy()
    {
        // 用一个可达但状态码不匹配的端点
        var endpoint = new HealthEndpoint
        {
            Name = "状态码不匹配",
            Url = "http://127.0.0.1:1/test",
            ExpectedStatus = 999  // 不可达会返回 unhealthy
        };
        var r = await _checker.CheckEndpointAsync(endpoint);
        Assert.False(r.IsHealthy);
    }

    [Fact]
    public async Task CheckAll_MultipleEndpoints_ReturnsResults()
    {
        var checker = new WebsiteHealthChecker(new WebsiteHealthSection
        {
            Endpoints = new List<HealthEndpoint>
            {
                new() { Name = "端点1", Url = "http://127.0.0.1:1/a", ExpectedStatus = 200 },
                new() { Name = "端点2", Url = "http://127.0.0.1:1/b", ExpectedStatus = 0 }
            },
            TimeoutSeconds = 1,
            IntervalSeconds = 60
        });
        var results = await checker.CheckAllAsync();
        Assert.Equal(2, results.Count);
        Assert.All(results, r => Assert.False(r.IsHealthy));  // 都不可达
        checker.Dispose();
    }

    [Fact]
    public async Task CheckEndpoint_NullEndpoint_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => _checker.CheckEndpointAsync(null!));
    }

    [Fact]
    public void StartMonitoring_DoesNotThrow()
    {
        // 启动后立即 Dispose 不会抛异常
        var checker = new WebsiteHealthChecker(new WebsiteHealthSection
        {
            Endpoints = new List<HealthEndpoint>
            {
                new() { Name = "测试", Url = "http://127.0.0.1:1/test", ExpectedStatus = 0 }
            },
            TimeoutSeconds = 1,
            IntervalSeconds = 60
        });
        checker.StartMonitoring();
        checker.Dispose();
    }

    [Fact]
    public async Task CheckEndpoint_ExpectedStatusZero_OnlyChecksReachability()
    {
        // ExpectedStatus=0 表示仅校验可达，不校验状态码
        // 不可达端点仍返回 unhealthy
        var endpoint = new HealthEndpoint
        {
            Name = "仅可达校验",
            Url = "http://127.0.0.1:1/test",
            ExpectedStatus = 0
        };
        var r = await _checker.CheckEndpointAsync(endpoint);
        Assert.False(r.IsHealthy);
        Assert.Equal(0, r.StatusCode);
    }

    [Fact]
    public async Task CheckAll_FiresCompletedEvent()
    {
        var fired = false;
        var checker = new WebsiteHealthChecker(new WebsiteHealthSection
        {
            Endpoints = new List<HealthEndpoint>
            {
                new() { Name = "测试", Url = "http://127.0.0.1:1/test", ExpectedStatus = 0 }
            },
            TimeoutSeconds = 1,
            IntervalSeconds = 60
        });
        checker.CheckCompleted += _ => fired = true;
        await checker.CheckAllAsync();
        Assert.True(fired);
        checker.Dispose();
    }
}
