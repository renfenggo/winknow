using Winknow.Network;
using Winknow.Policy;

namespace Winknow.Policy.Tests;

/// <summary>
/// 网站白名单过滤器测试。
/// </summary>
public class WebsiteFilterTests
{
    private readonly WebsiteFilter _filter = new();

    public WebsiteFilterTests()
    {
        var config = new WebsiteWhitelistSection
        {
            Domains = new List<string>
            {
                "luogu.com.cn",
                "*.luogu.com.cn",
                "cdn.luogu.com.cn",
                "www.luogu.com.cn"
            }
        };
        _filter.LoadFromPolicy(config);
    }

    [Fact(DisplayName = "精确域名匹配")]
    public void IsAllowed_ExactMatch_True()
    {
        Assert.True(_filter.IsAllowed("luogu.com.cn"));
        Assert.True(_filter.IsAllowed("cdn.luogu.com.cn"));
        Assert.True(_filter.IsAllowed("www.luogu.com.cn"));
    }

    [Fact(DisplayName = "通配符域名匹配")]
    public void IsAllowed_WildcardMatch_True()
    {
        Assert.True(_filter.IsAllowed("sub.luogu.com.cn"));
        Assert.True(_filter.IsAllowed("abc.luogu.com.cn"));
    }

    [Fact(DisplayName = "非白名单域名拒绝")]
    public void IsAllowed_UnknownDomain_False()
    {
        Assert.False(_filter.IsAllowed("baidu.com"));
        Assert.False(_filter.IsAllowed("github.com"));
        Assert.False(_filter.IsAllowed("google.com"));
    }

    [Fact(DisplayName = "空域名拒绝")]
    public void IsAllowed_EmptyDomain_False()
    {
        Assert.False(_filter.IsAllowed(""));
        Assert.False(_filter.IsAllowed(string.Empty));
    }

    [Fact(DisplayName = "URL 白名单判断")]
    public void IsUrlAllowed_WhitelistedUrl_True()
    {
        Assert.True(_filter.IsUrlAllowed("https://luogu.com.cn"));
        Assert.True(_filter.IsUrlAllowed("https://www.luogu.com.cn/problem/123"));
    }

    [Fact(DisplayName = "非白名单 URL 拒绝")]
    public void IsUrlAllowed_UnknownUrl_False()
    {
        Assert.False(_filter.IsUrlAllowed("https://baidu.com"));
        Assert.False(_filter.IsUrlAllowed("https://github.com"));
    }

    [Fact(DisplayName = "无效 URL 拒绝")]
    public void IsUrlAllowed_InvalidUrl_False()
    {
        Assert.False(_filter.IsUrlAllowed("not a url"));
        Assert.False(_filter.IsUrlAllowed(""));
    }

    [Fact(DisplayName = "重载策略清空旧数据")]
    public void LoadFromPolicy_ReloadClearsOldData()
    {
        var newConfig = new WebsiteWhitelistSection
        {
            Domains = new List<string> { "newdomain.com" }
        };
        _filter.LoadFromPolicy(newConfig);

        Assert.True(_filter.IsAllowed("newdomain.com"));
        Assert.False(_filter.IsAllowed("luogu.com.cn"));
    }
}
