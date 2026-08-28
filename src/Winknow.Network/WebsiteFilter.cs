using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Winknow.Policy;

namespace Winknow.Network;

/// <summary>
/// 网站白名单过滤器。
/// 判断域名是否在白名单中（支持 * 通配符）。
/// </summary>
public sealed class WebsiteFilter
{
    private readonly ILogger<WebsiteFilter>? _logger;
    private readonly HashSet<string> _exactDomains = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Regex> _wildcardPatterns = new();

    /// <summary>创建网站过滤器。</summary>
    /// <param name="logger">可选的日志记录器。</param>
    public WebsiteFilter(ILogger<WebsiteFilter>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// 从策略配置加载白名单域名。
    /// </summary>
    public void LoadFromPolicy(WebsiteWhitelistSection config)
    {
        ArgumentNullException.ThrowIfNull(config);

        _exactDomains.Clear();
        _wildcardPatterns.Clear();

        foreach (var domain in config.Domains)
        {
            if (domain.Contains('*'))
            {
                // 通配符域名转正则
                var pattern = "^" + Regex.Escape(domain)
                    .Replace("\\*", ".*") + "$";
                _wildcardPatterns.Add(new Regex(pattern, RegexOptions.IgnoreCase));
            }
            else
            {
                _exactDomains.Add(domain);
            }
        }

        _logger?.LogInformation("Loaded {Exact} exact + {Wildcard} wildcard domains",
            _exactDomains.Count, _wildcardPatterns.Count);
    }

    /// <summary>
    /// 判断域名是否在白名单中。
    /// </summary>
    public bool IsAllowed(string domain)
    {
        if (string.IsNullOrEmpty(domain))
        {
            return false;
        }

        // 精确匹配
        if (_exactDomains.Contains(domain))
        {
            return true;
        }

        // 通配符匹配
        foreach (var pattern in _wildcardPatterns)
        {
            if (pattern.IsMatch(domain))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// 判断 URL 是否在白名单中。
    /// </summary>
    public bool IsUrlAllowed(string url)
    {
        if (string.IsNullOrEmpty(url))
        {
            return false;
        }

        try
        {
            var uri = new Uri(url);
            return IsAllowed(uri.Host);
        }
        catch (UriFormatException)
        {
            return false;
        }
    }
}
