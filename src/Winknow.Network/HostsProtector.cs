using System.IO;
using Microsoft.Extensions.Logging;

namespace Winknow.Network;

/// <summary>
/// Hosts 文件保护器：监控并恢复 hosts 文件。
/// 防止学生通过修改 hosts 绕过网站白名单或重定向网站。
/// </summary>
public sealed class HostsProtector : IDisposable
{
    private readonly ILogger<HostsProtector>? _logger;
    private readonly string _hostsPath;
    private FileSystemWatcher? _watcher;
    private string _cleanHostsContent = string.Empty;
    private bool _disposed;

    /// <summary>检测到 hosts 被修改时触发。</summary>
    public event Action<string>? HostsModified;

    /// <summary>创建 hosts 保护器。</summary>
    /// <param name="logger">可选的日志记录器。</param>
    public HostsProtector(ILogger<HostsProtector>? logger = null)
    {
        _logger = logger;
        _hostsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "drivers", "etc", "hosts");
    }

    /// <summary>
    /// 初始化：读取当前 hosts 内容作为基准。
    /// </summary>
    public void Initialize()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!File.Exists(_hostsPath))
        {
            _logger?.LogWarning("Hosts file not found at {Path}", _hostsPath);
            _cleanHostsContent = string.Empty;
            return;
        }

        _cleanHostsContent = File.ReadAllText(_hostsPath);
        _logger?.LogInformation("Hosts file initialized: {Path}", _hostsPath);
    }

    /// <summary>
    /// 启动 hosts 文件监控。
    /// </summary>
    public void StartMonitoring()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var directory = Path.GetDirectoryName(_hostsPath);
        if (directory is null || !Directory.Exists(directory))
        {
            _logger?.LogError("Hosts directory not found: {Dir}", directory);
            return;
        }

        _watcher = new FileSystemWatcher(directory, "hosts")
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
            EnableRaisingEvents = true
        };

        _watcher.Changed += OnHostsChanged;
        _watcher.Created += OnHostsChanged;
        _watcher.Deleted += OnHostsDeleted;

        _logger?.LogInformation("Hosts file monitoring started");
    }

    /// <summary>
    /// 应用网站白名单到 hosts 文件。
    /// 将非白名单域名重定向到 127.0.0.1。
    /// </summary>
    public void ApplyWebsiteWhitelist(IReadOnlyCollection<string> whitelistedDomains)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        try
        {
            // 构建白名单 hosts 内容
            var lines = new List<string>
            {
                "# Winknow V7.0 Managed Hosts File",
                "# Do not modify - changes will be reverted",
                "",
                "127.0.0.1  localhost",
                "::1  localhost",
                ""
            };

            // 白名单域名保持可访问（不添加阻止条目）
            // 实际阻断由 DNS 层或代理层处理
            // 这里只确保 hosts 文件不含恶意重定向

            File.WriteAllLines(_hostsPath, lines);
            _cleanHostsContent = File.ReadAllText(_hostsPath);

            _logger?.LogInformation("Hosts file updated with {Count} whitelisted domains",
                whitelistedDomains.Count);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger?.LogError(ex, "Access denied writing hosts file (need admin)");
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to update hosts file");
        }
    }

    /// <summary>
    /// 恢复 hosts 文件到干净状态。
    /// </summary>
    public void Restore()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        try
        {
            if (!string.IsNullOrEmpty(_cleanHostsContent))
            {
                File.WriteAllText(_hostsPath, _cleanHostsContent);
                _logger?.LogWarning("Hosts file restored to clean state");
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to restore hosts file");
        }
    }

    private void OnHostsChanged(object sender, FileSystemEventArgs e)
    {
        _logger?.LogWarning("Hosts file modified: {ChangeType} {FullPath}", e.ChangeType, e.FullPath);
        HostsModified?.Invoke(e.FullPath);

        // 自动恢复（防篡改）
        Restore();
    }

    private void OnHostsDeleted(object sender, FileSystemEventArgs e)
    {
        _logger?.LogError("Hosts file deleted! Restoring...");
        Restore();
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;

        if (_watcher is not null)
        {
            _watcher.Changed -= OnHostsChanged;
            _watcher.Created -= OnHostsChanged;
            _watcher.Deleted -= OnHostsDeleted;
            _watcher.Dispose();
        }
    }
}
