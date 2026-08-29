using Microsoft.Extensions.Logging;
using Winknow.Core;
using Winknow.DeviceSecurity;
using Winknow.Ipc;
using Winknow.Logging;
using Winknow.Network;
using Winknow.Policy;
using Winknow.ProcessControl;
using Winknow.Security;

namespace Winknow.ControlService;

/// <summary>
/// ControlService 核心管控服务的工作器。
/// 运行身份：LocalSystem | 服务名：Winknow Control Service
///
/// 禁止：不承担交互式键盘钩子（由 SessionAgent 负责）
/// </summary>
internal sealed class Worker : BackgroundService
{
    // 服务名：必须与 Program.cs 中 AddWindowsService(options => options.ServiceName) 保持一致
    private const string ServiceName = "Winknow Control Service";

    private readonly ILogger<Worker> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private IpcServer? _ipcServer;
    private WmiProcessMonitor? _wmiMonitor;
    private ProcessScanner? _scanner;
    private ProcessJudge? _judge;
    private ProcessTerminator? _terminator;
    private HostsProtector? _hostsProtector;
    private WebsiteFilter? _websiteFilter;
    private UsbStorageController? _usbController;
    private ProxyGuard? _proxyGuard;
    private DnsMonitor? _dnsMonitor;
    private BrowserPolicyEnforcer? _browserPolicyEnforcer;
    private VpnTunDetector? _vpnDetector;
    private WebsiteHealthChecker? _websiteHealthChecker;
    private PolicyFile? _policy;
    private DeviceLogKeyGenerator? _keyGenerator;
    private LogCipher? _logCipher;
    private HashChain? _hashChain;
    private LogCheckpointSigner? _checkpointSigner;
    private EventLogAnchor? _eventLogAnchor;
    private DataRetentionManager? _retentionManager;
    private SingleInstanceGuard? _instanceGuard;
    private HeartbeatLease? _heartbeatLease;

    internal Worker(ILogger<Worker> logger, ILoggerFactory loggerFactory)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // 第 10 周单实例守卫：全局 Mutex 竞争唯一运行权，拿不到锁说明已有实例在运行，
        // 本实例直接退出（防更新/守护交叉拉起产生双进程）
        var dataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Winknow");
        _instanceGuard = new SingleInstanceGuard(@"Global\Winknow_ControlService_Instance", dataDir);
        if (!_instanceGuard.IsAcquired)
        {
            var owner = _instanceGuard.ReadOwner();
            _logger.LogCritical(
                "另一个 ControlService 实例正在运行（PID={OwnerPid}，{OwnerPath}），本实例退出",
                owner?.Pid, owner?.ExePath);
            _instanceGuard.Dispose();
            _instanceGuard = null;
            return; // 不继续初始化任何管控设施：双实例会导致策略重复执行与 IPC 端口竞争
        }

        // 0. 自保护：进程 DACL + 服务 DACL + SCM 失败恢复 + SafeBoot 注册（幂等）
        // 服务级保护也可由 RecoveryTool protect 在安装期应用；此处确保运行期自硬化
        ApplySelfProtection();

        // 1. 加载策略文件（单一可信源：白名单/高风险黑名单/网络/USB 均来自此）
        var policyPath = Path.Combine(
            AppContext.BaseDirectory, "policies", "default_policy_v7.0.json");
        if (File.Exists(policyPath))
        {
            var policyLoader = new PolicyLoader(_loggerFactory.CreateLogger<PolicyLoader>());
            var policyResult = policyLoader.Load(policyPath);
            if (policyResult.IsSuccess)
            {
                _policy = policyResult.Data!;
                _logger?.LogInformation("Policy loaded: {PolicyId} v{Version}",
                    _policy.PolicyId, _policy.Version);
            }
            else
            {
                _logger?.LogError("Failed to load policy: {Error}", policyResult.ErrorMessage);
            }
        }
        else
        {
            _logger?.LogWarning("Policy file not found at {Path}, using defaults", policyPath);
        }

        // 8. 自保护加固
        var serviceDacl = new ServiceDaclProtector(_loggerFactory.CreateLogger<ServiceDaclProtector>());
        serviceDacl.Harden("Winknow Control Service");
        serviceDacl.Harden("Winknow Guard Service");
        serviceDacl.DisableStopForUsers("Winknow Control Service");
        _logger?.LogInformation("Service DACL hardened");

        // 9. 注册表保护 + 策略执行
        var registryProtector = new RegistryAclProtector(_loggerFactory.CreateLogger<RegistryAclProtector>());
        registryProtector.ProtectWinknowServiceKeys();
        _logger?.LogInformation("Registry keys protected");

        var policyEnforcer = new PolicyEnforcer(_loggerFactory.CreateLogger<PolicyEnforcer>());
        policyEnforcer.DisableTaskManager();
        policyEnforcer.DisableRegistryEditor();
        policyEnforcer.DisableCommandPrompt();
        _logger?.LogInformation("System policy enforced (TaskMgr/RegEdit/CMD disabled)");

        // 检查 Run 键篡改
        var suspiciousItems = policyEnforcer.CheckRunKeyForModifications();
        if (suspiciousItems.Count > 0)
        {
            _logger?.LogWarning("Suspicious Run key entries detected: {Count}", suspiciousItems.Count);
            foreach (var item in suspiciousItems)
            {
                _logger?.LogWarning("  Suspicious: {Entry}", item);
            }
        }

        // 10. 密钥与日志完整性基础设施（第 9 周）
        var deviceId = DeviceId.Generate();
        var programDataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Winknow");
        var keyDir = Path.Combine(programDataDir, "keys");
        Directory.CreateDirectory(keyDir);

        _keyGenerator = new DeviceLogKeyGenerator(
            keyDir, deviceId, _loggerFactory.CreateLogger<DeviceLogKeyGenerator>());
        var logKeyResult = _keyGenerator.GetOrCreateLogEncryptionKey();
        var hmacKeyResult = _keyGenerator.GetOrCreateLogCheckpointKey();

        if (logKeyResult.IsSuccess && hmacKeyResult.IsSuccess)
        {
            _logCipher = new LogCipher(logKeyResult.Data!, _loggerFactory.CreateLogger<LogCipher>());
            _hashChain = new HashChain(logger: _loggerFactory.CreateLogger<HashChain>());
            _checkpointSigner = new LogCheckpointSigner(
                hmacKeyResult.Data!, _loggerFactory.CreateLogger<LogCheckpointSigner>());
            _logger?.LogInformation("Log infrastructure initialized (AES-256-GCM + HashChain + HMAC checkpoint)");

            // 生成密钥清单（声明客户端不含签名私钥）
            var manifest = _keyGenerator.GenerateManifest(deviceId);
            _logger?.LogInformation("Key manifest: {Count} keys declared (CodeSigning private key: {HasSigningKey})",
                manifest.Keys.Count,
                manifest.Keys.Any(k => k.Purpose == KeyPurpose.CodeSigning && k.ContainsPrivateKey));
        }
        else
        {
            _logger?.LogError("Failed to initialize log keys: logKey={LogErr}, hmacKey={HmacErr}",
                logKeyResult.ErrorMessage, hmacKeyResult.ErrorMessage);
        }

        // Event Log 锚点：关键事件双写到 Windows 事件日志
        _eventLogAnchor = new EventLogAnchor("Winknow", logger: _loggerFactory.CreateLogger<EventLogAnchor>());
        var anchorInit = _eventLogAnchor.Initialize();
        _logger?.LogInformation("Event log anchor: {Status}", anchorInit.IsSuccess ? "initialized" : anchorInit.ErrorMessage);
        _eventLogAnchor.WriteSecurityAnchor("ServiceStarted", deviceId);

        // 数据保留管理器：启动时清理过期记录
        var dbPath = Path.Combine(programDataDir, Constants.Logging.DatabaseFileName);
        _retentionManager = new DataRetentionManager(
            dbPath, logger: _loggerFactory.CreateLogger<DataRetentionManager>());
        var purgeResult = _retentionManager.PurgeExpired();
        if (purgeResult.IsSuccess && purgeResult.Data > 0)
        {
            _logger?.LogInformation("Purged {Count} expired audit records on startup (retention: {Days} days)",
                purgeResult.Data, _retentionManager.RetentionDays);
        }

        _logger?.LogInformation("Privacy policy: {Summary}", PrivacyPolicy.GetSummary());

        // 2. 初始化进程管控（白名单与高风险黑名单从策略加载，无策略时用系统基础设施兜底）
        var whitelist = _policy is not null
            ? WhitelistRuleSet.FromPolicy(_policy)
            : WhitelistRuleSet.CreateDefault();
        var highRisk = _policy?.SoftwareControl.HighRiskInterpreters.Blocked;
        _judge = new ProcessJudge(
            whitelist,
            _loggerFactory.CreateLogger<ProcessJudge>(),
            highRisk);
        _terminator = new ProcessTerminator(_loggerFactory.CreateLogger<ProcessTerminator>());

        // 3. 启动 IPC 服务端
        var authenticator = IpcAuthenticator.CreateForControlService(deviceId);
        _ipcServer = new IpcServer(
            IpcConstants.ControlPipeName,
            authenticator,
            _loggerFactory.CreateLogger<IpcServer>());
        _ipcServer.MessageReceived += OnMessageReceived;
        await _ipcServer.StartAsync();
        _logger?.LogInformation("IPC server started on pipe {PipeName}", IpcConstants.ControlPipeName);

        // 4. 启动 WMI 进程实时监听
        _wmiMonitor = new WmiProcessMonitor(_loggerFactory.CreateLogger<WmiProcessMonitor>());
        _wmiMonitor.ProcessStarted += OnProcessStarted;
        _wmiMonitor.Start();
        _logger?.LogInformation("WMI ProcessStartTrace monitor started");

        // 5. 启动全量扫描 + 周期扫描
        _scanner = new ProcessScanner(
            scanInterval: TimeSpan.FromSeconds(2),
            logger: _loggerFactory.CreateLogger<ProcessScanner>());
        _scanner.ScanCompleted += OnScanCompleted;

        // 启动时执行一次全量扫描
        _logger?.LogInformation("Performing initial full process scan...");
        _scanner.ScanAll();

        // 启动周期扫描
        _scanner.StartPeriodicScan();
        _logger?.LogInformation("Periodic scan started (interval: 2s)");

        // 6. 应用网络管控（策略已加载时）
        if (_policy is not null)
        {
            _websiteFilter = new WebsiteFilter(_loggerFactory.CreateLogger<WebsiteFilter>());
            _websiteFilter.LoadFromPolicy(_policy.NetworkControl.WebsiteWhitelist);
            _logger?.LogInformation("Website filter loaded: {Count} domains",
                _policy.NetworkControl.WebsiteWhitelist.Domains.Count);

            _hostsProtector = new HostsProtector(_loggerFactory.CreateLogger<HostsProtector>());
            _hostsProtector.Initialize();
            _hostsProtector.StartMonitoring();
            _logger?.LogInformation("Hosts file protection started");

            // 8. 第 8 周网络防绕过：代理守卫 + PAC 保护 + DNS 监控 + 浏览器策略 + VPN 检测 + 网站健康
            _proxyGuard = new ProxyGuard(
                _policy.NetworkControl.Proxy,
                _loggerFactory.CreateLogger<ProxyGuard>());
            _proxyGuard.StartMonitoring();
            _logger?.LogInformation("Proxy guard started (20s periodic check)");

            _dnsMonitor = new DnsMonitor(
                _policy.NetworkControl.Dns,
                _loggerFactory.CreateLogger<DnsMonitor>());
            _dnsMonitor.Check();
            _logger?.LogInformation("DNS monitor initialized");

            _browserPolicyEnforcer = new BrowserPolicyEnforcer(
                _loggerFactory.CreateLogger<BrowserPolicyEnforcer>());
            var browserResult = _browserPolicyEnforcer.ApplyAll(_policy.NetworkControl.BrowserPolicy);
            _logger?.LogInformation("Browser enterprise policy: {Status}",
                browserResult.IsSuccess ? "applied" : browserResult.ErrorMessage);

            _vpnDetector = new VpnTunDetector(
                _policy.NetworkControl.VpnDetection,
                _loggerFactory.CreateLogger<VpnTunDetector>());
            var vpnResult = _vpnDetector.Detect();
            if (vpnResult.Detected)
            {
                _logger?.LogWarning("VPN detected on startup: {Count} items", vpnResult.Items.Count);
            }

            if (_policy.NetworkControl.WebsiteHealth.Endpoints.Count > 0)
            {
                _websiteHealthChecker = new WebsiteHealthChecker(
                    _policy.NetworkControl.WebsiteHealth,
                    _loggerFactory.CreateLogger<WebsiteHealthChecker>());
                _websiteHealthChecker.UnhealthyDetected += items =>
                    _logger?.LogWarning("Website unhealthy: {Endpoints}",
                        string.Join(", ", items.Select(i => i.Name)));
                _websiteHealthChecker.StartMonitoring();
                _logger?.LogInformation("Website health checker started");
            }

            // 9. 应用 USB 管控
            _usbController = new UsbStorageController(_loggerFactory.CreateLogger<UsbStorageController>());
            if (!_policy.UsbControl.MassStorage.Enabled)
            {
                _usbController.Disable();
                _logger?.LogWarning("USB Mass Storage disabled by policy");
            }
            else
            {
                _usbController.Enable();
                _logger?.LogInformation("USB Mass Storage enabled by policy");
            }
        }

        // 11. 心跳租约：周期续签供 GuardService 判定真实活性（第 10 周）
        //     替代纯服务状态检测：本循环挂起时租约自然过期，守护将识别"Running 但僵死"
        _heartbeatLease = new HeartbeatLease(dataDir);
        var processStartedAt = DateTimeOffset.UtcNow;
        _logger?.LogInformation("Heartbeat lease writer started (interval: {Interval}s)",
            Constants.Guard.HeartbeatIntervalSeconds);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                _ = _heartbeatLease.Write(Environment.ProcessId, ServiceName, Constants.Version, processStartedAt);
                await Task.Delay(TimeSpan.FromSeconds(Constants.Guard.HeartbeatIntervalSeconds), stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            // 正常关闭
        }
        finally
        {
            _wmiMonitor?.Dispose();
            _scanner?.Dispose();
            _hostsProtector?.Dispose();
            _proxyGuard?.Dispose();
            _websiteHealthChecker?.Dispose();
            _logCipher?.Dispose();
            _checkpointSigner?.Dispose();
            _eventLogAnchor?.Dispose();
            authenticator.Dispose();

            if (_ipcServer is not null)
            {
                _ipcServer.MessageReceived -= OnMessageReceived;
                await _ipcServer.StopAsync();
            }

            // 正常退出时清除租约：守护立即感知停止，无需等待超时
            _heartbeatLease?.Clear();
            _instanceGuard?.Dispose();
        }
    }

    /// <summary>
    /// WMI 检测到新进程启动时的处理。
    /// </summary>
    private void OnProcessStarted(ProcessInfo info)
    {
        if (_judge is null || _terminator is null)
        {
            return;
        }

        var result = _judge.Judge(info);
        if (!result.IsSuccess)
        {
            _logger?.LogWarning("Blocking process: {Pid} {Name} {Path} - {Reason}",
                info.ProcessId, info.ProcessName, info.FilePath, result.ErrorMessage);
            _terminator.Terminate(info.ProcessId, result.ErrorMessage ?? "Blocked by policy");
            _eventLogAnchor?.WriteSecurityAnchor("ProcessBlocked",
                $"{info.ProcessName} (PID={info.ProcessId}): {result.ErrorMessage}");
        }
    }

    /// <summary>
    /// 周期扫描完成时的处理。
    /// </summary>
    private void OnScanCompleted(IReadOnlyList<ProcessInfo> processes)
    {
        if (_judge is null || _terminator is null)
        {
            return;
        }

        var blockedCount = 0;
        foreach (var info in processes)
        {
            var result = _judge.Judge(info);
            if (!result.IsSuccess)
            {
                _logger?.LogWarning("Blocking process (scan): {Pid} {Name} - {Reason}",
                    info.ProcessId, info.ProcessName, result.ErrorMessage);
                if (_terminator.Terminate(info.ProcessId, result.ErrorMessage ?? "Blocked by scan"))
                {
                    blockedCount++;
                }
            }
        }

        if (blockedCount > 0)
        {
            _logger?.LogWarning("Scan completed: {Total} processes, {Blocked} blocked",
                processes.Count, blockedCount);
        }
    }

    /// <summary>
    /// 应用服务自保护（幂等）：
    /// 1. 进程 DACL：防止标准用户 taskkill 本服务进程
    /// 2. 服务 DACL：防止标准用户 Stop-Service / sc stop
    /// 3. SCM 失败恢复：异常退出后自动重启
    /// 4. SafeBoot 注册：安全模式下正常启动
    /// 任一失败仅记录日志，不阻断主流程。
    /// </summary>
    private void ApplySelfProtection()
    {
        // 进程 DACL：LocalSystem 可直接应用
        var proc = ProcessSecurity.ProtectCurrentProcess(_logger);
        _logger?.LogInformation("Process DACL: {Status}", proc.IsSuccess ? "applied" : proc.ErrorMessage);

        // 服务级保护：需 SCM 句柄，LocalSystem 具备权限
        var dacl = ServiceSecurity.ApplyServiceProtection(ServiceName, _logger);
        _logger?.LogInformation("Service DACL: {Status}", dacl.IsSuccess ? "applied" : dacl.ErrorMessage);

        var recovery = ServiceRecovery.ApplyServiceRecovery(ServiceName, _logger);
        _logger?.LogInformation("Service recovery: {Status}", recovery.IsSuccess ? "configured" : recovery.ErrorMessage);

        var safeBoot = SafeBootRegistrar.Register(ServiceName, "Winknow 核心管控服务", _logger);
        _logger?.LogInformation("SafeBoot registration: {Status}", safeBoot.IsSuccess ? "registered" : safeBoot.ErrorMessage);
    }

    private Task OnMessageReceived(IpcMessage message, CancellationToken cancellationToken)
    {
        _logger?.LogDebug("Received IPC message: Type={MessageType} RequestId={RequestId}",
            message.MessageType, message.RequestId);
        return Task.CompletedTask;
    }
}
