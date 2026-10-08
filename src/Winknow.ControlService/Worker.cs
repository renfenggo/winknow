using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Winknow.CodeRunner;
using Winknow.CodeRunner.Compilation;
using Winknow.Core;
using Winknow.Core.Results;
using Winknow.DeviceSecurity;
using Winknow.Ipc;
using Winknow.Ipc.Protocol;
using Winknow.Ipc.Session;
using Winknow.Logging;
using Winknow.Network;
using Winknow.Policy;
using Winknow.ProcessControl;
using Winknow.Security;
using Winknow.Telemetry;

namespace Winknow.ControlService;

/// <summary>
/// ControlService 核心管控服务的工作器。
/// 运行身份：LocalSystem | 服务名：Winknow Control Service
///
/// 禁止：不承担交互式键盘钩子（由 SessionAgent 负责）
/// </summary>
internal sealed class Worker : BackgroundService
{
    private const string ServiceName = Constants.Services.Control;

    /// <summary>
    /// IPC 握手宣布的服务端能力清单（与 ControlCommandHost 注册表的
    /// RequiredCapability 对齐；提取为常量供对齐测试引用）。
    ///
    /// P1（2026-10-08）：补 runner.execute——此前清单缺失导致生产握手
    /// 取交集后仅授予 runner.read，学习端编程工作台的 runner.execute 被
    /// IPC_CAPABILITY_MISMATCH 拒绝。dispatcher 的能力/角色校验保持不变
    /// （仅 bridge 角色可调、命令级 90s 超时）。
    /// </summary>
    internal static readonly IReadOnlySet<string> SupportedIpcCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            "status.read", "device.read", "classroom.control", "policy.control",
            "runner.read", "runner.execute", "system.control",
        };

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
    private ControlCommandHost? _commandHost;
    private DynamicSidAuthorizer? _sidAuthorizer;
    private WtsSessionMonitor? _wtsMonitor;
    private TelemetryRuntime? _telemetry;

    /// <summary>
    /// N01（2026-10-08 第二轮复核）：构造改 public 并注入 IHostEnvironment。
    /// 此前 internal 构造在 DI CallSiteFactory 只枚举 public 构造的约束下
    /// 无法被 host 激活（服务从未真实过 AddHostedService 路径）；public
    /// 构造不破坏 internal sealed 类的封装。宿主环境为权威环境事实来源。
    /// </summary>
    public Worker(
        ILogger<Worker> logger,
        ILoggerFactory loggerFactory,
        IConfiguration configuration,
        IHostEnvironment? hostEnvironment = null)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
        _configuration = configuration;
        _hostEnvironment = hostEnvironment;
    }

    private readonly IConfiguration _configuration;

    /// <summary>宿主注入的权威环境（Host.CreateApplicationBuilder 已注册；测试可注入 fake）。</summary>
    private readonly IHostEnvironment? _hostEnvironment;

    /// <summary>云端遥测运行时句柄（null = 未配置 BaseUrl，遥测整体禁用）。</summary>
    private sealed record TelemetryRuntime(
        TelemetryCollector Collector, CancellationTokenSource Cts, HttpClient Http);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // 第 10 周单实例守卫：全局 Mutex 竞争唯一运行权，拿不到锁说明已有实例在运行，
        // 本实例直接退出（防更新/守护交叉拉起产生双进程）
        var paths = new ProductPaths();
        paths.EnsureDirectories();
        var dataDir = paths.Root;
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
        // P0 生产收紧（2026-10-07）+ N01（2026-10-08 第二轮复核）：以宿主
        // IHostEnvironment 为权威环境（缺省 Production）；非 Development 环境
        // 必须提供正式公钥且策略验签通过，否则拒绝启用管控（fail-closed）。
        var policyPath = paths.ActivePolicy;
        if (File.Exists(policyPath))
        {
            var policyLoader = new PolicyLoader(_loggerFactory.CreateLogger<PolicyLoader>());
            var policyResult = LoadPolicyTrusted(policyLoader, policyPath);
            if (policyResult.IsSuccess)
            {
                _policy = policyResult.Data!;
                _logger?.LogInformation("Policy loaded: {PolicyId} v{Version}",
                    _policy.PolicyId, _policy.Version);
            }
            else
            {
                _logger?.LogError("Failed to load policy: {Error}", policyResult.ErrorMessage);
                if (!PolicyAllowsDevKey())
                {
                    _logger?.LogCritical(
                        "Production environment: refusing to start control service " +
                        "without a verifiable signed policy (fail-closed)");
                    _instanceGuard?.Dispose();
                    _instanceGuard = null;
                    return;
                }
            }
        }
        else if (!PolicyAllowsDevKey())
        {
            _logger?.LogCritical(
                "Production environment: active policy file missing at {Path}; " +
                "refusing to start control service (fail-closed)", policyPath);
            _instanceGuard?.Dispose();
            _instanceGuard = null;
            return;
        }
        else
        {
            _logger?.LogWarning("Policy file not found at {Path}, using defaults", policyPath);
        }

        // 8. 自保护加固
        var serviceDacl = new ServiceDaclProtector(_loggerFactory.CreateLogger<ServiceDaclProtector>());
        serviceDacl.Harden(Constants.Services.Control);
        serviceDacl.Harden(Constants.Services.Guard);
        serviceDacl.DisableStopForUsers(Constants.Services.Control);
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
        var programDataDir = paths.Root;
        var keyDir = paths.Keys;
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

        // 3. 启动 IPC 服务端（M2：连接期握手 + 能力协商，ADR-001）
        var authenticator = IpcAuthenticator.CreateForControlService(deviceId);
        var serverDescriptor = new IpcServerDescriptor
        {
            Protocol = ProtocolVersion.Current,
            ComponentVersion = Constants.Version,
            SupportedCapabilities = new HashSet<string>(Worker.SupportedIpcCapabilities, StringComparer.Ordinal),
            DeviceId = deviceId,
            SessionTtlSeconds = 28800,
        };
        _ipcServer = new IpcServer(
            IpcConstants.ControlPipeName,
            authenticator,
            new IpcHandshakeValidator(serverDescriptor),
            _loggerFactory.CreateLogger<IpcServer>());
        _ipcServer.MessageReceived += OnMessageReceived;

        // M3-5：Runner 执行器注入（runner.get_capabilities / runner.execute 后端）。
        // 启动期一次探测：工具链缺失不阻断服务启动，runner.* 诚实报告不可用
        var runnerToolchain = GppToolchain.Discover();
        var runnerExecutor = new RunnerExecutor(runnerToolchain, paths.RunnerWork);
        if (runnerExecutor.IsAvailable)
        {
            _logger?.LogInformation("CodeRunner toolchain ready: {Path} ({Version})",
                runnerToolchain!.CompilerPath, runnerToolchain.Version);
        }
        else
        {
            _logger?.LogWarning("CodeRunner toolchain not found; runner.* methods will report unavailable");
        }

        // M2-3：注册表式 dispatcher（method_registry.md 白名单，system/bridge 角色区分）
        // M8 Lane W：云端遥测（BaseUrl 未配置则整体禁用，管控功能零依赖云端）
        _telemetry = StartTelemetry(deviceId);
        var systemSidValue = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value;
        var adminsSidValue = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value;
        _commandHost = new ControlCommandHost(
            _loggerFactory.CreateLogger<ControlCommandHost>(),
            deviceId,
            Constants.Version,
            sid => sid == systemSidValue || sid == adminsSidValue,
            new IpcAuditSink(_loggerFactory.CreateLogger<IpcAuditSink>(), _eventLogAnchor),
            telemetrySink: _telemetry?.Collector)
        {
            PolicySnapshot = () => _policy,
            PolicyApplier = policyJson => ApplyPolicy(policyPath, policyJson),
            PolicyRestorer = () => RestorePolicy(policyPath),
            Runner = runnerExecutor,
        };
        _ipcServer.RequestReceived += OnRequestReceived;
        await _ipcServer.StartAsync();
        _logger?.LogInformation("IPC server started on pipe {PipeName}", IpcConstants.ControlPipeName);
        _logger?.LogInformation("IPC command registry ready: {Count} methods", _commandHost.Registry.Count);

        // M2-4：学生 SID 动态授权（ADR-002）：登录会话建立→AllowSid(TTL≤8h)，注销→RevokeSid
        _sidAuthorizer = new DynamicSidAuthorizer(
            authenticator, WtsSessionMonitor.QuerySessionUserSid,
            _loggerFactory.CreateLogger<DynamicSidAuthorizer>());
        _wtsMonitor = new WtsSessionMonitor(
            _sidAuthorizer.HandleSessionChange, _loggerFactory.CreateLogger<WtsSessionMonitor>());
        _wtsMonitor.Start();
        // 服务重启不应孤儿化既有登录会话：恢复授权现存 Active 会话
        foreach (var (existingSessionId, existingSid) in WtsSessionMonitor.EnumerateActiveSessionsWithSid())
        {
            if (existingSid is not null)
            {
                _sidAuthorizer.AuthorizeSession(existingSessionId, existingSid);
            }
        }

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
            var dnsStartupCheck = _dnsMonitor.Check();
            if (!dnsStartupCheck.IsSuccess)
            {
                _logger?.LogError("DNS monitor initial check failed: {Error}", dnsStartupCheck.ErrorMessage);
            }
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
                if (!_usbController.Disable())
                {
                    _logger?.LogError("USB Mass Storage Disable() failed on startup (registry write rejected)");
                }
                else
                {
                    _logger?.LogWarning("USB Mass Storage disabled by policy");
                }
            }
            else
            {
                if (!_usbController.Enable())
                {
                    _logger?.LogError("USB Mass Storage Enable() failed on startup (registry write rejected)");
                }
                else
                {
                    _logger?.LogInformation("USB Mass Storage enabled by policy");
                }
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
            _wtsMonitor?.Dispose();
            authenticator.Dispose();

            if (_ipcServer is not null)
            {
                _ipcServer.MessageReceived -= OnMessageReceived;
                _ipcServer.RequestReceived -= OnRequestReceived;
                await _ipcServer.StopAsync();
            }

            // 正常退出时清除租约：守护立即感知停止，无需等待超时
            _heartbeatLease?.Clear();
            _instanceGuard?.Dispose();

            // 云端遥测停机（尽力而为；未配置时为 null）
            if (_telemetry is not null)
            {
                _telemetry.Cts.Cancel();
                _telemetry.Cts.Dispose();
                _telemetry.Http.Dispose();
                _logger?.LogInformation("Cloud telemetry stopped");
            }
        }
    }

    /// <summary>
    /// 读取 "Telemetry" 配置节并启动云端遥测（M8 Lane W）。
    /// BaseUrl 为空 → 返回 null（默认禁用，零行为变化）；
    /// 启用后周期心跳（/v1/devices/heartbeat）+ 事件排空（/v1/events），
    /// 全部失败静默——管控功能不依赖云端可用性。
    /// </summary>
    private TelemetryRuntime? StartTelemetry(string deviceId)
    {
        var options = _configuration.GetSection("Telemetry").Get<TelemetryOptions>()
            ?? new TelemetryOptions();
        if (string.IsNullOrWhiteSpace(options.BaseUrl))
        {
            _logger?.LogInformation("Cloud telemetry disabled (Telemetry:BaseUrl not configured)");
            return null;
        }

        var http = new HttpClient
        {
            BaseAddress = new Uri(options.BaseUrl.TrimEnd('/') + "/"),
            Timeout = TimeSpan.FromSeconds(15),
        };
        var client = new PlatformApiClient(
            http, options, _loggerFactory.CreateLogger<PlatformApiClient>());
        var collector = new TelemetryCollector(options.MaxQueueSize);
        var worker = new TelemetryWorker(
            client, collector,
            () => new HeartbeatPayload
            {
                DeviceId = deviceId,
                DisplayName = Environment.MachineName,
                Status = "online",
                ClientVersion = Constants.Version,
                PolicyVersion = _policy?.Version,
            },
            options,
            _loggerFactory.CreateLogger<TelemetryWorker>());
        var cts = new CancellationTokenSource();
        _ = worker.RunAsync(cts.Token); // fire-and-forget：RunAsync 全吞异常
        _logger?.LogInformation(
            "Cloud telemetry enabled (heartbeat {Interval}s, user={User})",
            options.HeartbeatIntervalSeconds, options.Username);
        return new TelemetryRuntime(collector, cts, http);
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

    /// <summary>
    /// 业务请求帧处理（M2-3 注册表式 dispatcher）：解析 RequestEnvelope 并转发命令注册表。
    /// </summary>
    private async Task<ResponseEnvelope> OnRequestReceived(IpcRequestContext context, CancellationToken cancellationToken)
    {
        if (_commandHost is null)
        {
            return ResponseEnvelope.FromError(ErrorEnvelope.Create(
                IpcErrorCodes.Unavailable, "command host is not initialized."));
        }

        RequestEnvelope? request;
        try
        {
            var json = Encoding.UTF8.GetString(context.Message.Payload);
            request = RequestEnvelope.Deserialize(json);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning("IPC request payload parse failed: {Error}", ex.Message);
            request = null;
        }

        if (request is null || string.IsNullOrEmpty(request.Method))
        {
            return ResponseEnvelope.FromError(ErrorEnvelope.Create(
                IpcErrorCodes.InvalidArgument, "malformed request payload."));
        }

        return await _commandHost.DispatchAsync(request, context.Session, cancellationToken, context.Message.RequestId);
    }

    /// <summary>
    /// 验证、备份并落盘新策略，随后重载并同步应用到运行中的执行器（policy.apply 后端）。
    /// 非法策略在候选文件上即被拒绝，绝不触碰当前生效文件。
    /// R04：候选与重载均强制真实验签（未签名/伪签名/篡改拒绝）。
    /// P1 生效链：落盘成功后调用 ApplyPolicyToExecutors 刷新执行器；
    /// 部分执行器失败不影响落盘结果，错误清单随 PolicyApplyOutcome 如实上报。
    /// </summary>
    private Result<PolicyApplyOutcome> ApplyPolicy(string policyPath, string policyJson)
    {
        var loader = new PolicyLoader(_loggerFactory.CreateLogger<PolicyLoader>());
        var candidatePath = policyPath + ".candidate";
        try
        {
            File.WriteAllText(candidatePath, policyJson);
            var validated = LoadPolicyTrusted(loader, candidatePath);
            if (!validated.IsSuccess)
            {
                TryDeleteFile(candidatePath);
                return Result<PolicyApplyOutcome>.Failure(validated.ErrorCode, validated.ErrorMessage);
            }

            if (File.Exists(policyPath))
            {
                File.Copy(policyPath, policyPath + ".bak", overwrite: true);
            }

            File.Move(candidatePath, policyPath, overwrite: true);

            var reloaded = LoadPolicyTrusted(loader, policyPath);
            if (!reloaded.IsSuccess)
            {
                return Result<PolicyApplyOutcome>.Failure(reloaded.ErrorCode, reloaded.ErrorMessage);
            }

            _policy = reloaded.Data!;
            var applyErrors = ApplyPolicyToExecutors(_policy);
            return Result<PolicyApplyOutcome>.Success(new PolicyApplyOutcome(_policy, applyErrors));
        }
        catch (Exception ex)
        {
            TryDeleteFile(candidatePath);
            return Result<PolicyApplyOutcome>.Failure(ErrorCode.Unknown, ex.Message);
        }
    }

    /// <summary>
    /// R04：可信策略加载——强制真实验签，公钥来自 PolicyTrustAnchor
    /// （配置 Policy:PublicKeyXml / 环境变量 / 开发环境回落内置 dev 公钥）。
    /// P0 生产收紧：生产环境缺正式公钥 → InvalidConfiguration（fail-closed）。
    /// N01：生产环境显式配置 dev 公钥本身同样被拒绝（见 PolicyTrustAnchor）。
    /// </summary>
    private Result<PolicyFile> LoadPolicyTrusted(PolicyLoader loader, string path)
    {
        using var publicKey = CreatePolicyPublicKey();
        if (publicKey is null)
        {
            return Result<PolicyFile>.Failure(
                ErrorCode.InvalidConfiguration,
                "production environment requires an official policy public key " +
                "(Policy:PublicKeyXml or WINKNOW_POLICY_PUBLIC_KEY_XML); dev fallback disabled");
        }
        return loader.Load(path, validateSignature: true, publicKey);
    }

    /// <summary>
    /// 构建策略验签公钥；生产环境缺正式公钥时返回 null（调用方 fail-closed），
    /// 不向调用方抛异常（ApplyPolicy/RestorePolicy 走 Result 失败路径）。
    /// </summary>
    private RSA? CreatePolicyPublicKey()
    {
        try
        {
            return PolicyTrustAnchor.CreatePublicKey(
                _configuration["Policy:PublicKeyXml"],
                allowDevKeyFallback: PolicyAllowsDevKey());
        }
        catch (InvalidOperationException ex)
        {
            _logger?.LogCritical(ex, "Policy trust anchor rejected: {Message}", ex.Message);
            return null;
        }
    }

    /// <summary>
    /// N01（2026-10-08 第二轮复核）：dev 公钥回落的权威判定。
    ///
    /// 旧实现用 Policy:Environment / Environment / DOTNET_ENVIRONMENT 三源
    /// 自判且"缺省当开发"——而宿主（Host.CreateApplicationBuilder）缺省环境
    /// 是 Production：装了就跑的服务在零配置下以开发公钥验签生产策略。
    /// 现在以宿主注入的 IHostEnvironment 为唯一事实来源：仅显式
    /// Development 允许回落；未注入（null，保守起见）或任何其他环境
    /// （Production/Staging/自定义）一律要求正式公钥。开发机便利由
    /// launchSettings 显式 DOTNET_ENVIRONMENT=Development 提供，不再依赖
    /// "缺省即开发"。
    /// </summary>
    internal static bool AllowsDevKey(IHostEnvironment? hostEnvironment)
    {
        return string.Equals(
            hostEnvironment?.EnvironmentName,
            "Development",
            StringComparison.OrdinalIgnoreCase);
    }

    private bool PolicyAllowsDevKey() => AllowsDevKey(_hostEnvironment);

    /// <summary>
    /// 从备份恢复策略并重载，随后同步应用到运行中的执行器（policy.restore 后端）。
    /// </summary>
    private Result<PolicyApplyOutcome> RestorePolicy(string policyPath)
    {
        var backupPath = policyPath + ".bak";
        if (!File.Exists(backupPath))
        {
            return Result<PolicyApplyOutcome>.Failure(ErrorCode.PathNotFound, "no policy backup available.");
        }

        try
        {
            var loader = new PolicyLoader(_loggerFactory.CreateLogger<PolicyLoader>());
            var restored = LoadPolicyTrusted(loader, backupPath);
            if (!restored.IsSuccess)
            {
                return Result<PolicyApplyOutcome>.Failure(restored.ErrorCode, restored.ErrorMessage);
            }

            File.Copy(backupPath, policyPath, overwrite: true);
            var reloaded = LoadPolicyTrusted(loader, policyPath);
            if (!reloaded.IsSuccess)
            {
                return Result<PolicyApplyOutcome>.Failure(reloaded.ErrorCode, reloaded.ErrorMessage);
            }

            _policy = reloaded.Data!;
            var applyErrors = ApplyPolicyToExecutors(_policy);
            return Result<PolicyApplyOutcome>.Success(new PolicyApplyOutcome(_policy, applyErrors));
        }
        catch (Exception ex)
        {
            return Result<PolicyApplyOutcome>.Failure(ErrorCode.Unknown, ex.Message);
        }
    }

    /// <summary>
    /// P1（2026-10-08）策略生效链：将已验证的策略同步应用到运行中的执行器。
    /// 问题复现：此前 ApplyPolicy/RestorePolicy 仅"写文件 + 重载内存快照"，
    /// 进程白名单/网站过滤/代理/DNS/浏览器策略/USB 等执行器全部维持旧值
    /// 直到服务重启——策略更新形同虚设，且响应恒报 applied=true。
    /// 本方法可重入：执行器尚未创建（启动期无策略文件）时按需创建；
    /// 已创建的更新策略引用并立即强制校验一次。各执行器独立容错——
    /// 部分失败不影响其余执行器，错误清单如实上报（applied=false + apply_errors）。
    /// </summary>
    /// <returns>执行器应用错误清单（空 = 全部应用成功）。</returns>
    private IReadOnlyList<string> ApplyPolicyToExecutors(PolicyFile policy)
    {
        var errors = new List<string>();

        // 1. 进程管控：白名单 + 高风险解释器黑名单
        try
        {
            if (_judge is null)
            {
                _judge = new ProcessJudge(
                    WhitelistRuleSet.FromPolicy(policy),
                    _loggerFactory.CreateLogger<ProcessJudge>(),
                    policy.SoftwareControl.HighRiskInterpreters.Blocked);
            }
            else
            {
                _judge.UpdateRules(
                    WhitelistRuleSet.FromPolicy(policy),
                    policy.SoftwareControl.HighRiskInterpreters.Blocked);
            }
        }
        catch (Exception ex)
        {
            errors.Add($"process_judge: {ex.Message}");
        }

        // 2. 网站白名单过滤
        try
        {
            _websiteFilter ??= new WebsiteFilter(_loggerFactory.CreateLogger<WebsiteFilter>());
            _websiteFilter.LoadFromPolicy(policy.NetworkControl.WebsiteWhitelist);
        }
        catch (Exception ex)
        {
            errors.Add($"website_filter: {ex.Message}");
        }

        // 3. hosts 文件保护（无策略参数，仅保证已启动；幂等）
        try
        {
            if (_hostsProtector is null)
            {
                _hostsProtector = new HostsProtector(_loggerFactory.CreateLogger<HostsProtector>());
                _hostsProtector.Initialize();
                _hostsProtector.StartMonitoring();
            }
        }
        catch (Exception ex)
        {
            errors.Add($"hosts_protector: {ex.Message}");
        }

        // 4. 代理守卫：更新策略并立即恢复一次（新禁用策略即时生效）
        // N05（2026-10-08 第二轮复核）：CheckAndRestore 返回 Result——
        // 恢复失败（注册表被占/权限等）必须进 apply_errors，不得只吞异常。
        try
        {
            if (_proxyGuard is null)
            {
                _proxyGuard = new ProxyGuard(
                    policy.NetworkControl.Proxy,
                    _loggerFactory.CreateLogger<ProxyGuard>());
                _proxyGuard.StartMonitoring();
            }
            else
            {
                _proxyGuard.UpdatePolicy(policy.NetworkControl.Proxy);
            }

            var proxyCheck = _proxyGuard.CheckAndRestore();
            if (!proxyCheck.IsSuccess)
            {
                errors.Add($"proxy_guard: {proxyCheck.ErrorMessage}");
            }
        }
        catch (Exception ex)
        {
            errors.Add($"proxy_guard: {ex.Message}");
        }

        // 5. DNS 监控：更新策略并立即检查一次
        // N05：Check 返回 Result——检测到违规 DNS（InvalidConfiguration）
        // 或检查异常（Unknown）都进 apply_errors。
        try
        {
            if (_dnsMonitor is null)
            {
                _dnsMonitor = new DnsMonitor(
                    policy.NetworkControl.Dns,
                    _loggerFactory.CreateLogger<DnsMonitor>());
            }
            else
            {
                _dnsMonitor.UpdatePolicy(policy.NetworkControl.Dns);
            }

            var dnsCheck = _dnsMonitor.Check();
            if (!dnsCheck.IsSuccess)
            {
                errors.Add($"dns_monitor: {dnsCheck.ErrorMessage}");
            }
        }
        catch (Exception ex)
        {
            errors.Add($"dns_monitor: {ex.Message}");
        }

        // 6. 浏览器企业策略
        try
        {
            _browserPolicyEnforcer ??= new BrowserPolicyEnforcer(
                _loggerFactory.CreateLogger<BrowserPolicyEnforcer>());
            var browserResult = _browserPolicyEnforcer.ApplyAll(policy.NetworkControl.BrowserPolicy);
            if (!browserResult.IsSuccess)
            {
                errors.Add($"browser_policy: {browserResult.ErrorMessage}");
            }
        }
        catch (Exception ex)
        {
            errors.Add($"browser_policy: {ex.Message}");
        }

        // 7. VPN/TUN 检测：更新策略并检测一次
        try
        {
            if (_vpnDetector is null)
            {
                _vpnDetector = new VpnTunDetector(
                    policy.NetworkControl.VpnDetection,
                    _loggerFactory.CreateLogger<VpnTunDetector>());
            }
            else
            {
                _vpnDetector.UpdatePolicy(policy.NetworkControl.VpnDetection);
            }

            var vpnResult = _vpnDetector.Detect();
            if (vpnResult.Detected)
            {
                _logger?.LogWarning("VPN detected after policy apply: {Count} items", vpnResult.Items.Count);
            }
        }
        catch (Exception ex)
        {
            errors.Add($"vpn_detector: {ex.Message}");
        }

        // 8. 网站健康检测：Timer 周期与 HttpClient 超时随策略构造，无法原位更新 → 重建
        try
        {
            _websiteHealthChecker?.Dispose();
            _websiteHealthChecker = null;
            if (policy.NetworkControl.WebsiteHealth.Endpoints.Count > 0)
            {
                _websiteHealthChecker = new WebsiteHealthChecker(
                    policy.NetworkControl.WebsiteHealth,
                    _loggerFactory.CreateLogger<WebsiteHealthChecker>());
                _websiteHealthChecker.UnhealthyDetected += items =>
                    _logger?.LogWarning("Website unhealthy: {Endpoints}",
                        string.Join(", ", items.Select(i => i.Name)));
                _websiteHealthChecker.StartMonitoring();
            }
        }
        catch (Exception ex)
        {
            errors.Add($"website_health: {ex.Message}");
        }

        // 9. USB 存储管控
        // N05：Enable/Disable 返回 bool——注册表写失败（权限/键被锁）时
        // 策略未生效，必须进 apply_errors（此前失败返回 false 被丢弃，
        // 空错误清单 + applied=true 掩盖了未生效事实）。
        try
        {
            _usbController ??= new UsbStorageController(_loggerFactory.CreateLogger<UsbStorageController>());
            if (policy.UsbControl.MassStorage.Enabled)
            {
                if (!_usbController.Enable())
                {
                    errors.Add("usb_controller: Enable() failed (registry write rejected)");
                }
            }
            else
            {
                if (!_usbController.Disable())
                {
                    errors.Add("usb_controller: Disable() failed (registry write rejected)");
                }
                else
                {
                    _logger?.LogWarning("USB Mass Storage disabled by policy");
                }
            }
        }
        catch (Exception ex)
        {
            errors.Add($"usb_controller: {ex.Message}");
        }

        if (errors.Count == 0)
        {
            _logger?.LogInformation("Policy {PolicyId} v{Version} applied to all executors",
                policy.PolicyId, policy.Version);
        }
        else
        {
            _logger?.LogError(
                "Policy {PolicyId} v{Version} applied with {Errors} executor error(s): {Detail}",
                policy.PolicyId, policy.Version, errors.Count, string.Join("; ", errors));
        }

        return errors;
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
            // 尽力清理，失败不影响主流程
        }
    }
}
