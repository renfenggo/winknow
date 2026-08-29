using System.ServiceProcess;
using Microsoft.Extensions.Logging;
using Winknow.Core;
using Winknow.Core.Guarding;
using Winknow.Ipc;
using Winknow.Logging;
using Winknow.Security;
using Winknow.TrustedUpdater;

namespace Winknow.GuardService;

/// <summary>
/// GuardService 守护进程工作器（V7.0 第 10 周守护增强版）。
/// 运行身份：LocalSystem | 服务名：Winknow Guard Service
///
/// 职责链（每 <see cref="Constants.Guard.HeartbeatIntervalSeconds"/> 秒一轮）：
/// 1. 更新模式检查：UpdateModeFlag 有效时暂停干预（防更新交叉拉起）；
/// 2. 心跳租约：替代纯服务状态检测，识别"Running 但挂起"的僵死实例；
/// 3. 对端验证：拉起前校验路径/签名/版本/Hash（防拉起被篡改二进制）；
/// 4. 指数退避 + 重启限流：连续崩溃时间隔 2^n 递增、10 分钟窗口最多 5 次；
/// 5. Safe Degraded：超阈值进降级，尝试 Recovery Vault / Previous 修复；
///    修复失败保持降级与最低管控——恢复失败绝不放行（Fail-Closed）。
/// 不承担交互式键盘钩子。
/// </summary>
internal sealed class Worker : BackgroundService
{
    private const string ControlServiceName = "Winknow Control Service";
    private const string ControlServiceExe = "Winknow.ControlService.exe";

    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(Constants.Guard.HeartbeatIntervalSeconds);
    private static readonly TimeSpan RepairRetryInterval = TimeSpan.FromSeconds(60);

    private readonly ILogger<Worker> _logger;
    private readonly string _dataDir;
    private readonly string _deployRoot;

    private HeartbeatLease _lease = null!;
    private PeerVerifier _verifier = null!;
    private RestartThrottle _throttle = null!;
    private ExponentialBackoff _backoff = null!;
    private SafeDegradedMode _degraded = null!;
    private AutoRepairService _repair = null!;
    private DeploymentSlots _slots = null!;
    private RecoveryVault _vault = null!;
    private EventLogAnchor _anchor = null!;

    private DateTimeOffset _nextAttemptAt = DateTimeOffset.MinValue;
    private DateTimeOffset _lastRepairAt = DateTimeOffset.MinValue;
    private bool _updateModeLogged;

    internal Worker(ILogger<Worker> logger)
    {
        _logger = logger;
        _dataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Winknow");
        _deployRoot = Path.Combine(_dataDir, "deploy");
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("GuardService started - monitoring {Service} via heartbeat lease", ControlServiceName);
        InitializeComponents();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await MonitorOnceAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GuardService monitoring error");
            }

            try
            {
                await Task.Delay(CheckInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger.LogInformation("GuardService stopped");
    }

    private void InitializeComponents()
    {
        _lease = new HeartbeatLease(_dataDir);
        _slots = new DeploymentSlots(_deployRoot);
        _vault = new RecoveryVault(_deployRoot);
        _repair = new AutoRepairService(_slots, _vault);
        _verifier = new PeerVerifier();
        _throttle = new RestartThrottle();
        _backoff = new ExponentialBackoff();
        _degraded = new SafeDegradedMode();
        _anchor = new EventLogAnchor("Winknow");
        _ = _anchor.Initialize();
    }

    private async Task MonitorOnceAsync(CancellationToken token)
    {
        // ── 1. 更新模式：暂停干预，避免与 Stop→切换→Start 交叉拉起 ──
        if (UpdateModeFlag.IsUpdateInProgress(_dataDir))
        {
            if (!_updateModeLogged)
            {
                _logger.LogInformation("更新进行中，守护暂停拉起干预");
                _updateModeLogged = true;
            }
            return;
        }
        _updateModeLogged = false;

        var status = _lease.Check();

        // ── 2. 租约存活：服务正常，退避归零，尝试退出降级 ──
        if (status.IsAlive)
        {
            _backoff.Reset();
            _nextAttemptAt = DateTimeOffset.MinValue;

            if (_degraded.IsDegraded && _throttle.WindowElapsed() && _degraded.TryExitDegraded())
            {
                _logger.LogInformation("ControlService 已恢复存活且限流窗口冷却完毕，退出 Safe Degraded Mode");
                _throttle.Clear();
                _ = _anchor.WriteSecurityAnchor("ExitDegraded", "ControlService 恢复存活，守护退出降级模式");
            }
            return;
        }

        var age = status.AgeSeconds >= 0 ? $"（租约 {status.AgeSeconds:F0}s 前）" : "（无租约文件）";
        _logger.LogWarning("ControlService 心跳租约失效{Age}", age);

        // ── 3. 已处降级：周期性尝试修复，修复成功且冷却期满后恢复；失败保持最低管控 ──
        if (_degraded.IsDegraded)
        {
            if (DateTimeOffset.UtcNow - _lastRepairAt >= RepairRetryInterval)
            {
                _lastRepairAt = DateTimeOffset.UtcNow;
                var repair = _repair.CheckAndRepair();
                if (repair.Success)
                {
                    _logger.LogInformation("降级期间修复成功（{Strategy}），等待租约恢复", repair.Strategy);
                    _ = _anchor.WriteUpdateAnchor("AutoRepairInDegraded", repair.Strategy.ToString());
                }
                else
                {
                    _logger.LogCritical("降级期间修复失败，维持最低管控（不放行）: {Detail}", repair.Detail);
                    _ = _anchor.WriteSecurityAnchor("RepairFailedKeepDegraded", "修复失败，保持 Safe Degraded（Fail-Closed）");
                }
            }
            return; // 降级期间不拉起：最低管控由守护自身与既有策略承担
        }

        // ── 4. 重启限流：窗口超阈值 → 进入 Safe Degraded 并立即尝试修复 ──
        if (!_throttle.CanRestart())
        {
            _degraded.EnterDegraded(ControlServiceName,
                $"{_throttle.CurrentWindowCount} 次重启 / {Constants.Guard.ThrottleWindowMinutes} 分钟超阈值");
            _logger.LogCritical("重启超阈值，进入 Safe Degraded Mode（保持最低管控）");
            _ = _anchor.WriteSecurityAnchor("EnterDegraded", $"重启超阈值（{_throttle.CurrentWindowCount} 次），进入安全降级");
            _lastRepairAt = DateTimeOffset.UtcNow;
            var first = _repair.CheckAndRepair();
            if (first.Success)
            {
                _logger.LogInformation("进入降级后首次修复成功（{Strategy}），等待服务自愈", first.Strategy);
            }
            return;
        }

        // ── 5. 指数退避：未到下次尝试时间则本轮跳过 ──
        if (DateTimeOffset.UtcNow < _nextAttemptAt)
        {
            return;
        }

        // ── 6. 对端验证：路径/签名/版本/Hash 任一失败 → 修复而非拉起 ──
        var exePath = Path.Combine(_slots.CurrentDir, ControlServiceExe);
        var manifest = _vault.GetManifest();
        var exeEntry = manifest?.Files.FirstOrDefault(f =>
            f.Path.Equals(ControlServiceExe, StringComparison.OrdinalIgnoreCase));

        var verify = _verifier.Verify(exePath, new PeerVerifier.PeerExpectation
        {
            AllowedDir = _slots.CurrentDir,
            RequireSignature = true,
            MinimumVersion = null,
            ExpectedSha256 = exeEntry?.Sha256
        });

        if (!verify.IsTrusted)
        {
            _logger.LogCritical("对端验证失败，拒绝拉起: {Detail}", verify.FailureDetail);
            _ = _anchor.WriteSecurityAnchor("PeerVerifyFailed", verify.FailureDetail ?? "未知原因");

            _degraded.EnterDegraded(ControlServiceName, $"对端验证失败: {verify.FailureDetail}");
            _lastRepairAt = DateTimeOffset.UtcNow;
            var fix = _repair.CheckAndRepair();
            _logger.LogInformation("验证失败后修复结果: {Success}（{Strategy}）", fix.Success, fix.Strategy);
            return;
        }

        // ── 7. 执行拉起：成功记入限流窗口，失败进入下一轮退避 ──
        _nextAttemptAt = DateTimeOffset.UtcNow + _backoff.NextDelay();
        _backoff.OnFailure(); // 先按失败计：观察到租约存活时才 Reset（启动即崩持续升级退避）

        if (TryRestartService())
        {
            _throttle.RecordRestart();
            _logger.LogWarning("ControlService 已拉起（窗口内第 {Count}/{Max} 次）",
                _throttle.CurrentWindowCount, Constants.Guard.MaxRestartsPerWindow);
        }
        else
        {
            _logger.LogError("拉起 ControlService 失败，{Delay:F0}s 后重试", _backoff.NextDelay().TotalSeconds);
        }

        await Task.CompletedTask;
    }

    /// <summary>
    /// 尝试启动 ControlService。
    /// </summary>
    private bool TryRestartService()
    {
        try
        {
            using var sc = new ServiceController(ControlServiceName);
            var timeout = TimeSpan.FromSeconds(30);

            if (sc.Status == ServiceControllerStatus.Stopped)
            {
                sc.Start();
                sc.WaitForStatus(ServiceControllerStatus.Running, timeout);
                return sc.Status == ServiceControllerStatus.Running;
            }
            if (sc.Status == ServiceControllerStatus.Paused)
            {
                sc.Continue();
                sc.WaitForStatus(ServiceControllerStatus.Running, timeout);
                return sc.Status == ServiceControllerStatus.Running;
            }
            if (sc.Status == ServiceControllerStatus.Running)
            {
                // 服务 Running 但租约失效 = 僵死实例：停止后重启
                sc.Stop();
                sc.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
                sc.Refresh();
                sc.Start();
                sc.WaitForStatus(ServiceControllerStatus.Running, timeout);
                return sc.Status == ServiceControllerStatus.Running;
            }
            return sc.Status == ServiceControllerStatus.Running;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Restart attempt failed for {Service}", ControlServiceName);
            return false;
        }
    }
}
