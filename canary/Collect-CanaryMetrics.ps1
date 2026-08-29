# Collect-CanaryMetrics.ps1 —— 灰度机每日指标采集（12 项观察指标自动化部分）
# 在灰度机上以管理员运行（事件日志查询需要）；生成《灰度日报》草稿，人工项留空待填。
# 指标来源（与代码实现对应）：
#   - 拦截事件   ：Application 日志，源 Winknow，事件 9001（WriteSecurityAnchor "ProcessBlocked"）
#   - 维护次数   ：Application 日志，源 Winknow，事件 9002（WriteMaintenanceAnchor）
#   - 更新事件   ：Application 日志，源 Winknow，事件 9003（WriteUpdateAnchor）
#   - WMI 重连   ：Application 日志，源 Winknow，消息含 "WMI watcher"（第 13 周弹性重连日志）
#   - 服务重启   ：System 日志，SCM 7031（崩溃）按服务名过滤；7036 仅作启停参考
#   - 资源       ：服务进程 CPU/工作集；ProgramData\Winknow 目录大小（日志/数据增长）
# 用法：
#   .\Collect-CanaryMetrics.ps1 -Stage 1 -Day 1
#   .\Collect-CanaryMetrics.ps1 -Stage 3 -Day 2 -SinceHours 48
param(
    [int]$Stage = 1,
    [int]$Day = 1,
    [string]$MachineId = "",
    [double]$SinceHours = 24,
    [string]$OutDir = ""
)

$ErrorActionPreference = 'Continue'
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path $MyInvocation.MyCommand.Path -Parent }
if (-not $MachineId) { $MachineId = $env:COMPUTERNAME }
if (-not $OutDir) { $OutDir = Join-Path $scriptRoot 'reports' }
if (-not [IO.Path]::IsPathRooted($OutDir)) { $OutDir = Join-Path $scriptRoot $OutDir }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$since = (Get-Date).AddHours(-1 * $SinceHours)
$dataRoot = Join-Path $env:ProgramData 'Winknow'
$services = @('WinknowControl', 'WinknowGuard')
$procs = @('Winknow.ControlService', 'Winknow.GuardService')

function Get-Events([hashtable]$filter) {
    try { return @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop) } catch { return @() }
}
function DirSizeMB([string]$p) {
    if (-not (Test-Path $p)) { return 0 }
    try {
        $sum = (Get-ChildItem $p -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
        return [math]::Round($sum / 1MB, 2)
    } catch { return 0 }
}

# ---- 1. 服务状态与非计划重启 ----
$svcLines = @()
foreach ($s in $services) {
    $svc = Get-Service $s -ErrorAction SilentlyContinue
    if ($null -eq $svc) { $svcLines += "- $s ：**未安装**" ; continue }
    $svcLines += "- $s ：$($svc.Status)"
}
$crashEvts = Get-Events @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7031; StartTime = $since } |
    Where-Object { $_.Message -match 'Winknow' }
$transEvts = Get-Events @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7036; StartTime = $since } |
    Where-Object { $_.Message -match 'Winknow' }

# ---- 2. Winknow 事件锚点 ----
$blocked = Get-Events @{ LogName = 'Application'; ProviderName = 'Winknow'; Id = 9001; StartTime = $since }
$maint = Get-Events @{ LogName = 'Application'; ProviderName = 'Winknow'; Id = 9002; StartTime = $since }
$updates = Get-Events @{ LogName = 'Application'; ProviderName = 'Winknow'; Id = 9003; StartTime = $since }
$wmiAll = Get-Events @{ LogName = 'Application'; ProviderName = 'Winknow'; StartTime = $since } |
    Where-Object { $_.Message -match 'WMI watcher' }

# ---- 3. 资源 ----
$resLines = @()
foreach ($pn in $procs) {
    $p = Get-Process $pn -ErrorAction SilentlyContinue
    if ($null -eq $p) { $resLines += "- $pn ：未运行"; continue }
    $resLines += ("- {0} ：CPU {1:N1}s，内存 {2:N0} MB" -f $pn, $p.TotalProcessorTime.TotalSeconds, ($p.WorkingSet64 / 1MB))
}
$rootMB = DirSizeMB $dataRoot
$audit = Join-Path $dataRoot 'audit.db'

# ---- 4. TrustedUpdater 状态（可选） ----
$verLine = ""
$updater = Join-Path $dataRoot 'deploy\Current\Winknow.TrustedUpdater.exe'
if (Test-Path $updater) {
    try { $verLine = (& $updater status 2>$null | Where-Object { $_ -match '版本|Previous' }) -join '；' } catch { $verLine = "status 调用失败" }
}

# ---- 生成日报草稿 ----
$date = Get-Date -Format 'yyyy-MM-dd'
$sb = New-Object System.Text.StringBuilder
function Add-Line([string]$t = '') { [void]$sb.AppendLine($t) }

Add-Line "【灰度日报】第 $Stage 阶段 第 $Day 天（草稿：自动采集部分）"
Add-Line "日期：$date  机器编号：$MachineId  品牌/型号：____  操作人：____"
Add-Line
Add-Line "1. 服务状态（采集窗口 $SinceHours 小时）"
$svcLines | ForEach-Object { Add-Line "   $_" }
Add-Line ("   - 非计划崩溃（SCM 7031）：{0} 次；启停转换（7036）：{1} 次" -f @($crashEvts).Count, @($transEvts).Count)
Add-Line "2. 拦截情况"
Add-Line ("   - 拦截事件（9001 ProcessBlocked）：{0} 次" -f @($blocked).Count)
$blocked | Select-Object -First 8 | ForEach-Object { Add-Line "     - $($_.TimeCreated.ToString('HH:mm:ss')) $($_.Message)" }
Add-Line "   - 其中复核误拦：__（人工填写）"
Add-Line "   - 未授权软件平均关闭时间：__ s（人工按日志时间差抽样填写）"
Add-Line "3. WMI 状态"
Add-Line ("   - 重连/异常事件（消息含 WMI watcher）：{0} 次" -f @($wmiAll).Count)
$wmiAll | Select-Object -First 5 | ForEach-Object { Add-Line "     - $($_.TimeCreated.ToString('HH:mm:ss')) $($_.LevelDisplayName)：$($_.Message)" }
Add-Line "   - 是否自愈：__（人工确认 watcher 重建后事件恢复）"
Add-Line "4. 学生使用"
Add-Line "   - 编译/调试成功率：__%   洛谷提交成功率：__%（人工记录）"
Add-Line "5. 更新/回滚演练"
if (@($updates).Count -gt 0) { $updates | ForEach-Object { Add-Line "   - $($_.TimeCreated.ToString('HH:mm:ss')) $($_.Message)" } }
else { Add-Line "   - 窗口内无更新事件（9003）" }
if ($verLine) { Add-Line "   - TrustedUpdater：$verLine" }
Add-Line "6. USB/启动安全（人工实测）"
Add-Line "   - U 盘：□阻止 □放行   键鼠：□正常 □异常   DeviceSecurity 评分：__"
Add-Line "7. 资源"
$resLines | ForEach-Object { Add-Line "   $_" }
Add-Line ("   - {0} 目录：{1} MB（audit.db：{2}）" -f $dataRoot, $rootMB, $(if (Test-Path $audit) { "{0:N1} MB" -f ((Get-Item $audit).Length / 1MB) } else { "不存在" }))
Add-Line "8. 维护操作"
Add-Line ("   - 维护事件（9002）：{0} 次" -f @($maint).Count)
$maint | Select-Object -First 5 | ForEach-Object { Add-Line "     - $($_.TimeCreated.ToString('HH:mm:ss')) $($_.Message)" }
Add-Line "9. 缺陷记录：__（P0/P1/P2）"
Add-Line "10. 备注/异常：____"
Add-Line
Add-Line "> 生成：Collect-CanaryMetrics.ps1 @$date；('__' 与勾选项为人工复核字段)"

$out = Join-Path $OutDir ("日报_S{0}D{1}_{2}_{3}.md" -f $Stage, $Day, $MachineId, ($date -replace '-', ''))
[IO.File]::WriteAllText($out, $sb.ToString(), [Text.UTF8Encoding]::new($true))
Write-Host "==> 日报草稿：$out"
Write-Host ("汇总：9001 拦截 {0}，9002 维护 {1}，9003 更新 {2}，WMI 异常 {3}，7031 崩溃 {4}" -f @($blocked).Count, @($maint).Count, @($updates).Count, @($wmiAll).Count, @($crashEvts).Count)
