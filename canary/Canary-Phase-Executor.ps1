# Canary-Phase-Executor.ps1 - 灰度三阶段测试执行助手
# 用途：指导测试人员按照三阶段计划执行测试，自动生成日报草稿
# 用法：
#   .\Canary-Phase-Executor.ps1 -Stage 1 -Day 1 -Machine "T-01"
#   .\Canary-Phase-Executor.ps1 -Stage 2 -Day 3 -Machine "S-01"

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet(0,1,2,3)]
    [int]$Stage,
    
    [Parameter(Mandatory=$true)]
    [int]$Day,
    
    [Parameter(Mandatory=$true)]
    [string]$Machine,
    
    [string]$OutDir = "",
    [string]$TestOperator = ""
)

$ErrorActionPreference = 'Continue'
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path $MyInvocation.MyCommand.Path -Parent }
if (-not $OutDir) { $OutDir = Join-Path $scriptRoot 'reports' }
if (-not [IO.Path]::IsPathRooted($OutDir)) { $OutDir = Join-Path $scriptRoot $OutDir }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

function Write-Step([string]$msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

Write-Step "灰度阶段 $Stage 第 $Day 天测试 - 机器 $Machine"
Write-Host ""

# ── 阶段特定任务提示 ───────────────────────────────────────
switch ($Stage) {
    0 {
        Write-Host "【Stage 0：灰度前检查】" -ForegroundColor Yellow
        Write-Host "1. 确认安装包已编译并签名"
        Write-Host "2. 运行产物核验：$scriptRoot\Verify-Release.ps1"
        Write-Host "3. 干净机安装演练：Verify-Release.ps1 -Installed"
        Write-Host "4. 基础功能演练：拦截/U盘/DeviceSecurity检测"
        Write-Host "5. 全量回归测试：dotnet test -c Release"
    }
    1 {
        Write-Host "【阶段一：小规模测试（2台）】" -ForegroundColor Yellow
        Write-Host "D1 任务：" 
        Write-Host "  1. 按 Stage 0.4 安装 + 装机核验"
        Write-Host "  2. TrustedUpdater status 确认版本"
        Write-Host "  3. AdminUI 首次检测导出报告"
        Write-Host "  4. 策略拦截测试 + 授权验证演练（第八节）"
        Write-Host "  5. 故障注入：WMI停止/进程强杀/冷启动"
        
        Write-Host "`nD2 任务："
        Write-Host "  6. 更新演练（7.0.1测试包）"
        Write-Host "  7. 断电演练：上电自愈验证"
        Write-Host "  8. 整包回退演练（任一台）"
        Write-Host "  9. 生成《灰度阶段报告（一）》"
    }
    2 {
        Write-Host "【阶段二：中规模测试（5台）】" -ForegroundColor Yellow
        Write-Host "D3 任务："
        Write-Host "  1. 学生机安装 + 装机核验"
        Write-Host "  2. 真实上课环境测试"
        Write-Host "  3. 远程观察软件兼容性"
        
        Write-Host "`nD4 任务："
        Write-Host "  4. 编程软件误拦统计"
        Write-Host "  5. 学生反馈收集"
        Write-Host "  6. 生成《灰度阶段报告（二）》"
    }
    3 {
        Write-Host "【阶段三：全规模测试（10-20台）】" -ForegroundColor Yellow
        Write-Host "D5-D7+ 任务："
        Write-Host "  1. 全量灰度机安装"
        Write-Host "  2. 跨周末冷启动测试"
        Write-Host "  3. 课堂断电演练"
        Write-Host "  4. Windows更新兼容性测试"
        Write-Host "  5. 每日指标监控（12项发布门槛）"
        Write-Host "  6. 生成《灰度阶段报告（三）》+《发布决策检查单》"
    }
}

# ── 自动化指标采集 ──────────────────────────────────────────
Write-Host "`n==> 自动化指标采集开始" -ForegroundColor Green

$metricsScript = Join-Path $scriptRoot 'Collect-CanaryMetrics.ps1'
if (Test-Path $metricsScript) {
    try {
        & $metricsScript -Stage $Stage -Day $Day -MachineId $Machine -OutDir $OutDir
        Write-Host "==> 日报草稿已生成" -ForegroundColor Green
    } catch {
        Write-Host "指标采集失败：$_" -ForegroundColor Red
    }
} else {
    Write-Host "指标采集脚本不存在：$metricsScript" -ForegroundColor Yellow
}

# ── 阶段特定检查清单 ───────────────────────────────────────
Write-Host "`n==> 当前阶段检查清单" -ForegroundColor Yellow

switch ($Stage) {
    1 {
        Write-Host "阶段一出口条件核验："
        Write-Host "  ☐ 无P0缺陷"
        Write-Host "  ☐ 双服务48h无崩溃重启"
        Write-Host "  ☐ Rollback演练成功"
        Write-Host "  ☐ 断电/强杀自愈成功"
        Write-Host "  ☐ 授权验证功能正常（第八节演练通过）"
        Write-Host "  ☐ 授权指标监控正常（心跳≥98%，锁定≈0）"
    }
    2 {
        Write-Host "阶段二出口条件核验："
        Write-Host "  ☐ 无P0、P1有结论"
        Write-Host "  ☐ 关键编程软件零阻断性误拦"
        Write-Host "  ☐ 键鼠零影响"
        Write-Host "  ☐ 可解释投诉≤1起/天"
        Write-Host "  ☐ 授权指标稳定达标"
    }
    3 {
        Write-Host "阶段三出口条件核验："
        Write-Host "  ☐ 12项发布门槛全部通过"
        Write-Host "  ☐ 15项检查项全部通过（含授权3项）"
        Write-Host "  ☐ 7天连续运行数据达标"
        Write-Host "  ☐ 用户体验反馈可接受"
        Write-Host "  ☐ 风险评估在可接受范围"
    }
}

# ── 授权系统专项检查（阶段1-3） ──────────────────────────────
if ($Stage -ge 1) {
    Write-Host "`n==> 授权系统专项检查（阶段C新增）" -ForegroundColor Yellow
    Write-Host "第八节授权验证演练项目："
    Write-Host "  ☐ 拔网线锁定测试（超过5分钟宽限）"
    Write-Host "  ☐ 电话报码解锁验证（TOTP动态码）"
    Write-Host "  ☐ 固定码解锁验证（维护密码）"
    Write-Host "  ☐ 插线自动解锁验证"
    Write-Host "  ☐ TOTP时效性验证（过期码拒绝）"
    Write-Host "  ☐ 授权心跳监控（Collect-CanaryMetrics第九节）"
}

# ── 报告生成指引 ───────────────────────────────────────────
Write-Host "`n==> 阶段报告生成指引" -ForegroundColor Yellow

$reportTemplates = @{
    1 = "灰度阶段报告_一_模板.md"
    2 = "灰度阶段报告_二_模板.md"
    3 = "灰度阶段报告_三_模板.md"
}

$templatePath = Join-Path $OutDir $reportTemplates[$Stage]
if (Test-Path $templatePath) {
    Write-Host "阶段报告模板：$templatePath"
    Write-Host "建议在阶段最后一天使用该模板生成最终报告"
} else {
    Write-Host "阶段报告模板不存在，请检查：$templatePath" -ForegroundColor Red
}

# ── 熔断检查 ───────────────────────────────────────────────
Write-Host "`n==> 熔断条件检查" -ForegroundColor Yellow
Write-Host "如遇以下情况，立即停止放量并回退："
Write-Host "  🔴 P0缺陷：锁死/蓝屏/断网/重启风暴"
Write-Host "  🔴 授权系统故障：全机断网锁定/无法解锁"
Write-Host "  🔴 性能严重退化：CPU占用持续>80%/内存泄漏"
Write-Host "  🟡 重大兼容问题：关键软件无法使用"

# ── 操作记录 ───────────────────────────────────────────────
Write-Host "`n==> 操作记录" -ForegroundColor Green
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$record = "$timestamp | Stage $Stage Day $Day | Machine: $Machine | Operator: $TestOperator"

$logFile = Join-Path $OutDir "灰度执行记录.log"
Add-Content -Path $logFile -Value $record
Write-Host "记录已保存：$logFile"

Write-Host "`n==> 执行完成" -ForegroundColor Green
Write-Host "下一步：根据检查清单完成人工测试项，生成阶段报告"