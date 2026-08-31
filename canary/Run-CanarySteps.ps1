# Run-CanarySteps.ps1 —— 灰度三阶段分步引导执行器（可确认 / 可检测 / 可排障 / 可续跑）
# 设计：
#   每个步骤 = 指令提示 + 可选自动检测 + 排障指引 + 状态记录(stepstate.json)
#   - 交互模式：每步 Read-Host 确认（通过/失败/跳过/退出）
#   - -Auto：跳过人工确认，以自动检测结果为准（无检测项默认通过）
#   - -Resume：跳过状态文件中已 PASS 的步骤
# 用法示例：
#   .\Run-CanarySteps.ps1 -Group menu                              # 主菜单（默认）
#   .\Run-CanarySteps.ps1 -Group pre  -Machine T-01                # 前置检查
#   .\Run-CanarySteps.ps1 -Group p1d1 -Machine T-01                # 阶段一 D1
#   .\Run-CanarySteps.ps1 -Group lic  -Machine T-01 -Operator 张三  # 授权专项
#   .\Run-CanarySteps.ps1 -Group p1d1 -Machine T-01 -Resume        # 断点续跑
#   .\Run-CanarySteps.ps1 -List                                    # 仅列出全部步骤
#   .\Run-CanarySteps.ps1 -Step A2 -Machine T-01                   # 单步执行
param(
    [ValidateSet('menu','pre','p1d1','p1d2','phase2','phase3','lic','fuse','all','status')]
    [string]$Group = 'menu',
    [string]$Machine = '',
    [string]$Step = '',
    [string]$Operator = '',
    [switch]$List,
    [switch]$Auto,
    [switch]$Resume,
    [switch]$Reset
)

$ErrorActionPreference = 'Continue'
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path $MyInvocation.MyCommand.Path -Parent }
$reportsDir = Join-Path $scriptRoot 'reports'
if (-not (Test-Path $reportsDir)) { New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null }
$stateFile = Join-Path $reportsDir 'stepstate.json'
if (-not $Machine) { $Machine = $env:COMPUTERNAME }

# ============ 工具函数 ============
function Write-Title([string]$t) { Write-Host ""; Write-Host ("==== " + $t + " ====") -ForegroundColor Cyan }
function Write-Ok([string]$t)    { Write-Host ("[PASS] " + $t) -ForegroundColor Green }
function Write-Bad([string]$t)   { Write-Host ("[FAIL] " + $t) -ForegroundColor Red }
function Write-Info([string]$t)  { Write-Host ("[INFO] " + $t) -ForegroundColor Yellow }

# 服务/事件快捷检测（供 Check 脚本块复用）
function Test-SvcRunning([string]$name) {
    $s = Get-Service -Name $name -ErrorAction SilentlyContinue
    return ($null -ne $s -and $s.Status -eq 'Running')
}
function Test-SvcAbsent([string]$name) {
    return ($null -eq (Get-Service -Name $name -ErrorAction SilentlyContinue))
}
function Get-WkEventCount([int]$id, [string]$msgMatch, [double]$hours = 24) {
    try {
        $f = @{ LogName='Application'; ProviderName='Winknow'; Id=$id; StartTime=(Get-Date).AddHours(-1*$hours) }
        $ev = Get-WinEvent -FilterHashtable $f -ErrorAction Stop
        if ($msgMatch) { $ev = $ev | Where-Object { $_.Message -match $msgMatch } }
        return @($ev).Count
    } catch { return 0 }
}
function Get-WkMsgEventCount([string]$msgMatch, [double]$hours = 24) {
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='Winknow'; StartTime=(Get-Date).AddHours(-1*$hours) } -ErrorAction Stop |
              Where-Object { $_.Message -match $msgMatch }
        return @($ev).Count
    } catch { return 0 }
}

# ============ 状态管理 ============
$script:state = @{}
if (Test-Path $stateFile) {
    try { $script:state = Get-Content $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $script:state = @{} }
}
function Get-MachineState([string]$m) {
    if ($script:state.PSObject.Properties[$m]) { return $script:state.$m } else { return $null }
}
function Save-State {
    $script:state | ConvertTo-Json -Depth 5 | Set-Content $stateFile -Encoding UTF8
}
function Set-StepResult([string]$m, [string]$stepId, [string]$status, [string]$note) {
    $ms = Get-MachineState $m
    if ($null -eq $ms) {
        $ms = New-Object PSObject
        $script:state | Add-Member -MemberType NoteProperty -Name $m -Value $ms -Force
    }
    $ms | Add-Member -MemberType NoteProperty -Name $stepId -Value (
        New-Object PSObject -Property @{ status=$status; time=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); note=$note }
    ) -Force
    Save-State
}
function Get-StepResult([string]$m, [string]$stepId) {
    $ms = Get-MachineState $m
    if ($null -ne $ms -and $ms.PSObject.Properties[$stepId]) { return $ms.$stepId.status } else { return $null }
}

# ============ 步骤定义 ============
# 字段：Id/Title/Prompt(操作指令)/Cmd(参考命令)/Check(自动检测脚本块,返回$true/$false)/Pass(通过判据)/Fix(排障指引数组)
$Steps = @(
    # ---------- 〇 前置检查 ----------
    @{ Id='P1'; G='pre'; Title='管理员权限'
       Prompt='以管理员身份打开 PowerShell'
       Cmd='whoami /groups | find "S-1-16-12288"'
       Check={ ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
       Pass='当前会话为管理员'
       Fix=@('开始菜单 → Windows PowerShell → 右键"以管理员身份运行"','重新执行本脚本') },
    @{ Id='P2'; G='pre'; Title='.NET 8 运行时'
       Prompt='确认 .NET 8 运行时已安装'
       Cmd='dotnet --list-runtimes'
       Check={ try { (dotnet --list-runtimes 2>$null | Select-String 'Microsoft\.AspNetCore\.App 8\.').Count -gt 0 } catch { $false } }
       Pass='列表含 Microsoft.AspNetCore.App 8.x'
       Fix=@('下载安装 .NET 8 Desktop/Runtime：https://dotnet.microsoft.com/download/dotnet/8.0','安装后重开终端再检测') },
    @{ Id='P3'; G='pre'; Title='磁盘剩余空间'
       Prompt='确认 C 盘剩余 ≥10GB'
       Cmd='Get-PSDrive C'
       Check={ ((Get-PSDrive C).Free / 1GB) -ge 10 }
       Pass='C 盘剩余 ≥10GB'
       Fix=@('清理临时文件/回收站','必要时联系机房扩容') },
    @{ Id='P4'; G='pre'; Title='V6.0 处置确认'
       Prompt='控制面板确认旧版本状态：无V6.0(干净装) / 已卸载 / 已备份后保留，并在备注记录'
       Cmd='Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -match "Winknow"} | Select DisplayName,DisplayVersion'
       Pass='按实际情况记录'
       Fix=@('如保留 V6.0：先备份 C:\ProgramData\Winknow 配置','备份位置记入 00_灰度机清单 二节') },
    @{ Id='P5'; G='pre'; Title='升级前配置备份(有V6.0时)'
       Prompt='如有 V6.0，备份其配置目录并在备注填备份路径；无 V6.0 直接通过'
       Pass='备份完成或不适用'
       Fix=@('压缩 C:\ProgramData\Winknow 至安全位置','路径写入灰度机清单') },
    @{ Id='P6'; G='pre'; Title='BIOS 密码已设置'
       Prompt='重启进 BIOS 确认管理员密码已设（无法自动检测）'
       Pass='BIOS 密码已设'
       Fix=@('参考 docs\多品牌BIOS兼容矩阵与部署标准.md','按品牌 Key 设定统一密码') },
    @{ Id='P7'; G='pre'; Title='安装包 SHA256 核对'
       Prompt='将安装包放入本机，脚本自动计算 SHA256（与发布清单核对后通过）'
       Cmd='$pkg="WinknowSetup_7.0.0.exe"; if(Test-Path $pkg){(Get-FileHash $pkg -Algorithm SHA256).Hash}'
       Check={ (Test-Path '.\WinknowSetup_7.0.0.exe') }
       Pass='哈希与发布清单一致'
       Fix=@('从打包机重新拷贝安装包','用 release_manifest.json 核对哈希') },

    # ---------- 阶段一 D1 ----------
    @{ Id='A1'; G='p1d1'; Title='安装 V7.0'
       Prompt='运行安装包完成安装（静默或向导均可）'
       Cmd='.\WinknowSetup_7.0.0.exe /SILENT'
       Check={ (Test-Path 'C:\ProgramData\Winknow\deploy\Current\Winknow.ControlService.exe') }
       Pass='deploy\Current 下 ControlService.exe 存在'
       Fix=@('查看安装日志 %TEMP%\WinknowSetup*.log','确认 P1-P7 全部通过后重试','以管理员身份重跑安装包') },
    @{ Id='A2'; G='p1d1'; Title='双服务运行'
       Prompt='安装完成后核验双服务'
       Cmd='sc query WinknowControl & sc query WinknowGuard'
       Check={ (Test-SvcRunning 'WinknowControl') -and (Test-SvcRunning 'WinknowGuard') }
       Pass='两服务均 RUNNING'
       Fix=@('sc qc WinknowControl 检查启动类型应为 auto','sc qfailure 应配置 restart 5s/10s/30s','查看 Application 日志来源 Winknow 的错误') },
    @{ Id='A3'; G='p1d1'; Title='自动装机核验'
       Prompt='运行装机核验脚本，生成核验报告'
       Cmd="canary\Verify-Release.ps1 -Installed"
       Check={ (Get-ChildItem (Join-Path $reportsDir '装机核验_*') -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime -gt (Get-Date).AddHours(-2) }
       Pass='2 小时内生成新的装机核验报告'
       Fix=@('确认以管理员运行','核验报告四节自动项须全 PASS，否则先处理再继续') },
    @{ Id='A4'; G='p1d1'; Title='版本与回滚位'
       Prompt='确认当前版本 7.0.0 且具备回滚位'
       Cmd='C:\ProgramData\Winknow\deploy\Current\Winknow.TrustedUpdater.exe status'
       Check={ $out = & 'C:\ProgramData\Winknow\deploy\Current\Winknow.TrustedUpdater.exe' status 2>$null; ($out | Select-String '7\.0\.0').Count -gt 0 }
       Pass='status 输出 7.0.0'
       Fix=@('路径不对→检查 deploy\Current 落位','status 失败→看 updater 日志') },
    @{ Id='A5'; G='p1d1'; Title='AdminUI 首检导出'
       Prompt='打开 AdminUI → 设备安全页 → 检测 → 导出报告，评分记入备注'
       Pass='报告已导出归档，评分 __'
       Fix=@('AdminUI 打不开→确认 .NET 8 Desktop Runtime','检测失败→看 AdminUI 日志') },
    @{ Id='B1'; G='p1d1'; Title='策略下发'
       Prompt='AdminUI 下发默认策略 v7.0'
       Cmd='Get-Content C:\ProgramData\Winknow\policy\default_policy_v7.0.json'
       Check={ Test-Path 'C:\ProgramData\Winknow\policy\default_policy_v7.0.json' }
       Pass='策略文件落位'
       Fix=@('手动检查 policy 目录权限','重新从 AdminUI 下发') },
    @{ Id='B2'; G='p1d1'; Title='未授权软件拦截'
       Prompt='启动一个未授权测试程序，记录被关闭的时延(目标<5s)'
       Check={ (Get-WkEventCount 9001 '' 1) -gt 0 }
       Pass='9001 事件产生且时延 __ s'
       Fix=@('无事件→检查策略是否含该程序判定规则','时延>5s→记录为 P2 缺陷并联系开发') },
    @{ Id='B3'; G='p1d1'; Title='U 盘阻断'
       Prompt='插入 U 盘尝试读写（物理操作）'
       Pass='U 盘被阻止'
       Fix=@('放行了→检查 USB 分类策略(UsbDeviceClassifier)','看 9001 事件与 audit.db') },
    @{ Id='B4'; G='p1d1'; Title='键鼠不受影响'
       Prompt='拦截状态下打字/移动鼠标'
       Pass='键鼠正常'
       Fix=@('异常→立即视为 P0，执行熔断(见 fuse 组)','拔掉外设重启会话复测') },
    @{ Id='B5'; G='p1d1'; Title='DeviceSecurity 五项核验'
       Prompt='AdminUI 设备安全页执行"核验"，五项全过后导出'
       Pass='五项全过，报告归档'
       Fix=@('个别项失败→截图记录，评分写入日报','连续失败→登记缺陷') },
    @{ Id='C1'; G='p1d1'; Title='WMI 停止自愈'
       Prompt='执行命令停止 WMI，等 30 秒观察重建'
       Cmd='net stop winmgmt'
       Check={ (Get-WkMsgEventCount 'WMI watcher' 1) -gt 0 }
       Pass='日志含"WMI watcher 意外停止…重建"'
       Fix=@('看 Application 日志 Winknow 来源','重建失败→sc start winmgmt 手动恢复并登记 P1') },
    @{ Id='C2'; G='p1d1'; Title='强杀 ControlService 自愈'
       Prompt='停止 ControlService，观察 Guard 拉起/租约接管，记录耗时'
       Cmd='sc stop WinknowControl; Start-Sleep 30; sc query WinknowControl'
       Check={ Start-Sleep 35; Test-SvcRunning 'WinknowControl' }
       Pass='35 秒内服务恢复 RUNNING，耗时 __ s'
       Fix=@('未拉起→sc start WinknowControl 手动启动','登记 P1：Guard 未接管，看 Guard 日志') },
    @{ Id='C3'; G='p1d1'; Title='冷启动'
       Prompt='重启机器（脚本重启前会先记录状态，重启后请用 -Resume 继续）'
       Cmd='shutdown /r /t 0'
       Pass='重启后双服务自启且无重启风暴'
       Fix=@('服务未自启→sc qc 检查 auto','反复重启→P0 熔断：进安全模式卸载') },
    @{ Id='D1'; G='p1d1'; Title='D1 收尾采集+人工补填'
       Prompt='执行采集脚本生成日报草稿，再补填人工项(误拦数/时延/自愈确认)'
       Cmd="canary\Canary-Phase-Executor.ps1 -Stage 1 -Day 1 -Machine $Machine"
       Check={ (Get-ChildItem (Join-Path $reportsDir ('日报_S1D1_' + $Machine + '_*')) -ErrorAction SilentlyContinue).Count -gt 0 }
       Pass='日报草稿生成并补填'
       Fix=@('脚本失败→检查 BOM/编码与管理员权限','手动兜底：canary\Collect-CanaryMetrics.ps1 -Stage 1 -Day 1') },

    # ---------- 阶段一 D2 ----------
    @{ Id='E1'; G='p1d2'; Title='构建 7.0.1 测试包(打包机)'
       Prompt='在打包机执行构建（记录 SHA256）'
       Cmd='installer\Build-Release.ps1'
       Pass='测试包生成，SHA256 __'
       Fix=@('构建失败→看构建日志错误','确认签名步骤完成') },
    @{ Id='E2'; G='p1d2'; Title='更新到 7.0.1'
       Prompt='触发更新机制安装 7.0.1'
       Check={ $out = & 'C:\ProgramData\Winknow\deploy\Current\Winknow.TrustedUpdater.exe' status 2>$null; ($out | Select-String '7\.0\.1').Count -gt 0 }
       Pass='status 显示 7.0.1'
       Fix=@('更新失败→看 updater 日志与健康检查结果','必要时 rollback 回 7.0.0') },
    @{ Id='E3'; G='p1d2'; Title='回滚演练(二选一)'
       Prompt='①构造健康检查失败看自动回滚 或 ②手动 rollback，方式记备注'
       Cmd='C:\ProgramData\Winknow\deploy\Current\Winknow.TrustedUpdater.exe rollback'
       Check={ $out = & 'C:\ProgramData\Winknow\deploy\Current\Winknow.TrustedUpdater.exe' status 2>$null; ($out | Select-String '7\.0\.0').Count -gt 0 }
       Pass='版本回退 7.0.0 且服务正常，方式 __'
       Fix=@('rollback 失败→检查 Previous 槽是否存在','服务异常→sc query 两服务并看日志') },
    @{ Id='E4'; G='p1d2'; Title='断电演练(物理)'
       Prompt='运行中直接断闸→上电开机，用 -Resume 继续'
       Check={ Start-Sleep 2; (Test-SvcRunning 'WinknowControl') -and (Test-SvcRunning 'WinknowGuard') }
       Pass='上电后双服务自启，策略仍生效'
       Fix=@('未自启→sc qc 核对 auto 与恢复策略','重启风暴→P0 熔断') },
    @{ Id='E5'; G='p1d2'; Title='整包回退演练(任一台)'
       Prompt='维护模式→卸载 V7.0→sc query 双服务应 1060→重装 V7.0'
       Cmd='sc query WinknowControl'
       Check={ Test-SvcAbsent 'WinknowControl' }
       Pass='卸载后查询返回 1060；重装后恢复'
       Fix=@('卸载残留→检查 ProgramData\Winknow 与服务项','重装失败→重跑 A1 流程') },
    @{ Id='E6'; G='p1d2'; Title='维护模式进出'
       Prompt='用第 9 周密钥清单中的维护授权码进入并退出维护模式'
       Pass='进出成功'
       Fix=@('授权码不匹配→核对 keys\ 密钥清单','退出失败→重启 ControlService 后重试') },
    @{ Id='E7'; G='p1d2'; Title='D2 收尾采集'
       Prompt='执行 D2 采集并补填人工项'
       Cmd="canary\Canary-Phase-Executor.ps1 -Stage 1 -Day 2 -Machine $Machine"
       Check={ (Get-ChildItem (Join-Path $reportsDir ('日报_S1D2_' + $Machine + '_*')) -ErrorAction SilentlyContinue).Count -gt 0 }
       Pass='D2 日报生成'
       Fix=@('兜底：canary\Collect-CanaryMetrics.ps1 -Stage 1 -Day 2') },
    @{ Id='E8'; G='p1d2'; Title='汇总《灰度阶段报告(一)》'
       Prompt='填写 reports\灰度阶段报告_一_模板.md，逐项判定出口条件'
       Pass='报告完成，出口判定 __'
       Fix=@('数据缺失→补跑当日采集','出口不通过→写明问题并暂停放量') },

    # ---------- 阶段二 ----------
    @{ Id='F1'; G='phase2'; Title='S-01~S-05 安装(同A1-A5)'
       Prompt='5 台学生机逐台执行 A1→A5 流程（可用本脚本 -Group pre/p1d1 逐台跑）'
       Check={ Test-SvcRunning 'WinknowControl' }
       Pass='五台核验报告归档'
       Fix=@('单台失败→按该机 A1-A5 的 Fix 处理','全部失败→检查安装包/网络') },
    @{ Id='F2'; G='phase2'; Title='学生账户登录验证'
       Prompt='按上课真实环境登录学生账户，确认服务与拦截在学生权限下正常'
       Pass='学生权限下正常'
       Fix=@('权限问题→检查服务运行账户 LocalSystem','策略未生效→重新下发') },
    @{ Id='F3'; G='phase2'; Title='D3 当日采集×5'
       Prompt='5 台各执行 Stage 2 Day 3 采集'
       Cmd="canary\Canary-Phase-Executor.ps1 -Stage 2 -Day 3 -Machine <机器>"
       Pass='五份日报草稿'
       Fix=@('兜底：Collect-CanaryMetrics.ps1 -Stage 2 -Day 3') },
    @{ Id='G1'; G='phase2'; Title='每日误拦复核'
       Prompt='逐条核对当日 9001 事件（两天各一次），阻断性误拦须为零'
       Cmd='Get-WinEvent -FilterHashtable @{LogName="Application";ProviderName="Winknow";Id=9001}'
       Check={ (Get-WkEventCount 9001 '' 24) -ge 0 }
       Pass='D3 __条 / D4 __条，零阻断性误拦'
       Fix=@('出现阻断性误拦→登记 P1，评估是否暂停放量','截图+程序路径记入日报') },
    @{ Id='G2'; G='phase2'; Title='编译成功率抽样'
       Prompt='学生机编译测试×3 次/天，记录成功率(≥95%)'
       Pass='D3 __% / D4 __%'
       Fix=@('失败→定位是否拦截/资源占用导致','<95% 记 P1') },
    @{ Id='G3'; G='phase2'; Title='洛谷提交抽样'
       Prompt='洛谷提交×3 次/天，记录成功率(≥95%)'
       Pass='D3 __% / D4 __%'
       Fix=@('网络/浏览器被拦→核对白名单策略') },
    @{ Id='G4'; G='phase2'; Title='键鼠体验反馈'
       Prompt='收集学生键鼠反馈（两天）'
       Pass='零影响'
       Fix=@('有影响→P0 熔断处理') },
    @{ Id='G5'; G='phase2'; Title='可解释投诉统计'
       Prompt='记录每天投诉内容与条数(≤1起/天)'
       Pass='D3 __起 / D4 __起'
       Fix=@('超线→分析是否策略误伤，调整并记录') },
    @{ Id='H1'; G='phase2'; Title='D4 收尾采集×5'
       Prompt='5 台执行 Stage 2 Day 4 采集'
       Cmd="canary\Canary-Phase-Executor.ps1 -Stage 2 -Day 4 -Machine <机器>"
       Pass='五份日报'
       Fix=@('兜底：Collect-CanaryMetrics.ps1 -Stage 2 -Day 4') },
    @{ Id='H2'; G='phase2'; Title='汇总《灰度阶段报告(二)》'
       Prompt='填写 reports\灰度阶段报告_二_模板.md'
       Pass='报告完成，出口判定 __'
       Fix=@('数据缺口→回看各机日报') },

    # ---------- 阶段三 ----------
    @{ Id='I1'; G='phase3'; Title='全量安装(含最老/最新机型)'
       Prompt='10~20 台逐台 pre+p1d1 流程；品牌合计≥3 类记入备注'
       Check={ Test-SvcRunning 'WinknowControl' }
       Pass='全量核验报告齐全，品牌 __ 类'
       Fix=@('个别机型失败→查 docs\多品牌BIOS兼容矩阵','同型多台失败→登记缺陷暂停该型号放量') },
    @{ Id='I2'; G='phase3'; Title='每日收尾采集(连续)'
       Prompt='每天每台执行 Stage 3 Day n 采集'
       Cmd="canary\Canary-Phase-Executor.ps1 -Stage 3 -Day <n> -Machine <机器>"
       Pass='日报连续无缺'
       Fix=@('缺漏当天补跑并注明') },
    @{ Id='I3'; G='phase3'; Title='跨周末冷启动(≥1次)'
       Prompt='周五关机→周一开机核验（日期记备注）'
       Check={ (Test-SvcRunning 'WinknowControl') -and (Test-SvcRunning 'WinknowGuard') }
       Pass='双服务自启正常，日期 __'
       Fix=@('未自启→sc qc 核对；登记缺陷') },
    @{ Id='I4'; G='phase3'; Title='课堂断电演练(≥1次)'
       Prompt='上课中断电→上电核验'
       Check={ (Test-SvcRunning 'WinknowControl') -and (Test-SvcRunning 'WinknowGuard') }
       Pass='自愈成功，日期 __'
       Fix=@('未自愈→按 E4 的 Fix 处理') },
    @{ Id='I5'; G='phase3'; Title='Windows 更新重启(≥1次)'
       Prompt='触发系统更新并重启，核验服务自愈'
       Check={ (Test-SvcRunning 'WinknowControl') -and (Test-SvcRunning 'WinknowGuard') }
       Pass='自愈正常，日期 __'
       Fix=@('更新把服务禁用→登记 P1 并调整更新策略豁免') },
    @{ Id='I6'; G='phase3'; Title='7天连续运行计时'
       Prompt='起算机与起算日记入备注（阶段一测试机可合并计入）'
       Pass='连续 ≥7 天无 P0，起算 __'
       Fix=@('中断→重新起算并记录原因') },
    @{ Id='I7'; G='phase3'; Title='每日12项指标核对'
       Prompt='对每日日报第1-9节核对达标线'
       Pass='达标/可接受'
       Fix=@('不达标项→标注并评估是否熔断') },
    @{ Id='I8'; G='phase3'; Title='15项发布门槛过单'
       Prompt='逐项核对 docs\发布决策检查单.md'
       Pass='15 项全部勾选'
       Fix=@('未过项→补证据或整改后复审') },
    @{ Id='I9'; G='phase3'; Title='《灰度阶段报告(三)》+评审'
       Prompt='填写模板并组织四负责人签字'
       Pass='结论：☐批准 ☐条件批准 ☐暂缓'
       Fix=@('意见不齐→另约评审，暂缓发布') },

    # ---------- 授权专项 ----------
    @{ Id='L1'; G='lic'; Title='拔网线锁定'
       Prompt='断开学生机网络→等待超过宽限(默认5分钟)→观察全屏锁定遮罩'
       Check={ (Get-WkMsgEventCount 'GRACE_PERIOD|LOCKED|authorization failed' 1) -gt 0 }
       Pass='触发锁定，耗时 __ min'
       Fix=@('未锁定→检查 SessionAgent 与教师机心跳通道','看事件日志 Winknow 来源授权记录') },
    @{ Id='L2'; G='lic'; Title='电话报码解锁(TOTP)'
       Prompt='教师机课堂页对该设备"生成动态码"→口头告知→学生机输入'
       Check={ (Get-WkMsgEventCount 'unlocked|Dynamic code' 1) -gt 0 }
       Pass='解锁成功，耗时 __ s'
       Fix=@('码不匹配→确认教师机/学生机时钟同步(NTP)','连续失败→看 TeacherLicenseServer 日志') },
    @{ Id='L3'; G='lic'; Title='固定码解锁'
       Prompt='使用预置固定密码解锁'
       Check={ (Get-WkMsgEventCount 'unlocked|Fixed code' 1) -gt 0 }
       Pass='解锁成功'
       Fix=@('固定码错误→核对 RecoveryCodeStore/维护密码','仍失败→走维护模式重置') },
    @{ Id='L4'; G='lic'; Title='插线自动解锁'
       Prompt='重新联网→等待心跳恢复→观察自动解除锁定'
       Check={ (Get-WkMsgEventCount 'ONLINE' 1) -gt 0 }
       Pass='自动解锁，恢复耗时 __ min'
       Fix=@('未恢复→检查心跳间隔与网络','超过宽限仍未恢复→重启 SessionAgent') },
    @{ Id='L5'; G='lic'; Title='TOTP 时效性(负向)'
       Prompt='使用超过有效期的动态码尝试解锁，应被拒绝'
       Pass='拒绝解锁(安全符合预期)'
       Fix=@('过期码能解锁→登记 P1 安全缺陷','检查 TotpGenerator 时间窗配置') },
    @{ Id='L6'; G='lic'; Title='授权指标核对'
       Prompt='查看当日日报第 9 节：心跳≥98%、断网锁定≈0、解锁成功'
       Pass='心跳 __% / 锁定 __次 / 解锁 __次'
       Fix=@('心跳<98%→检查教师机负载与网络抖动','锁定次数异常→分析是否宽限配置过短') },

    # ---------- 熔断/回退 ----------
    @{ Id='M1'; G='fuse'; Title='P0 熔断：停止放量+回退'
       Prompt='立即停止新机安装→问题机回退'
       Cmd='C:\ProgramData\Winknow\deploy\Current\Winknow.TrustedUpdater.exe rollback'
       Pass='版本回退且服务正常；仍异常则整包回退(维护模式→卸载)'
       Fix=@('rollback 无效→维护模式卸载整包','键鼠锁死类 P0→进安全模式卸载后联系开发') },
    @{ Id='M2'; G='fuse'; Title='取证采集(72h)'
       Prompt='回退后 72 小时窗口取证'
       Cmd='canary\Collect-CanaryMetrics.ps1 -Stage <n> -Day <m> -SinceHours 72'
       Pass='日报+事件日志导出完成，缺陷登记完毕'
       Fix=@('导出事件：wevtutil epl Application C:\winknow_app.evtx') }
)

# ============ 执行引擎 ============
function Show-Fix([object]$step) {
    Write-Host "  ---- 排障指引 ----" -ForegroundColor Yellow
    foreach ($f in $step.Fix) { Write-Host ("   * " + $f) }
    Write-Host "  通用：sc query WinknowControl/WinknowGuard；Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='Winknow'} -MaxEvents 20" -ForegroundColor DarkYellow
}
function Invoke-Step([object]$step, [string]$mach) {
    $prev = Get-StepResult $mach $step.Id
    if ($Resume -and $prev -eq 'PASS') {
        Write-Info ("跳过(已PASS) " + $step.Id + " " + $step.Title)
        return $true
    }
    Write-Title ($step.Id + " " + $step.Title)
    Write-Host ("操作: " + $step.Prompt) -ForegroundColor White
    if ($step.Cmd)  { Write-Host ("命令: " + $step.Cmd) -ForegroundColor Gray }
    Write-Host ("判据: " + $step.Pass) -ForegroundColor Gray

    $choice = 'y'
    if (-not $Auto) {
        $choice = (Read-Host "已完成? [Y=通过 N=失败 S=跳过 Q=退出组] (默认Y)").ToLower()
        if ($choice -eq '') { $choice = 'y' }
        if ($choice -eq 'q') { Write-Info "退出当前组（状态已保存，可用 -Resume 续跑）"; return $null }
    }

    $status = 'PASS'; $note = ''
    if ($choice -eq 's') {
        $status = 'SKIP'
    } elseif ($step.Check -and ($choice -eq 'y' -or $Auto)) {
        Write-Info "自动检测中..."
        $chk = & $step.Check
        if ($chk) { Write-Ok "自动检测通过" }
        else {
            Write-Bad "自动检测未通过"
            if (-not $Auto) {
                $ov = (Read-Host "人工确认是否算通过? [y/n] (默认n)").ToLower()
                if ($ov -ne 'y') { $status = 'FAIL' }
            } else { $status = 'FAIL' }
        }
    } elseif ($choice -eq 'n') { $status = 'FAIL' }

    if ($status -eq 'PASS') {
        $note = if ($Operator) { ('操作员:' + $Operator) } else { '' }
        Write-Ok ($step.Id + " 记录为 PASS")
    } elseif ($status -eq 'SKIP') {
        Write-Info ($step.Id + " 记录为 SKIP（需在阶段报告注明原因）")
    } else {
        Write-Bad ($step.Id + " 记录为 FAIL")
        Show-Fix $step
        if (-not $Auto) {
            $r = (Read-Host "排障后: [r=重试本步 s=记为跳过继续 c=继续下一步 q=终止]").ToLower()
            if ($r -eq 'r') { return (Invoke-Step $step $mach) }
            if ($r -eq 's') { $status = 'SKIP' }
            if ($r -eq 'q') { Set-StepResult $mach $step.Id $status '终止'; return $null }
        }
    }
    Set-StepResult $mach $step.Id $status $note
    return ($status -ne 'FAIL')
}
function Invoke-Group([string]$g, [string]$mach) {
    $list = $Steps | Where-Object { $_.G -eq $g }
    $fail = 0
    foreach ($s in $list) {
        $r = Invoke-Step $s $mach
        if ($null -eq $r) { break }
        if ($r -eq $false) { $fail++ }
    }
    Write-Title ("组 " + $g + " 结束（机器 " + $mach + "，失败 " + $fail + " 步）")
    Write-Host ("状态文件: " + $stateFile)
    if ($fail -gt 0) { Write-Bad "存在失败步骤：处理后用 -Resume 续跑" }
    else { Write-Ok "全部通过或跳过" }
}
function Show-Status([string]$mach) {
    Write-Title ("步骤状态总览（机器 " + $mach + "）")
    $pass=0;$fail=0;$skip=0;$todo=0
    foreach ($s in $Steps) {
        $st = Get-StepResult $mach $s.Id
        if ($st -eq 'PASS') { $pass++; $mark='PASS' } elseif ($st -eq 'FAIL') { $fail++; $mark='FAIL' } elseif ($st -eq 'SKIP') { $skip++; $mark='SKIP' } else { $todo++; $mark='--' }
        Write-Host ("  {0,-4} {1,-40} {2}" -f $s.Id, $s.Title, $mark)
    }
    Write-Host ("汇总: PASS " + $pass + " / FAIL " + $fail + " / SKIP " + $skip + " / 待执行 " + $todo)
}

# ============ 入口 ============
if ($Reset) {
    if (Test-Path $stateFile) { Remove-Item $stateFile -Force; Write-Info "状态已重置" } else { Write-Info "无状态文件" }
}
if ($List) {
    Write-Title "全部步骤清单"
    foreach ($s in $Steps) { Write-Host ("  [{0}] {1,-4} {2}" -f $s.G, $s.Id, $s.Title) }
    return
}
if ($Step) {
    $s = $Steps | Where-Object { $_.Id -eq $Step }
    if (-not $s) { Write-Bad ("未知步骤: " + $Step + "（用 -List 查看）"); exit 1 }
    Invoke-Step $s $Machine | Out-Null
    Show-Status $Machine
    exit 0
}
switch ($Group) {
    'menu' {
        Write-Title "Winknow V7.0 灰度分步执行器"
        Write-Host "机器: $Machine  状态: $stateFile"
        Write-Host @"
  1) pre     通用前置检查 P1-P7
  2) p1d1    阶段一 D1 安装+拦截+故障注入 A/B/C/D
  3) p1d2    阶段一 D2 更新回滚+断电+整包回退 E1-E8
  4) phase2  阶段二 5台学生机 F/G/H
  5) phase3  阶段三 全量 I1-I9
  6) lic     授权专项演练 L1-L6(每台必做)
  7) fuse    熔断/回退/取证 M1-M2
  8) status  查看状态
  9) exit
"@ -ForegroundColor White
        $sel = Read-Host "选择"
        switch ($sel) {
            '1' { Invoke-Group 'pre' $Machine }
            '2' { Invoke-Group 'p1d1' $Machine }
            '3' { Invoke-Group 'p1d2' $Machine }
            '4' { Invoke-Group 'phase2' $Machine }
            '5' { Invoke-Group 'phase3' $Machine }
            '6' { Invoke-Group 'lic' $Machine }
            '7' { Invoke-Group 'fuse' $Machine }
            '8' { Show-Status $Machine }
            '9' { return }
            default { Write-Info "无选择，退出" }
        }
    }
    'all'   { foreach ($g in 'pre','p1d1','p1d2','phase2','phase3','lic') { Invoke-Group $g $Machine } }
    'status'{ Show-Status $Machine }
    default { Invoke-Group $Group $Machine }
}
