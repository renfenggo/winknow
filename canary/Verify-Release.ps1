# Verify-Release.ps1 —— 灰度 Stage 0 / 部署核验脚本
# 用途：
#   模式 A（默认，本机/打包机）  ：校验发布产物完整性（release_manifest.json SHA256 逐文件比对）
#                                  + 逐文件签名状态清单（Get-AuthenticodeSignature）
#   模式 B（-Installed，灰度机上）：核验安装结果（双服务状态/部署槽布局/数据目录/事件源）
# 输出：Markdown 核验报告（默认 canary/reports/），退出码 0=全部通过，1=存在失败项
# 用法：
#   .\Verify-Release.ps1                                  # 模式 A（产物核验）
#   .\Verify-Release.ps1 -PayloadDir D:\release\payload   # 指定产物目录
#   .\Verify-Release.ps1 -Installed                       # 模式 B（装机核验）
param(
    [string]$PayloadDir = "",
    [switch]$Installed,
    [string]$ReportDir = ""
)

$ErrorActionPreference = 'Stop'
# PS 5.1 + 宿主包装兼容：脚本体内解析路径（param 默认值阶段 $PSScriptRoot 可能为空）
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path $MyInvocation.MyCommand.Path -Parent }
if (-not $PayloadDir) { $PayloadDir = Join-Path $scriptRoot '..\installer\payload' }
if (-not [IO.Path]::IsPathRooted($PayloadDir)) { $PayloadDir = Join-Path $scriptRoot $PayloadDir }
$PayloadDir = [IO.Path]::GetFullPath($PayloadDir)
if (-not $ReportDir) { $ReportDir = Join-Path $scriptRoot 'reports' }
if (-not [IO.Path]::IsPathRooted($ReportDir)) { $ReportDir = Join-Path $scriptRoot $ReportDir }
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$dataRoot = Join-Path $env:ProgramData 'Winknow'
$services = @('WinknowControl', 'WinknowGuard')
$sb = New-Object System.Text.StringBuilder
$failed = 0

function Add-Line([string]$t = '') { [void]$sb.AppendLine($t) }
function Add-Fail([string]$t) { $script:failed++; Add-Line $t }

Add-Line "# Winknow V7.0 核验报告"
Add-Line
Add-Line "- 时间：$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  机器：$env:COMPUTERNAME  模式：$(if ($Installed) {'B 已安装核验'} else {'A 发布产物核验'})"

if (-not $Installed) {
    # ---------- 模式 A：产物完整性 + 签名状态 ----------
    $manifestPath = Join-Path $PayloadDir 'release_manifest.json'
    Add-Line "- 产物目录：$PayloadDir"
    if (-not (Test-Path $manifestPath)) {
        Add-Fail "- **[失败]** 未找到 release_manifest.json"
        Add-Line
        Add-Line "## 结论：未通过（无清单）"
        $out = Join-Path $ReportDir "Stage0_产物核验_$stamp.md"
        [IO.File]::WriteAllText($out, $sb.ToString(), [Text.UTF8Encoding]::new($true))
        Write-Host "==> 报告：$out" ; exit 1
    }
    $manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Add-Line "- 清单：版本 $($manifest.version)，共 $($manifest.files.Count) 个文件，生成于 $($manifest.generated)"
    Add-Line
    Add-Line "## 一、完整性校验（SHA256）"
    $miss = 0; $hashBad = 0; $ok = 0
    foreach ($f in $manifest.files) {
        $p = Join-Path $PayloadDir $f.path
        if (-not (Test-Path $p)) { $miss++; Add-Fail "- **缺失** $($f.path)"; continue }
        $h = (Get-FileHash $p -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($h -ne $f.sha256.ToLowerInvariant()) { $hashBad++; Add-Fail "- **哈希不符** $($f.path)"; continue }
        $ok++
    }
    Add-Line "- 通过 $ok / $($manifest.files.Count)；缺失 $miss；哈希不符 $hashBad"
    Add-Line
    Add-Line "## 二、签名状态（Authenticode，信息性）"
    # 权威签名判定在 Sign-Release.ps1 的验签步骤（测试证书走指纹匹配）；
    # 本段仅呈现状态清单：测试证书无信任链时 UnknownError/NotSigned 属预期。
    $sigOk = 0; $sigNotSigned = 0; $sigOther = 0
    $bins = Get-ChildItem $PayloadDir -Recurse -Include *.exe, *.dll
    foreach ($b in $bins) {
        $sig = Get-AuthenticodeSignature $b.FullName
        $rel = $b.FullName.Substring($PayloadDir.Length + 1)
        switch ($sig.Status) {
            'Valid'    { $sigOk++; Add-Line "- ✅ $rel" }
            'NotSigned'{ $sigNotSigned++; Add-Line "- ⚠️ 未签名 $rel" }
            default    { $sigOther++; Add-Line "- ℹ️ $($sig.Status)（无信任链，见说明） $rel" }
        }
    }
    Add-Line "- 小计：有效签名 $sigOk；未签名 $sigNotSigned；无信任链 $sigOther（共 $($bins.Count) 个 exe/dll）"
    Add-Line
    Add-Line "> 说明：自签名测试证书在本机不受信时 Status 非 Valid 属预期；签名是否生效以 Sign-Release.ps1 验签输出（指纹匹配/verify /pa）为准。**核验硬门槛 = 第一节 SHA256 完整性。**"
    Add-Line
    if ($failed -eq 0) { Add-Line "## 结论：✅ 通过（$ok 个文件哈希全部一致）" }
    else { Add-Line "## 结论：❌ 未通过（完整性失败项 $failed）" }
    $out = Join-Path $ReportDir "Stage0_产物核验_$stamp.md"
}
else {
    # ---------- 模式 B：安装结果核验（对应发布门槛 #11） ----------
    Add-Line "- 数据根：$dataRoot"
    Add-Line
    Add-Line "## 一、服务状态"
    foreach ($s in $services) {
        $svc = Get-Service $s -ErrorAction SilentlyContinue
        if ($null -eq $svc) { Add-Fail "- **未安装** $s"; continue }
        $start = (Get-CimInstance Win32_Service -Filter "Name='$s'").StartMode
        $acct = (Get-CimInstance Win32_Service -Filter "Name='$s'").StartName
        if ($svc.Status -ne 'Running') { Add-Fail "- ❌ $s 状态 $($svc.Status)（应 Running）" }
        else { Add-Line "- ✅ $s Running（启动类型 $start，账户 $acct）" }
    }
    Add-Line
    Add-Line "## 二、部署槽布局"
    $current = Join-Path $dataRoot 'deploy\Current'
    foreach ($exe in 'Winknow.ControlService.exe', 'Winknow.GuardService.exe', 'Winknow.TrustedUpdater.exe') {
        $p = Join-Path $current $exe
        if (Test-Path $p) { Add-Line "- ✅ Current\$exe" } else { Add-Fail "- ❌ 缺失 Current\$exe" }
    }
    foreach ($slot in 'Previous', 'Staging') {
        $d = Join-Path $dataRoot "deploy\$slot"
        if (Test-Path $d) { Add-Line "- ℹ️ $slot 存在" } else { Add-Line "- ℹ️ $slot 不存在（首装无 Previous 属预期）" }
    }
    Add-Line
    Add-Line "## 三、数据目录与策略"
    foreach ($d in 'device_security', 'keys') {
        if (Test-Path (Join-Path $dataRoot $d)) { Add-Line "- ✅ $d\" } else { Add-Fail "- ❌ 缺失 $d\" }
    }
    $pol = Join-Path $dataRoot 'deploy\Current\policy\default_policy_v7.0.json'
    if (Test-Path $pol) { Add-Line "- ✅ 默认策略落位（$(Split-Path -Leaf $pol)）" } else { Add-Fail "- ❌ 未找到默认策略" }
    Add-Line
    Add-Line "## 四、事件日志锚点源"
    try {
        $src = Get-WinEvent -ListProvider 'Winknow' -ErrorAction Stop
        Add-Line "- ✅ 事件源 Winknow 已注册（Application 日志，锚点 9001/9002/9003）"
    } catch { Add-Fail "- ❌ 事件源 Winknow 未注册（服务未成功启动过？）" }
    Add-Line
    if ($failed -eq 0) { Add-Line "## 结论：✅ 安装核验通过（部署核验记录归档用）" }
    else { Add-Line "## 结论：❌ 安装核验未通过（失败项 $failed）" }
    $out = Join-Path $ReportDir "装机核验_${env:COMPUTERNAME}_$stamp.md"
}

[IO.File]::WriteAllText($out, $sb.ToString(), [Text.UTF8Encoding]::new($true))
Write-Host "==> 报告：$out"
if ($failed -ne 0) { exit 1 } else { exit 0 }
