<#
.SYNOPSIS
    Winknow V7.0 基线验证脚本（v8 计划 P0-04）。
    一条命令输出：Git 基线、SDK/包锁定、构建结果、各测试程序集实际执行数、
    依赖漏洞、安装 payload 完整性检查。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\Verify-Baseline.ps1
    powershell -ExecutionPolicy Bypass -File tools\Verify-Baseline.ps1 -ReportPath docs\baseline\阶段0_基线验证报告.md
    powershell -ExecutionPolicy Bypass -File tools\Verify-Baseline.ps1 -SkipVulnScan
#>
param(
    [string]$Configuration = "Release",
    [switch]$SkipVulnScan,
    [string]$ReportPath = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$report  = New-Object System.Collections.Generic.List[string]
$fail    = New-Object System.Collections.Generic.List[string]
$warn    = New-Object System.Collections.Generic.List[string]

function Add-Line([string]$text) {
    $script:report.Add($text)
    Write-Host $text
}

Add-Line "# Winknow V7.0 基线验证报告（Verify-Baseline）"
Add-Line ("- 生成时间(UTC): " + (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"))

# ---------- 1. Git 基线 ----------
Add-Line ""
Add-Line "## 1. Git 基线"
$branch = (git rev-parse --abbrev-ref HEAD)
$commit = (git rev-parse HEAD)
$dirty  = @(git status --porcelain)
Add-Line ("- 分支: " + $branch)
Add-Line ("- 提交: " + $commit)
if ($dirty.Count -gt 0) {
    Add-Line ("- 工作区: 存在未提交变更（" + $dirty.Count + " 项）")
    $script:warn.Add("工作区存在未提交变更，基线报告不代表干净提交状态")
} else {
    Add-Line "- 工作区: 干净"
}

# ---------- 2. SDK 与包锁定 ----------
Add-Line ""
Add-Line "## 2. SDK 与包锁定"
$sdk = (dotnet --version)
Add-Line ("- 已解析 SDK: " + $sdk)
Add-Line "- global.json 要求: 8.0.400（rollForward: latestFeature）"
Add-Line "- 包版本策略: Directory.Packages.props 中央包管理；锁文件(RestorePackagesWithLockFile)于阶段 1 CI 门禁任务中评估引入"
if ($sdk -notlike "8.*") {
    $script:fail.Add("已解析 SDK($sdk) 不是 8.x，与 global.json 要求不符")
}

# ---------- 3. 还原与构建 ----------
Add-Line ""
Add-Line ("## 3. 还原与构建（Configuration=" + $Configuration + "）")
dotnet restore WinknowV7.sln --nologo 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { $script:fail.Add("dotnet restore 失败") }

$buildOut   = (dotnet build WinknowV7.sln --configuration $Configuration --no-restore --nologo 2>&1 | Out-String)
$buildExit  = $LASTEXITCODE
$warnAll    = [regex]::Matches($buildOut, '(\d+) Warning\(s\)')
$errAll     = [regex]::Matches($buildOut, '(\d+) Error\(s\)')
$warnCount  = if ($warnAll.Count -gt 0) { [int]$warnAll[$warnAll.Count - 1].Groups[1].Value } else { 0 }
$errCount   = if ($errAll.Count  -gt 0) { [int]$errAll[$errAll.Count - 1].Groups[1].Value }  else { 0 }
Add-Line ("- 构建退出码: " + $buildExit + "；Warning(s): " + $warnCount + "；Error(s): " + $errCount)
if ($buildExit -ne 0 -or $errCount -gt 0) { $script:fail.Add("构建失败（退出码 $buildExit, Error $errCount）") }
if ($warnCount -gt 0)                     { $script:fail.Add("构建存在 $warnCount 个警告（TreatWarningsAsErrors 应为 0）") }

# ---------- 4. 测试（按程序集统计实际执行数） ----------
Add-Line ""
Add-Line "## 4. 测试执行（按程序集统计实际执行数）"
$trxDir = Join-Path $root "artifacts\baseline-trx"
if (Test-Path $trxDir) { Remove-Item $trxDir -Recurse -Force }
New-Item -ItemType Directory -Path $trxDir -Force | Out-Null

dotnet test WinknowV7.sln --configuration $Configuration --no-build --nologo --logger trx --results-directory $trxDir 2>&1 | Out-Null
$testExit = $LASTEXITCODE

$trxFiles = @(Get-ChildItem -Path $trxDir -Filter *.trx | Sort-Object Name)
Add-Line ("- 测试程序集(TRX)数: " + $trxFiles.Count)
Add-Line "| 测试程序集 | 已执行 | 通过 | 失败 | 未执行(跳过等) |"
Add-Line "|---|---:|---:|---:|---:|"
$sumExec = 0; $sumPass = 0; $sumFail = 0
foreach ($trx in $trxFiles) {
    $executed = 0; $passed = 0; $failed = 0; $total = 0; $name = ""
    try {
        [xml]$xml = Get-Content -LiteralPath $trx.FullName -Raw
        $c = $xml.TestRun.ResultSummary.Counters
        $executed = [int]$c.GetAttribute("executed")
        $passed   = [int]$c.GetAttribute("passed")
        $failed   = [int]$c.GetAttribute("failed")
        $total    = [int]$c.GetAttribute("total")
        $unit = @($xml.TestRun.TestDefinitions.UnitTest)
        if ($unit.Count -gt 0) {
            $storage = $unit[0].GetAttribute("storage")
            if ($storage) { $name = [System.IO.Path]::GetFileNameWithoutExtension($storage) }
        }
    } catch {
        $script:warn.Add("TRX 解析失败: " + $trx.Name)
    }
    if ([string]::IsNullOrWhiteSpace($name)) { $name = $trx.BaseName }
    Add-Line ("| " + $name + " | " + $executed + " | " + $passed + " | " + $failed + " | " + [Math]::Max(0, $total - $executed) + " |")
    $sumExec += $executed; $sumPass += $passed; $sumFail += $failed
    if ($executed -eq 0) {
        $script:warn.Add("测试程序集 [$name] 实际执行 0 项（零执行假绿风险，阶段 7 CI 门禁将拒绝）")
    }
}
Add-Line ("- 合计: 已执行 " + $sumExec + " / 通过 " + $sumPass + " / 失败 " + $sumFail)
if ($testExit -ne 0) { $script:fail.Add("dotnet test 退出码 $testExit") }
if ($sumFail -gt 0)  { $script:fail.Add("存在 $sumFail 个失败测试") }

# ---------- 5. 依赖漏洞 ----------
if (-not $SkipVulnScan) {
    Add-Line ""
    Add-Line "## 5. 依赖漏洞（--vulnerable --include-transitive）"
    $vulnText = (dotnet list WinknowV7.sln package --vulnerable --include-transitive 2>&1 | Out-String)
    $vulnHits = @($vulnText -split "`r?`n" | Where-Object { $_ -match "> " } | ForEach-Object { ($_ -replace '\s+', ' ').Trim() } | Select-Object -Unique)
    if ($vulnHits.Count -gt 0) {
        Add-Line ("- 发现 " + ($vulnHits | Select-Object -Unique).Count + " 条漏洞依赖记录：")
        foreach ($v in ($vulnHits | Select-Object -Unique)) { Add-Line ("  - " + $v.Trim()) }
        $script:warn.Add("存在已知漏洞依赖（阶段 7 门禁要求 High/Critical=0，需在 P2/PR-11 前升级）")
    } else {
        Add-Line "- 未发现已知漏洞依赖"
    }
}

# ---------- 6. 安装 payload ----------
Add-Line ""
Add-Line "## 6. 安装 payload 完整性"
$manifestPath = Join-Path $root "installer\payload\release_manifest.json"
if (Test-Path $manifestPath) {
    $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
    $files = @($manifest.files)
    $missing = 0; $hashBad = 0
    foreach ($f in $files) {
        $p = Join-Path $root (Join-Path "installer\payload" $f.path)
        if (-not (Test-Path $p)) { $missing++; continue }
        $h = (Get-FileHash -Path $p -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($h -ne ([string]$f.sha256).ToLowerInvariant()) { $hashBad++ }
    }
    Add-Line ("- manifest 文件数: " + $files.Count + "；缺失: " + $missing + "；哈希不符: " + $hashBad)
    if ($missing -gt 0) { $script:fail.Add("payload 缺失 $missing 个 manifest 文件") }
    if ($hashBad -gt 0) { $script:fail.Add("payload 有 $hashBad 个文件哈希不符") }
} else {
    Add-Line "- installer\payload\release_manifest.json 未生成（跳过；由 installer\Build-Release.ps1 生成后复检）"
}

# ---------- 结论 ----------
Add-Line ""
Add-Line "## 结论"
if ($fail.Count -gt 0) {
    Add-Line ("**基线验证未通过**，阻断项 " + $fail.Count + " 个：")
    foreach ($f in $fail) { Add-Line ("- [FAIL] " + $f) }
} else {
    Add-Line "**基线验证通过**（阻断项 0）"
}
if ($warn.Count -gt 0) {
    Add-Line ("警告 " + $warn.Count + " 个：")
    foreach ($w in $warn) { Add-Line ("- [WARN] " + $w) }
}

if ($ReportPath -ne "") {
    $dir = Split-Path -Parent (Join-Path $root $ReportPath)
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $report | Out-File -FilePath (Join-Path $root $ReportPath) -Encoding utf8
    Write-Host ("报告已写入: " + (Join-Path $root $ReportPath))
}

if ($fail.Count -gt 0) { exit 1 } else { exit 0 }
