# =====================================================================
# Winknow V7.0 发布构建脚本（第 13 周）
# 用途：Release 构建 → 组装安装 payload →（可选）签名 → SHA256 清单
# 与 RecoveryVault/PeerVerifier 的 manifest 格式一致（更新与修复信任同一清单）
# =====================================================================
[CmdletBinding()]
param(
    # 输出根目录（相对路径相对于本脚本目录）
    [string]$OutputRoot = "",
    # 跳过构建（复用已有产物）
    [switch]$SkipBuild,
    # 跳过混淆（调试用）
    [switch]$SkipObfuscation,
    # 构建后调用 Sign-Release.ps1（需要证书或 -TestCert）
    [switch]$Sign,
    # 签名脚本参数透传
    [string]$CertThumbprint = "",
    [switch]$TestCert
)

$ErrorActionPreference = 'Stop'
# $PSScriptRoot 在 param 默认值求值阶段可能为空（宿主包装场景）——脚本体内解析
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path $MyInvocation.MyCommand.Path -Parent }
$solutionRoot = Split-Path $scriptRoot -Parent
if (-not $OutputRoot) { $OutputRoot = Join-Path $scriptRoot 'payload' }
# 相对路径 → 绝对（dotnet publish -o 以 cwd 解析，必须钉死基准）
if (-not [IO.Path]::IsPathRooted($OutputRoot)) {
    $OutputRoot = Join-Path $scriptRoot $OutputRoot
}

$targets = @(
    # (项目, payload 子目录)  服务 → services；更新器 → updater；控制台 → admin
    @{ Project = 'Winknow.ControlService'; Out = 'services' },
    @{ Project = 'Winknow.GuardService';   Out = 'services' },
    @{ Project = 'Winknow.TrustedUpdater'; Out = 'updater' },
    @{ Project = 'Winknow.AdminUI';        Out = 'admin' }
)

function Write-Step([string]$msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

# ── 1. 构建与发布 ─────────────────────────────────────────────
if (-not $SkipBuild) {
    Write-Step "Release 构建解决方案"
    dotnet build "$solutionRoot\WinknowV7.sln" -c Release --nologo `
        | Where-Object { $_ -match 'error|warning' } `
        | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
    if ($LASTEXITCODE -ne 0) { throw "构建失败（exit $LASTEXITCODE）" }

    foreach ($t in $targets) {
        $proj = "$solutionRoot\src\$($t.Project)\$($t.Project).csproj"
        $dest = Join-Path $OutputRoot $t.Out
        Write-Step "publish $($t.Project) → $dest"
        $pub = dotnet publish $proj -c Release -o $dest --nologo 2>&1
        if ($LASTEXITCODE -ne 0) {
            $pub | Select-Object -Last 10 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
            throw "publish $($t.Project) 失败"
        }
    }
}

# ── 2. 混淆（publish → 混淆 → 签名 → manifest）──────────────────────
# 混淆必须在签名前：签名改变文件字节，manifest必须描述最终分发字节
if (-not $SkipObfuscation) {
    Write-Step "代码混淆"
    
    # 检查 Obfuscar 是否已安装
    $obfuscarExe = Get-Command obfuscar.console -ErrorAction SilentlyContinue
    if (-not $obfuscarExe) {
        # 尝试全局查找
        $obfuscarExe = where.exe obfuscar.console 2>$null
    }
    
    if (-not $obfuscarExe) {
        Write-Host "未找到 Obfuscar，正在安装..." -ForegroundColor Yellow
        dotnet tool install --global Obfuscar.GlobalTool
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Obfuscar 安装失败" -ForegroundColor Red
            throw "无法安装 Obfuscar"
        }
        # 刷新PATH
        $env:PATH = [System.Environment]::GetEnvironmentVariable("Path", "User") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    }
    
    # 检查混淆配置
    $obfuscarConfig = Join-Path $scriptRoot 'obfuscar.xml'
    if (-not (Test-Path $obfuscarConfig)) {
        throw "未找到 Obfuscar 配置文件: $obfuscarConfig"
    }
    
    # 准备混淆工作目录
    $obfuscatedOutput = Join-Path $OutputRoot 'obfuscated_temp'
    if (Test-Path $obfuscatedOutput) {
        Remove-Item -Path $obfuscatedOutput -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $obfuscatedOutput | Out-Null
    
    # 执行混淆
    Write-Host "执行混淆，配置: $obfuscarConfig"
    $env:OBFUSCAR_INPUT_PATH = $OutputRoot
    $env:OBFUSCAR_OUTPUT_PATH = $obfuscatedOutput
    
    obfuscar.console "$obfuscarConfig"
    if ($LASTEXITCODE -ne 0) {
        throw "混淆失败（exit $LASTEXITCODE）"
    }
    
    # 备份原始DLL
    $backupDir = Join-Path $OutputRoot 'original_backup'
    if (Test-Path $backupDir) {
        Remove-Item -Path $backupDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
    
    # 混淆的DLL列表
    $obfuscatedDlls = @(
        'services\Winknow.ControlService.dll',
        'services\Winknow.GuardService.dll',
        'services\Winknow.Core.dll',
        'services\Winknow.Security.dll',
        'services\Winknow.Ipc.dll',
        'services\Winknow.Logging.dll',
        'services\Winknow.Network.dll',
        'services\Winknow.Policy.dll',
        'services\Winknow.ProcessControl.dll',
        'services\Winknow.DeviceSecurity.dll',
        'services\Winknow.SessionAgent.dll',
        'services\Winknow.Licensing.dll',
        'updater\Winknow.TrustedUpdater.dll'
    )
    
    # 备份并替换混淆后的DLL
    foreach ($dllPath in $obfuscatedDlls) {
        $originalPath = Join-Path $OutputRoot $dllPath
        $backupPath = Join-Path $backupDir $dllPath
        $obfuscatedPath = Join-Path $obfuscatedOutput $dllPath
        
        if (Test-Path $originalPath -and (Test-Path $obfuscatedPath)) {
            # 备份原始文件
            $backupSubDir = Split-Path $backupPath -Parent
            if (-not (Test-Path $backupSubDir)) {
                New-Item -ItemType Directory -Force -Path $backupSubDir | Out-Null
            }
            Copy-Item -Path $originalPath -Destination $backupPath -Force
            
            # 替换为混淆版本
            Copy-Item -Path $obfuscatedPath -Destination $originalPath -Force
            Write-Host "  已混淆: $dllPath" -ForegroundColor Green
        }
    }
    
    # 清理临时文件
    if (Test-Path $obfuscatedOutput) {
        Remove-Item -Path $obfuscatedOutput -Recurse -Force
    }
    
    Write-Host "混淆完成，原始DLL已备份到: $backupDir" -ForegroundColor Green
} else {
    Write-Step "跳过混淆（-SkipObfuscation 指定）"
}

# ── 3. 默认策略入 payload ─────────────────────────────────────
Write-Step "部署默认策略文件"
$policyDir = Join-Path $OutputRoot 'policy'
New-Item -ItemType Directory -Force -Path $policyDir | Out-Null
Copy-Item "$solutionRoot\policies\default_policy_v7.0.json" $policyDir -Force

# ── 4. 签名（可选）——必须在生成清单之前：签名改变文件字节，──
#    release_manifest.json 必须描述最终分发字节（灰度 Stage 0 核验教训）
if ($Sign) {
    Write-Step "调用 Sign-Release.ps1"
    $signArgs = @{ Path = $OutputRoot }
    if ($CertThumbprint) { $signArgs.CertThumbprint = $CertThumbprint }
    if ($TestCert) { $signArgs.TestCert = $true }
    & "$PSScriptRoot\Sign-Release.ps1" @signArgs
}

# ── 5. SHA256 清单（与 RecoveryVault manifest 同格式约定） ─────
Write-Step "生成 SHA256 清单 release_manifest.json"
$files = Get-ChildItem $OutputRoot -Recurse -File |
    Where-Object { $_.Name -ne 'release_manifest.json' }
$entries = foreach ($f in $files) {
    $hash = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    [PSCustomObject]@{
        path     = $f.FullName.Substring($OutputRoot.Length + 1).Replace('\', '/')
        sha256   = $hash
        size     = $f.Length
    }
}
$manifest = [PSCustomObject]@{
    product   = 'Winknow'
    version   = '7.0.0'
    generated = (Get-Date).ToUniversalTime().ToString('o')
    files     = $entries
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content "$OutputRoot\release_manifest.json" -Encoding utf8
Write-Host ("清单含 {0} 个文件" -f $entries.Count) -ForegroundColor Green

Write-Step "完成。payload：$OutputRoot"
Write-Host "下一步：ISCC.exe `"$PSScriptRoot\WinknowSetup.iss`" 生成安装包（dist\）"