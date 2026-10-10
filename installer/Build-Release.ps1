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
    [switch]$TestCert,
    # RSA/ECDSA verification public key included with update-capable clients. Never pass a private key here.
    [string]$PublicKeyPath = "",
    # Flutter 客户端预构建目录（suanfatong: build\windows\x64\runner\Release）→ payload\app
    # BLK-001（Windows 开发者模式）阻塞本机构建时，可从其他机器拷贝 Release 目录后传入
    [string]$FlutterBuildRoot = "",
    # 完整融合候选发行必须显式开启：学生客户端缺失时在构建前失败。
    [switch]$RequireFlutterClient
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
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot).TrimEnd([char[]]'\/')
if ($RequireFlutterClient -and -not $FlutterBuildRoot) {
    throw '完整融合发行必须提供 -FlutterBuildRoot；未构建或复制任何产物。'
}
if ($FlutterBuildRoot) {
    $FlutterBuildRoot = [IO.Path]::GetFullPath($FlutterBuildRoot)
    & (Join-Path $scriptRoot 'Validate-FlutterRelease.ps1') -ReleaseRoot $FlutterBuildRoot
    if (Test-Path -LiteralPath (Join-Path $OutputRoot 'app')) {
        throw '客户端目标目录已存在，请使用新的 -OutputRoot，避免旧文件混入发行物。'
    }
}
elseif (Test-Path -LiteralPath (Join-Path $OutputRoot 'app')) {
    throw '服务组件发行目录包含旧客户端，请使用新的 -OutputRoot。'
}

$targets = @(
    # (项目, payload 子目录)  服务 → services；更新器 → updater；控制台 → admin
    # 桌面桥接器 → bridge（iss 装到 {app} 根，算法通客户端固定路径探测）
    @{ Project = 'Winknow.ControlService'; Out = 'services' },
    @{ Project = 'Winknow.GuardService';   Out = 'services' },
    @{ Project = 'Winknow.TrustedUpdater'; Out = 'updater' },
    @{ Project = 'Winknow.AdminUI';        Out = 'admin' },
    @{ Project = 'Winknow.SessionAgent';   Out = 'agent' },
    @{ Project = 'Winknow.RecoveryTool';   Out = 'tools' },
    @{ Project = 'Winknow.DesktopBridge';  Out = 'bridge' }
)

function Write-Step([string]$msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Remove-InstallerTemporaryDirectory([string]$Path) {
    $resolvedTarget = [IO.Path]::GetFullPath($Path)
    $allowedRoot = [IO.Path]::GetFullPath($scriptRoot).TrimEnd('\') + '\'
    if (-not $resolvedTarget.StartsWith($allowedRoot, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path $resolvedTarget -Leaf) -notin @('obf_workspace', 'original_backup')) {
        throw 'Temporary cleanup target escaped the installer workspace.'
    }
    Remove-Item -LiteralPath $resolvedTarget -Recurse -Force
}

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
        # 尝试全局查找（cmd /c 吞 stderr：PS5.1 + EAP=Stop 下 where.exe 2>$null 的
        # "INFO: Could not find" 会以 NativeCommandError 终止脚本）
        $obfuscarExe = cmd /c "where obfuscar.console 2>nul"
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
    
    # 构造平铺混淆工作区：Obfuscar 仅在 InPath 根目录解析依赖，
    # payload 的分目录结构（services/admin/agent/updater）会报
    # "Unable to resolve dependency"，故将全部程序集平铺到 installer\obf_workspace
    $obfWorkspace = Join-Path $scriptRoot 'obf_workspace'
    if (Test-Path $obfWorkspace) {
        Remove-InstallerTemporaryDirectory $obfWorkspace
    }
    New-Item -ItemType Directory -Force -Path $obfWorkspace | Out-Null
    Get-ChildItem $OutputRoot -Recurse -Include *.dll, *.exe -File |
        ForEach-Object { Copy-Item $_.FullName (Join-Path $obfWorkspace $_.Name) -Force }

    # 执行混淆（xml 的 InPath 相对 cwd 解析，以 installer\ 为 cwd）
    Write-Host "执行混淆，配置: $obfuscarConfig"
    Push-Location $scriptRoot
    try {
        obfuscar.console "$obfuscarConfig"
        if ($LASTEXITCODE -ne 0) {
            throw "混淆失败（exit $LASTEXITCODE）"
        }
    }
    finally {
        Pop-Location
    }
    $obfuscatedOutput = Join-Path $obfWorkspace 'obfuscated'

    # 备份原始DLL（放 payload 外：未混淆程序集不得进入 manifest 与分发产物）
    $backupDir = Join-Path $scriptRoot 'original_backup'
    if (Test-Path $backupDir) {
        Remove-InstallerTemporaryDirectory $backupDir
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
        'agent\Winknow.SessionAgent.dll',
        'admin\Winknow.Licensing.dll',
        'updater\Winknow.TrustedUpdater.dll'
    )
    
    # 备份并替换混淆后的DLL
    foreach ($dllPath in $obfuscatedDlls) {
        $originalPath = Join-Path $OutputRoot $dllPath
        $backupPath = Join-Path $backupDir $dllPath
        # 平铺工作区按文件名取回
        $obfuscatedPath = Join-Path $obfuscatedOutput (Split-Path $dllPath -Leaf)

        if (-not (Test-Path $obfuscatedPath)) {
            throw "混淆产物缺失: $obfuscatedPath"
        }
        if (Test-Path $originalPath) {
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

    # 清理临时工作区
    if (Test-Path $obfWorkspace) {
        Remove-InstallerTemporaryDirectory $obfWorkspace
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

# ── 3b. Flutter 客户端入 payload（可选）───────────────────────
# suanfatong 构建产物：flutter build windows --release
#   → <suanfatong>\build\windows\x64\runner\Release\
# iss 将 payload\app 装到 {app}\Suanfatong（缺失时 skipifsourcedoesntexist）
if ($FlutterBuildRoot) {
    if (-not [IO.Path]::IsPathRooted($FlutterBuildRoot)) {
        $FlutterBuildRoot = Join-Path (Get-Location) $FlutterBuildRoot
    }
    if (-not (Test-Path $FlutterBuildRoot -PathType Container)) { throw "FlutterBuildRoot 不存在: $FlutterBuildRoot" }
    Write-Step "注入 Flutter 客户端 → payload\app"
    $appDir = Join-Path $OutputRoot 'app'
    New-Item -ItemType Directory -Force -Path $appDir | Out-Null
    Copy-Item (Join-Path $FlutterBuildRoot '*') $appDir -Recurse -Force
    & (Join-Path $scriptRoot 'Validate-FlutterRelease.ps1') -ReleaseRoot $appDir
    $script:FlutterClientIncluded = $true
}
else {
    # N07（2026-10-08 第二轮复核）：本通道产出的是"服务组件单独发行"——
    # 含 ControlService/Guard/Bridge，不含算法通学生客户端（BLK-001 OPEN，
    # Flutter symlink 构建阻塞）。必须显式声明产品范围，避免被当作完整融合交付。
    Write-Warning "产品范围：仅服务端组件（ControlService / Guard / Bridge），不含算法通学生客户端。"
    Write-Warning "完整融合发行必须提供 -FlutterBuildRoot 注入客户端，并在干净机器完成安装验收。"
    $script:FlutterClientIncluded = $false
}

# A public key is required for any signed, distributable release.  It is deliberately
# copied as a separate verification artifact; private keys are never read by this script.
if ($PublicKeyPath) {
    if (-not (Test-Path $PublicKeyPath -PathType Leaf)) { throw "公钥不存在: $PublicKeyPath" }
    $keyDir = Join-Path $OutputRoot 'keys'
    New-Item -ItemType Directory -Force -Path $keyDir | Out-Null
    Copy-Item $PublicKeyPath (Join-Path $keyDir 'publickey.pem') -Force
}
elseif ($Sign -and -not $TestCert) {
    throw "正式签名构建必须提供 -PublicKeyPath（仅可提供验证公钥）"
}

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
    product         = 'Winknow'
    version         = '7.0.1'
    generated       = (Get-Date).ToUniversalTime().ToString('o')
    # N07：manifest 明示产品范围——服务端恒在；flutter_client 仅在注入后为 true。
    # 验收方据此区分"服务组件单独发行"与"完整融合交付"。
    components      = @('server')
    flutter_client  = [bool]$FlutterClientIncluded
    files           = $entries
}
if ($FlutterClientIncluded) { $manifest.components += 'flutter_client' }
$manifest | ConvertTo-Json -Depth 4 | Set-Content "$OutputRoot\release_manifest.json" -Encoding utf8
Write-Host ("清单含 {0} 个文件" -f $entries.Count) -ForegroundColor Green

Write-Step "完成。payload：$OutputRoot"
Write-Host "下一步：ISCC.exe `"$PSScriptRoot\WinknowSetup.iss`" 生成安装包（dist\）"
