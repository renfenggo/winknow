# =====================================================================
# Winknow V7.0 签名脚本（第 13 周"签名集成：安装包和核心文件签名验证"）
# 场景 A：生产 —— 组织代码签名证书（HSM/Token 或 PFX + 密码）
#          -CertThumbprint <thumb> 从 CurrentUser\My 定位证书
# 场景 B：测试 —— -TestCert 自签名证书（仅验证流水线，不可用于生产分发：
#          PeerVerifier RequireSignature=true 对自签名证书主题匹配需一致）
# 每次签名后 signtool verify 验签 + 时间戳（RFC3161）
# =====================================================================
[CmdletBinding()]
param(
    # 待签名目录（递归 exe/dll/msi）或单个文件
    [Parameter(Mandatory)][string]$Path,
    # 生产证书指纹（CurrentUser\My）
    [string]$CertThumbprint = "",
    # 测试证书模式：现场创建自签名证书（主题 CN=Winknow Test Signing）
    [switch]$TestCert,
    # RFC3161 时间戳服务器
    [string]$TimestampServer = "http://timestamp.digicert.com",
    # signtool 路径（Windows SDK）
    [string]$SignTool = ""
)

$ErrorActionPreference = 'Stop'

function Find-SignTool {
    if ($SignTool -and (Test-Path $SignTool)) { return $SignTool }
    $candidates = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "$env:ProgramFiles\Windows Kits\10\bin"
    ) | Where-Object { Test-Path $_ }
    foreach ($root in $candidates) {
        $found = Get-ChildItem $root -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    throw "未找到 signtool.exe（请安装 Windows SDK 或用 -SignTool 指定路径）"
}

$signtool = Find-SignTool
Write-Host "==> signtool: $signtool" -ForegroundColor Cyan

# ── 证书定位 ───────────────────────────────────────────────────
if ($TestCert) {
    Write-Host "==> 测试模式：创建/复用自签名证书" -ForegroundColor Yellow
    $existing = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq 'CN=Winknow Test Signing' }
    $cert = if ($existing) { $existing[0] } else {
        New-SelfSignedCertificate -Subject 'CN=Winknow Test Signing' `
            -Type CodeSigningCert -KeyUsage DigitalSignature `
            -FriendlyName 'Winknow Test Code Signing' `
            -CertStoreLocation Cert:\CurrentUser\My `
            -NotAfter (Get-Date).AddYears(2)
    }
    $CertThumbprint = $cert.Thumbprint
    Write-Host "    指纹: $CertThumbprint（仅流水线验证用）"
}
elseif (-not $CertThumbprint) {
    throw "生产签名必须提供 -CertThumbprint（或使用 -TestCert 走测试证书）"
}

# ── 目标收集 ───────────────────────────────────────────────────
$targets = if (Test-Path $Path -PathType Leaf) { @(Get-Item $Path) }
else {
    Get-ChildItem $Path -Recurse -Include *.exe, *.dll, *.msi -File
}
if (-not $targets) { throw "未找到可签名文件: $Path" }
Write-Host ("==> 待签名 {0} 个文件" -f $targets.Count)

# ── 签名 + 验签 ────────────────────────────────────────────────
$failed = @()
foreach ($f in $targets) {
    Write-Host "    签名 $($f.Name)"
    # 测试模式跳过 RFC3161 时间戳（内网/无外网环境可跑通流水线；生产强制时间戳）
    $signArgs = @('sign', '/fd', 'SHA256', '/sha1', $CertThumbprint, '/v', $f.FullName)
    if (-not $TestCert) {
        $signArgs = @('sign', '/fd', 'SHA256', '/tr', $TimestampServer, '/td', 'SHA256',
                      '/sha1', $CertThumbprint, '/v', $f.FullName)
    }
    & $signtool @signArgs | Out-Null
    if ($LASTEXITCODE -ne 0) { $failed += $f.FullName; continue }

    if ($TestCert) {
        # 测试证书无受信链，signtool verify /pa 必然失败——
        # 流水线验证目标改为：签名存在且签名者即测试证书（Get-AuthenticodeSignature）
        $sig = Get-AuthenticodeSignature $f.FullName
        if (-not $sig.SignerCertificate -or
            $sig.SignerCertificate.Thumbprint -ne $CertThumbprint) {
            $failed += $f.FullName
        }
    }
    else {
        # 生产：完整验链（/pa 默认策略）——安装包与 PeerVerifier 双重校验的前提
        & $signtool verify /pa /v "$($f.FullName)" | Out-Null
        if ($LASTEXITCODE -ne 0) { $failed += $f.FullName }
    }
}

if ($failed.Count -gt 0) {
    Write-Host "签名/验签失败（$($failed.Count) 个）：" -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    throw "存在签名失败文件"
}

Write-Host ("==> 签名+验签全部通过（{0} 个文件）" -f $targets.Count) -ForegroundColor Green
Write-Host "生产分发提醒：正式发布须使用组织 EV/OV 代码签名证书（对应第 9 周密钥清单 CodeSigning 条目），测试证书构建不得出机房。" -ForegroundColor Yellow
