# Verify-CanaryReadiness.ps1 - Canary Readiness Check
# Purpose: Verify canary test environment is ready for execution
# Usage: .\Verify-CanaryReadiness.ps1

$ErrorActionPreference = 'Stop'
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path $MyInvocation.MyCommand.Path -Parent }

function Write-Status([string]$msg, [bool]$pass) {
    $color = if ($pass) { "Green" } else { "Red" }
    $icon = if ($pass) { "[PASS]" } else { "[FAIL]" }
    Write-Host "$icon $msg" -ForegroundColor $color
    return $pass
}

function Write-Section([string]$title) {
    Write-Host ""
    Write-Host "=== $title ===" -ForegroundColor Cyan
}

$allChecksPassed = $true

# 1. File Existence Check
Write-Section "File Existence Check"

$requiredFiles = @{
    "Canary Machine List" = Join-Path $scriptRoot '00_灰度机清单.md'
    "Three-Phase Plan" = Join-Path $scriptRoot '01_三阶段执行计划.md'
    "Installation Report Template" = Join-Path $scriptRoot '02_装机核验报告模板.md'
    "Metrics Collection Script" = Join-Path $scriptRoot 'Collect-CanaryMetrics.ps1'
    "Canary Executor" = Join-Path $scriptRoot 'Canary-Phase-Executor.ps1'
    "Release Verification Script" = Join-Path $scriptRoot 'Verify-Release.ps1'
}

foreach ($item in $requiredFiles.GetEnumerator()) {
    $exists = Test-Path $item.Value
    $result = Write-Status "$($item.Key): $($item.Value)" $exists
    $allChecksPassed = $allChecksPassed -and $result
}

# 2. Report Templates Check
Write-Section "Report Templates Check"

$reportTemplates = @{
    "Phase 1 Report Template" = Join-Path $scriptRoot 'reports\灰度阶段报告_一_模板.md'
    "Phase 2 Report Template" = Join-Path $scriptRoot 'reports\灰度阶段报告_二_模板.md'
    "Phase 3 Report Template" = Join-Path $scriptRoot 'reports\灰度阶段报告_三_模板.md'
    "Canary Test Startup Guide" = Join-Path $scriptRoot '灰度测试启动指南.md'
}

foreach ($item in $reportTemplates.GetEnumerator()) {
    $exists = Test-Path $item.Value
    $result = Write-Status "$($item.Key): $($item.Value)" $exists
    $allChecksPassed = $allChecksPassed -and $result
}

# 3. Installation Package Check
Write-Section "Installation Package Check"

$installerRoot = Split-Path $scriptRoot -Parent
$installerDir = Join-Path $installerRoot 'installer'
$payloadDir = Join-Path $installerDir 'payload'

$payloadExists = Test-Path $payloadDir
$payloadResult = Write-Status "Payload Directory Exists: $payloadDir" $payloadExists
$allChecksPassed = $allChecksPassed -and $payloadResult

if ($payloadExists) {
    $dllCount = (Get-ChildItem $payloadDir -Filter *.dll -Recurse).Count
    $manifestExists = Test-Path (Join-Path $payloadDir 'release_manifest.json')
    
    $dllColor = if ($dllCount -ge 50) { "Green" } else { "Yellow" }
    Write-Host "   - DLL File Count: $dllCount (Expected >= 50)" -ForegroundColor $dllColor
    $manifestResult = Write-Status "   - Manifest File Exists: release_manifest.json" $manifestExists
    $allChecksPassed = $allChecksPassed -and $manifestResult
    
    # Check Licensing DLL
    $licensingDll = Get-ChildItem $payloadDir -Filter "Winknow.Licensing.dll" -Recurse
    $licensingResult = Write-Status "   - Licensing DLL Exists: Winknow.Licensing.dll" ($licensingDll.Count -gt 0)
    $allChecksPassed = $allChecksPassed -and $licensingResult
}

# 4. Release Decision Checklist Check
Write-Section "Release Decision Checklist Check"

$docsDir = Join-Path $installerRoot 'docs'
$checklistPath = Join-Path $docsDir '发布决策检查单.md'

$checklistExists = Test-Path $checklistPath
$checklistResult = Write-Status "Release Decision Checklist Exists: $checklistPath" $checklistExists
$allChecksPassed = $allChecksPassed -and $checklistResult

if ($checklistExists) {
    $content = Get-Content $checklistPath -Raw -Encoding UTF8
    $hasPhaseCItems = $content -match "阶段C新增|授权验证功能正常|授权指标监控正常"
    $phaseCResult = Write-Status "   - Includes Stage C Authorization Items (3 items)" $hasPhaseCItems
    $allChecksPassed = $allChecksPassed -and $phaseCResult

    $totalItems = ([regex]::Matches($content, "^\|\s*\d+\s*\|", [System.Text.RegularExpressions.RegexOptions]::Multiline)).Count
    $itemsColor = if ($totalItems -ge 15) { "Green" } else { "Yellow" }
    Write-Host "   - Total Items: $totalItems (Expected 15 items)" -ForegroundColor $itemsColor
}

# 5. Canary Machine List Check
Write-Section "Canary Machine List Check"

$canaryList = Join-Path $scriptRoot '00_灰度机清单.md'
if (Test-Path $canaryList) {
    $content = Get-Content $canaryList -Raw
    $hasPhase1 = $content -match "T-01|T-02"
    $hasPhase2 = $content -match "S-01|S-02|S-03|S-04|S-05"
    $hasPhase3 = $content -match "S-06|S-n|10~20"
    
    $phase1Result = Write-Status "   - Phase 1 Machine Configuration (T-01,T-02)" $hasPhase1
    $phase2Result = Write-Status "   - Phase 2 Machine Configuration (S-01~S-05)" $hasPhase2
    $phase3Result = Write-Status "   - Phase 3 Machine Configuration (S-06~S-n)" $hasPhase3
    
    $allChecksPassed = $allChecksPassed -and $phase1Result -and $phase2Result -and $phase3Result
} else {
    Write-Status "Canary Machine List File Does Not Exist" $false
    $allChecksPassed = $false
}

# 6. Obfuscation Configuration Check
Write-Section "Obfuscation Configuration Check"

$obfuscarConfig = Join-Path $installerDir 'obfuscar.xml'
$obfuscarExists = Test-Path $obfuscarConfig
$obfuscarResult = Write-Status "Obfuscar Config Exists: $obfuscarConfig" $obfuscarExists
$allChecksPassed = $allChecksPassed -and $obfuscarResult

if ($obfuscarExists) {
    $content = Get-Content $obfuscarConfig -Raw
    $hasLicensing = $content -match "Winknow.Licensing.dll"
    $licensingObfResult = Write-Status "   - Includes Licensing Obfuscation Config" $hasLicensing
    $allChecksPassed = $allChecksPassed -and $licensingObfResult
}

# 7. Handover Document Check
Write-Section "Handover Document Check"

$handoverDoc = Join-Path $docsDir '会话交接_防破解与双模式方案.md'
$handoverExists = Test-Path $handoverDoc
$handoverResult = Write-Status "Handover Document Exists: $handoverDoc" $handoverExists
$allChecksPassed = $allChecksPassed -and $handoverResult

# 8. Script Execution Permission Check
Write-Section "Script Execution Permission Check"

$scriptFiles = @(
    (Join-Path $scriptRoot 'Collect-CanaryMetrics.ps1')
    (Join-Path $scriptRoot 'Canary-Phase-Executor.ps1')
    (Join-Path $scriptRoot 'Verify-Release.ps1')
    (Join-Path $scriptRoot 'Verify-CanaryReadiness.ps1')
)

$scriptsExecutable = $true
foreach ($script in $scriptFiles) {
    if (Test-Path $script) {
        $parseErrors = $null; $parseTokens = $null
        try {
            [void][System.Management.Automation.Language.Parser]::ParseFile($script, [ref]$parseTokens, [ref]$parseErrors)
            if ($parseErrors.Count -eq 0) {
                Write-Status "   - $([IO.Path]::GetFileName($script)) Syntax OK" $true
            } else {
                Write-Status "   - $([IO.Path]::GetFileName($script)) Syntax ERRORS: $($parseErrors[0].Message)" $false
                $scriptsExecutable = $false
            }
        } catch {
            Write-Status "   - $([IO.Path]::GetFileName($script)) Read Failed" $false
            $scriptsExecutable = $false
        }
    }
}

$allChecksPassed = $allChecksPassed -and $scriptsExecutable

# 9. Environment Requirements Check
Write-Section "Environment Requirements Check"

$hasDotnet = Get-Command dotnet -ErrorAction SilentlyContinue
$dotnetResult = Write-Status " .NET SDK Installed" ($null -ne $hasDotnet)
$allChecksPassed = $allChecksPassed -and $dotnetResult

if ($hasDotnet) {
    try {
        $dotnetVersion = dotnet --version 2>$null
        $verColor = if ($dotnetVersion -match "8\.") { "Green" } else { "Yellow" }
        Write-Host "   - Version: $dotnetVersion (Expected >= 8.0)" -ForegroundColor $verColor
    } catch {
        Write-Host "   - Version Retrieval Failed" -ForegroundColor Yellow
    }
}

# 10. Final Conclusion
Write-Section "Final Conclusion"

if ($allChecksPassed) {
    Write-Host "SUCCESS: All Canary Readiness Checks Passed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Ready to start canary testing:" -ForegroundColor Cyan
    Write-Host "  1. Review 'Canary Test Startup Guide.md'"
    Write-Host "  2. Fill in '00_灰度机清单.md'"
    Write-Host "  3. Execute: .\canary\Canary-Phase-Executor.ps1 -Stage 1 -Day 1"
    Write-Host ""
    Write-Host "Three-Phase Test Sequence:"
    Write-Host "  Phase 1: 2 machines x 2 days -> Phase 2: 5 machines x 2 days -> Phase 3: 10-20 machines x >=3 days"
} else {
    Write-Host "FAILED: Canary Readiness Checks Not Passed, Please Fix Issues Above." -ForegroundColor Red
    Write-Host ""
    Write-Host "Fix Suggestions:" -ForegroundColor Yellow
    Write-Host "  1. Confirm all required files exist"
    Write-Host "  2. Check Payload directory integrity"
    Write-Host "  3. Fill in canary machine list"
    Write-Host "  4. Verify script encoding format"
}

# Generate Check Report
$filesAllExist = (@($requiredFiles.Values | Where-Object { -not (Test-Path $_) })).Count -eq 0
$templatesAllExist = (@($reportTemplates.Values | Where-Object { -not (Test-Path $_) })).Count -eq 0
$checklistOk = ($checklistExists -and $hasPhaseCItems)
$canaryListOk = ($phase1Result -and $phase2Result -and $phase3Result)
$obfuscarOk = ($obfuscarExists -and $hasLicensing)

$reportPath = Join-Path $scriptRoot "reports\ReadinessCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').md"
$reportContent = @"
# Canary Readiness Check Report

Check Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Check Result: $(if ($allChecksPassed) { "PASS" } else { "FAIL" })

## Check Details

| Check Item | Status | Notes |
|------------|--------|-------|
| File Existence | $(if ($filesAllExist) { "PASS" } else { "FAIL" }) | All required files present |
| Report Templates | $(if ($templatesAllExist) { "PASS" } else { "FAIL" }) | Three-phase report templates complete |
| Installation Payload | $(if ($payloadExists) { "PASS" } else { "FAIL" }) | Includes Licensing DLL |
| Release Decision Checklist | $(if ($checklistOk) { "PASS" } else { "FAIL" }) | Includes 15 items (3 authorization) |
| Canary Machine List | $(if ($canaryListOk) { "PASS" } else { "FAIL" }) | Three-phase machine config complete |
| Obfuscation Config | $(if ($obfuscarOk) { "PASS" } else { "FAIL" }) | Obfuscar config correct |
| Handover Document | $(if ($handoverExists) { "PASS" } else { "FAIL" }) | Four-phase plan document exists |
| Script Execution | $(if ($scriptsExecutable) { "PASS" } else { "FAIL" }) | UTF-8 BOM encoding correct |
| .NET Environment | $(if ($hasDotnet) { "PASS" } else { "FAIL" }) | SDK installed |

## Next Steps

$(if ($allChecksPassed) {
@"
1. Fill in test preparation checklist in 'Canary Test Startup Guide.md'
2. Execute Phase 1 testing: `.\canary\Canary-Phase-Executor.ps1 -Stage 1 -Day 1`
3. Follow three-phase plan for sequential testing
4. Fill in each phase report template
5. Complete release decision checklist verification
"@
} else {
@"
Please fix the failed check items above and run this script again.
"@
})
"@

New-Item -ItemType Directory -Force -Path (Split-Path $reportPath) | Out-Null
$reportContent | Set-Content $reportPath -Encoding UTF8

Write-Host ""
Write-Host "Check report generated: $reportPath" -ForegroundColor Cyan

exit $(if ($allChecksPassed) { 0 } else { 1 })