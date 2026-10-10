[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$ReleaseRoot)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ReleaseRoot -PathType Container)) {
    throw "Flutter Release directory does not exist: $ReleaseRoot"
}
$requiredFiles = @(
    'bfs_learn.exe',
    'flutter_windows.dll',
    'url_launcher_windows_plugin.dll',
    'data\icudtl.dat',
    'data\app.so'
)
foreach ($relativeFile in $requiredFiles) {
    $filePath = Join-Path $ReleaseRoot $relativeFile
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf) -or (Get-Item -LiteralPath $filePath).Length -eq 0) {
        throw "Flutter Release is incomplete: missing or empty $relativeFile"
    }
}
$assetRoot = Join-Path $ReleaseRoot 'data\flutter_assets'
$hasManifest = (Test-Path -LiteralPath (Join-Path $assetRoot 'AssetManifest.bin') -PathType Leaf) -or
    (Test-Path -LiteralPath (Join-Path $assetRoot 'AssetManifest.json') -PathType Leaf)
if (-not $hasManifest) { throw 'Flutter Release is incomplete: no Flutter asset manifest' }
foreach ($assetFile in @('assets\data\knowledge_content\content_index.json', 'assets\data\knowledge_content\item_part_index.json')) {
    if (-not (Test-Path -LiteralPath (Join-Path $assetRoot $assetFile) -PathType Leaf)) {
        throw "Flutter Release is incomplete: missing learning asset $assetFile"
    }
}
Write-Output "Validated Flutter Release: $ReleaseRoot"
