# bootstrap.ps1
# VC-Triage bootstrapper (PowerShell 5.1+)
# Downloads vc-triage toolkit from GitHub (no Git required), runs triage + PDF generator.

[CmdletBinding()]
param(
  [string]$RepoOwner = "vertexchaos",
  [string]$RepoName  = "vc-triage",
  [string]$Branch    = "main",
  [string]$WorkDir   = (Join-Path $env:TEMP ("vc-triage_" + (Get-Date -Format "yyyyMMdd-HHmmss"))),
  [switch]$IncludeAcls,
  [int]$AclLimit = 30,
  [int]$MaxDepth = 6,
  [int]$MaxOUs = 5000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Log([string]$Level, [string]$Msg) {
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[$ts][$Level] $Msg"
}

function Ensure-Tls {
  try {
    # PS 5.1 defaults can be crusty; force TLS 1.2+
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor `
      [Net.SecurityProtocolType]::Tls11 -bor `
      [Net.SecurityProtocolType]::Tls
  } catch { }
}

function Download-File([string]$Url, [string]$OutFile) {
  Ensure-Tls
  Write-Log "INFO" "Downloading: $Url"
  Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $OutFile
}

# --- Main
Write-Log "INFO" "WorkDir: $WorkDir"
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

$zipUrl  = "https://github.com/$RepoOwner/$RepoName/archive/refs/heads/$Branch.zip"
$zipPath = Join-Path $WorkDir "$RepoName-$Branch.zip"
Download-File -Url $zipUrl -OutFile $zipPath

Write-Log "INFO" "Extracting toolkit..."
Expand-Archive -Path $zipPath -DestinationPath $WorkDir -Force

$root = Join-Path $WorkDir "$RepoName-$Branch"
if (-not (Test-Path $root)) { throw "Expected extracted folder not found: $root" }

# Your repo currently contains scripts at root and also a vc-ad-triage\ folder.
# Prefer the clean toolkit folder if present, else fallback to repo root.
$toolkit = Join-Path $root "vc-ad-triage"
if (-not (Test-Path $toolkit)) { $toolkit = $root }

Write-Log "INFO" "ToolkitDir: $toolkit"
Set-Location $toolkit

$triage = Join-Path $toolkit "00-VC-Triage-AD.ps1"
$pdfgen = Join-Path $toolkit "New-VC-AD-TriageReportPdf.ps1"

if (-not (Test-Path $triage)) { throw "Missing triage script: $triage" }
if (-not (Test-Path $pdfgen)) { throw "Missing PDF generator: $pdfgen" }

Write-Log "INFO" "Running triage (read-only)..."
& $triage -MaxDepth $MaxDepth -MaxOUs $MaxOUs -IncludeAcls:$IncludeAcls -AclLimit $AclLimit

# find latest triage output folder
$outDir = Join-Path $toolkit "out"
if (-not (Test-Path $outDir)) { $outDir = $toolkit }

$run = Get-ChildItem -Directory $outDir -Filter "vc_ad_triage_*" -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1

if (-not $run) {
  # fallback: maybe triage wrote to current directory
  $run = Get-ChildItem -Directory . -Filter "vc_ad_triage_*" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
}
if (-not $run) { throw "Could not find triage output folder vc_ad_triage_*" }

Write-Log "INFO" "Generating PDF report from: $($run.FullName)"
& $pdfgen -InputDir $run.FullName -IncludeAclsIfPresent:$IncludeAcls

Write-Log "INFO" "Done."
Write-Host ""
Write-Host "OUTPUT FOLDER:" $run.FullName
Write-Host "Share the ZIP (triage output) and PDF in that folder with Vertex Chaos."
