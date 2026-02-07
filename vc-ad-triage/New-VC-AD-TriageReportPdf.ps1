#requires -version 5.1
<#
New-VC-AD-TriageReportPdf.ps1
Generate a client-ready PDF report from VC AD triage output folder.

Uses QuestPDF (NuGet download on first run).
Layout: Microsoft-ish clean report with dark green accents.

InputDir should contain (best-effort):
- triage.log
- ou_tree.txt
- domain_forest.json
- naming_contexts.json
- ou_list.csv (optional)
- ou_acl.csv (optional)

Output:
- VC_AD_Triage_Report_<timestamp>.pdf in OutputDir (default: InputDir)
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$InputDir,

  [string]$OutputDir = $null,

  [string]$ClientName = "Client",

  [string]$CompanyName = "VERTEX CONSULTING HOLISTIC ADVISORY OPERATIONS SOLUTIONS, LLC",

  [string]$ReportTitle = "Active Directory Health Check + Triage Report",

  [int]$MaxOuTreeLines = 120,

  [switch]$IncludeAclsIfPresent
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info($m){ Write-Host ("[INFO] {0}" -f $m) }
function Ensure-Dir([string]$p){ if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null } }

function Pick {
  param(
    [Parameter(Mandatory=$false)][object]$Value,
    [Parameter(Mandatory=$true)][string]$Fallback
  )
  if ($null -eq $Value) { return $Fallback }
  if ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) { return $Fallback }
  return [string]$Value
}

function Read-LinesSafe([string]$path){
  if (Test-Path -LiteralPath $path) { return (Get-Content -LiteralPath $path -ErrorAction Stop) }
  return @()
}
function Read-JsonSafe([string]$path){
  if (Test-Path -LiteralPath $path) {
    $raw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
    if (-not [string]::IsNullOrWhiteSpace($raw)) { return ($raw | ConvertFrom-Json) }
  }
  return $null
}

function Get-NugetPackageDll {
  param(
    [Parameter(Mandatory=$true)][string]$PackageId,
    [Parameter(Mandatory=$true)][string]$Version,
    [Parameter(Mandatory=$true)][string]$DllRelativePath,
    [Parameter(Mandatory=$true)][string]$CacheDir
  )

  Ensure-Dir $CacheDir

  $pkgFile = Join-Path $CacheDir ("{0}.{1}.nupkg" -f $PackageId.ToLowerInvariant(), $Version)
  $extractDir = Join-Path $CacheDir ("{0}.{1}" -f $PackageId.ToLowerInvariant(), $Version)
  $dllPath = Join-Path $extractDir $DllRelativePath

  if (Test-Path -LiteralPath $dllPath) { return $dllPath }

  $url = "https://www.nuget.org/api/v2/package/$PackageId/$Version"
  Write-Info "Downloading $PackageId $Version from NuGet..."
  Invoke-WebRequest -Uri $url -OutFile $pkgFile -UseBasicParsing

  if (Test-Path -LiteralPath $extractDir) { Remove-Item $extractDir -Recurse -Force }
  Ensure-Dir $extractDir

  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::ExtractToDirectory($pkgFile, $extractDir)

  if (-not (Test-Path -LiteralPath $dllPath)) { throw "DLL not found after extract: $dllPath" }
  return $dllPath
}

function Ensure-QuestPdfLoaded {
  $cache = Join-Path $env:LOCALAPPDATA "VertexChaos\QuestPDF"
  $dll = Get-NugetPackageDll -PackageId "QuestPDF" -Version "2024.3.0" `
    -DllRelativePath "lib\netstandard2.0\QuestPDF.dll" -CacheDir $cache

  Write-Info "Loading QuestPDF from: $dll"
  Add-Type -Path $dll

  try { [QuestPDF.Settings]::License = [QuestPDF.Infrastructure.LicenseType]::Community } catch { }
}

function Invoke-QuestPdfGeneratePdf {
  param(
    [Parameter(Mandatory=$true)]$Document,
    [Parameter(Mandatory=$true)][string]$OutFile
  )

  $asm = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GetName().Name -eq "QuestPDF" } |
    Select-Object -First 1

  if (-not $asm) { throw "QuestPDF assembly not loaded. Ensure-QuestPdfLoaded failed." }

  $binding = [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static
  $method = $null

  foreach ($t in $asm.GetTypes()) {
    foreach ($m in $t.GetMethods($binding)) {
      if ($m.Name -ne "GeneratePdf") { continue }
      $p = $m.GetParameters()
      if ($p.Count -ne 2) { continue }
      if ($p[1].ParameterType -ne [string]) { continue }
      if ($p[0].ParameterType.IsInstanceOfType($Document)) {
        $method = $m
        break
      }
    }
    if ($method) { break }
  }

  if (-not $method) {
    foreach ($t in $asm.GetTypes()) {
      foreach ($m in $t.GetMethods($binding)) {
        if ($m.Name -ne "GeneratePdf") { continue }
        $p = $m.GetParameters()
        if ($p.Count -eq 2 -and $p[1].ParameterType -eq [string]) {
          $method = $m
          break
        }
      }
      if ($method) { break }
    }
  }

  if (-not $method) {
    throw "Could not locate a public static GeneratePdf(Document, string) method inside QuestPDF assembly."
  }

  $null = $method.Invoke($null, @($Document, $OutFile))
}

function Get-CountsFromLog {
  param([string[]]$Lines)

  $out = [ordered]@{
    RootDseDN = $null
    OuCount   = $null
    AclLimit  = $null
    OutputDir = $null
  }

  foreach ($ln in $Lines) {
    if (-not $out.RootDseDN -and $ln -match "RootDSE defaultNamingContext:\s*(.+)$") { $out.RootDseDN = $matches[1].Trim() }
    if (-not $out.OuCount   -and $ln -match "OUs found \(capped\):\s*(\d+)")        { $out.OuCount   = [int]$matches[1] }
    if (-not $out.AclLimit  -and $ln -match "ACL scan limit reached:\s*(\d+)")      { $out.AclLimit  = [int]$matches[1] }
    if (-not $out.OutputDir -and $ln -match "OutputDir:\s*(.+)$")                   { $out.OutputDir = $matches[1].Trim() }
  }

  [pscustomobject]$out
}

function Build-ReportData {
  param([string]$Dir)

  $triageLogPath   = Join-Path $Dir "triage.log"
  $ouTreePath      = Join-Path $Dir "ou_tree.txt"
  $domainForestPth = Join-Path $Dir "domain_forest.json"
  $namingPth       = Join-Path $Dir "naming_contexts.json"
  $ouListCsvPth    = Join-Path $Dir "ou_list.csv"
  $ouAclCsvPth     = Join-Path $Dir "ou_acl.csv"

  $logLines = Read-LinesSafe $triageLogPath
  $counts = Get-CountsFromLog -Lines $logLines

  $df = Read-JsonSafe $domainForestPth
  $nc = Read-JsonSafe $namingPth

  $ouTreeLines = Read-LinesSafe $ouTreePath
  if ($MaxOuTreeLines -gt 0 -and $ouTreeLines.Count -gt $MaxOuTreeLines) {
    $ouTreeLines = $ouTreeLines[0..($MaxOuTreeLines-1)] + "... (truncated)"
  }

  $ouListCount = $null
  if (Test-Path -LiteralPath $ouListCsvPth) {
    try { $ouListCount = (Import-Csv -LiteralPath $ouListCsvPth | Measure-Object).Count } catch { $ouListCount = $null }
  }

  $aclPresent = (Test-Path -LiteralPath $ouAclCsvPth)

  [pscustomobject]@{
    Paths = [pscustomobject]@{
      TriageLog   = $triageLogPath
      OuTree      = $ouTreePath
      DomainForest= $domainForestPth
      Naming      = $namingPth
      OuListCsv   = $ouListCsvPth
      OuAclCsv    = $ouAclCsvPth
    }
    Counts = $counts
    DomainForest = $df
    NamingContexts = $nc
    OuTreeLines = $ouTreeLines
    OuListCount = $ouListCount
    AclPresent = $aclPresent
  }
}

function New-PdfReport {
  param(
    [Parameter(Mandatory=$true)][object]$Data,
    [Parameter(Mandatory=$true)][string]$OutFile
  )

  $C_DarkGreen = "#0B3D2E"
  $C_Green     = "#107C41"
  $C_Text      = "#111827"
  $C_Muted     = "#6B7280"
  $C_Border    = "#E5E7EB"
  $C_SoftBg    = "#F6F7F9"
  $C_ChipBg    = "#E8F3EC"
  $C_ChipText  = "#0B3D2E"

  $today = (Get-Date).ToString("yyyy-MM-dd")
  $tsLong = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

  $domainName = $null
  $forestName = $null
  $domainMode = $null
  $dcList = @()

  if ($Data.DomainForest -and $Data.DomainForest.domain) {
    $domainName = $Data.DomainForest.domain.name
    $forestName = $Data.DomainForest.domain.forest
    $domainMode = $Data.DomainForest.domain.domainMode
    $dcList = @($Data.DomainForest.domain.domainControllers)
  }

  $rootDn = $Data.Counts.RootDseDN
  if (-not $rootDn -and $Data.NamingContexts -and $Data.NamingContexts.defaultNamingContext) {
    $rootDn = $Data.NamingContexts.defaultNamingContext
  }

  $ouCount = $Data.Counts.OuCount
  if (-not $ouCount -and $Data.OuListCount) { $ouCount = $Data.OuListCount }

  $aclNote = "Not collected"
  if ($IncludeAclsIfPresent -and $Data.AclPresent) {
    if ($Data.Counts.AclLimit) { $aclNote = "Collected (sample cap: $($Data.Counts.AclLimit))" }
    else { $aclNote = "Collected (sample)" }
  }

  $topFindings = @(
    "Admin tier model detected (Tier0/1/2). Value comes from enforcement: PAWs, logon restrictions, group hygiene.",
    "Delegation drift is common in large domains. Expand ACL review on admin + domain management + site user/group branches.",
    "Standardize OU naming/ownership and document OU contract (ownership, lifecycle, and guardrails).",
    "Validate GPO design and inheritance boundaries; confirm staging/quarantine processes and link order.",
    "If replication/DC health is in scope, run expanded health collection (optional) for deeper diagnostics."
  )

  $fixOrder = @(
    "Confirm tier enforcement (admin accounts/groups, PAWs, interactive logon/RDP boundaries).",
    "Review delegation hotspots (ACLs) in admin and domain management branches; then per-site Users/Groups.",
    "Normalize OU naming + ownership rules and document OU contract.",
    "Review GPO lifecycle (staging/quarantine), inheritance, and link precedence.",
    "Optional: expanded DC/replication health collection for deeper validation."
  )

  $Section = {
    param($container, [string]$title, [scriptblock]$contentBlock)

    $container.Column([System.Action[QuestPDF.Fluent.IColumn]]{
      param($col)

      $col.Item().Row([System.Action[QuestPDF.Fluent.IRow]]{
        param($r)
        $r.ConstantItem(4).Background($C_Green) | Out-Null
        $r.RelativeItem().PaddingLeft(10).Text($title).FontSize(12).SemiBold().FontColor($C_Text) | Out-Null
      }) | Out-Null

      $col.Item().PaddingTop(6).Element([System.Func[QuestPDF.Fluent.IContainer, QuestPDF.Fluent.IContainer]]{
        param($c)
        & $contentBlock $c
        return $c
      }) | Out-Null
    }) | Out-Null
  }

  $safeDomain = Pick $domainName "Unknown"
  $safeOuCount = Pick $ouCount "N/A"
  $aclChip = "No"
  if ($IncludeAclsIfPresent -and $Data.AclPresent) { $aclChip = "Yes" }

  $Document = [QuestPDF.Fluent.Document]::Create([System.Action[QuestPDF.Infrastructure.IDocumentContainer]]{
    param($container)

    $container.Page([System.Action[QuestPDF.Fluent.IPage]]{
      param($page)

      $page.Size([QuestPDF.Infrastructure.PageSizes]::Letter) | Out-Null
      $page.Margin(36) | Out-Null

      $page.DefaultTextStyle([System.Action[QuestPDF.Infrastructure.TextStyle]]{
        param($t)
        $t.FontSize(10) | Out-Null
        $t.FontFamily("Segoe UI") | Out-Null
        $t.FontColor($C_Text) | Out-Null
      }) | Out-Null

      $page.Header([System.Action[QuestPDF.Fluent.IContainer]]{
        param($h)

        $h.Background($C_DarkGreen).Padding(16).Column([System.Action[QuestPDF.Fluent.IColumn]]{
          param($col)

          $col.Item().Text($ReportTitle).FontSize(18).SemiBold().FontColor("White") | Out-Null
          $col.Item().Text(("Prepared for: {0}   |   Date: {1}   |   Generated: {2}" -f $ClientName, $today, $tsLong)).FontSize(9).FontColor("#D1FAE5") | Out-Null

          $col.Item().PaddingTop(6).Row([System.Action[QuestPDF.Fluent.IRow]]{
            param($r)
            $r.Spacing(8) | Out-Null

            $r.AutoItem().Background("#0F5132").PaddingVertical(4).PaddingHorizontal(8).BorderRadius(3).
              Text(("Domain: {0}" -f $safeDomain)).FontSize(9).FontColor("White") | Out-Null

            $r.AutoItem().Background("#0F5132").PaddingVertical(4).PaddingHorizontal(8).BorderRadius(3).
              Text(("OUs: {0}" -f $safeOuCount)).FontSize(9).FontColor("White") | Out-Null

            $r.AutoItem().Background("#0F5132").PaddingVertical(4).PaddingHorizontal(8).BorderRadius(3).
              Text(("ACLs: {0}" -f $aclChip)).FontSize(9).FontColor("White") | Out-Null
          }) | Out-Null
        }) | Out-Null
      }) | Out-Null

      $page.Content([System.Action[QuestPDF.Fluent.IContainer]]{
        param($c)

        $c.PaddingTop(14).Column([System.Action[QuestPDF.Fluent.IColumn]]{
          param($col)
          $col.Spacing(14) | Out-Null

          $col.Item().Background($C_SoftBg).Border(1).BorderColor($C_Border).Padding(12).Column([System.Action[QuestPDF.Fluent.IColumn]]{
            param($b)
            $b.Spacing(6) | Out-Null
            $b.Item().Text("Executive Summary").FontSize(12).SemiBold() | Out-Null
            $b.Item().Text("This report is based on a read-only triage package you ran locally and provided for review. The goal is to highlight the highest-impact risks first, separate quick wins from longer remediation work, and provide a clear fix order.").FontSize(10) | Out-Null
          }) | Out-Null

          $col.Item().Element([System.Func[QuestPDF.Fluent.IContainer, QuestPDF.Fluent.IContainer]]{
            param($x)
            & $Section $x "Snapshot" {
              param($sec)

              $safeForest = Pick $forestName "Unknown / not provided"
              $safeMode = Pick $domainMode "Unknown / not provided"
              $safeRoot = Pick $rootDn "Unknown / not provided"
              $safeOuInv = if ($ouCount) { ("{0} OUs (capped/filtered)" -f $ouCount) } else { "Not available" }

              $sec.Background("White").Border(1).BorderColor($C_Border).Padding(10).Table([System.Action[QuestPDF.Fluent.ITable]]{
                param($t)
                $t.ColumnsDefinition([System.Action[QuestPDF.Fluent.IColumnsDefinition]]{
                  param($cd)
                  $cd.ConstantColumn(190) | Out-Null
                  $cd.RelativeColumn() | Out-Null
                }) | Out-Null

                function AddRow($k,$v){
                  $t.Cell().BorderBottom(1).BorderColor($C_Border).PaddingVertical(6).PaddingHorizontal(6).
                    Text($k).SemiBold().FontColor($C_Muted) | Out-Null
                  $t.Cell().BorderBottom(1).BorderColor($C_Border).PaddingVertical(6).PaddingHorizontal(6).
                    Text($v) | Out-Null
                }

                AddRow "Domain" $safeDomain
                AddRow "Forest" $safeForest
                AddRow "Domain Mode" $safeMode
                AddRow "Default Naming Context" $safeRoot
                AddRow "OU Inventory" $safeOuInv
                AddRow "OU ACL Sampling" $aclNote
                AddRow "Artifacts Reviewed" "ou_tree.txt, ou_list.csv/json, domain_forest.json, triage.log (and ou_acl.csv if present)"
              }) | Out-Null
            }
            return $x
          }) | Out-Null

          if ($dcList -and $dcList.Count -gt 0) {
            $col.Item().Element([System.Func[QuestPDF.Fluent.IContainer, QuestPDF.Fluent.IContainer]]{
              param($x)
              & $Section $x "Domain Controllers (as reported)" {
                param($sec)
                $sec.Background("White").Border(1).BorderColor($C_Border).Padding(10).
                  Text(("- " + ($dcList -join "`n- "))).FontSize(10) | Out-Null
              }
              return $x
            }) | Out-Null
          }

          $col.Item().Row([System.Action[QuestPDF.Fluent.IRow]]{
            param($r)
            $r.Spacing(12) | Out-Null

            $r.RelativeItem().Element([System.Func[QuestPDF.Fluent.IContainer, QuestPDF.Fluent.IContainer]]{
              param($x)
              & $Section $x "Top Findings (prioritized)" {
                param($sec)
                $sec.Background("White").Border(1).BorderColor($C_Border).Padding(10).
                  Text(("- " + ($topFindings -join "`n- "))).FontSize(10) | Out-Null
              }
              return $x
            }) | Out-Null

            $r.RelativeItem().Element([System.Func[QuestPDF.Fluent.IContainer, QuestPDF.Fluent.IContainer]]{
              param($x)
              & $Section $x "Recommended Fix Order" {
                param($sec)
                $sec.Background("White").Border(1).BorderColor($C_Border).Padding(10).
                  Text(("- " + ($fixOrder -join "`n- "))).FontSize(10) | Out-Null
              }
              return $x
            }) | Out-Null
          }) | Out-Null

          if ($Data.OuTreeLines -and $Data.OuTreeLines.Count -gt 0) {
            $col.Item().Element([System.Func[QuestPDF.Fluent.IContainer, QuestPDF.Fluent.IContainer]]{
              param($x)
              & $Section $x "OU Tree (excerpt)" {
                param($sec)
                $sec.Background("White").Border(1).BorderColor($C_Border).Padding(10).Column([System.Action[QuestPDF.Fluent.IColumn]]{
                  param($cc)
                  $cc.Item().Background($C_SoftBg).Border(1).BorderColor($C_Border).Padding(8).
                    Text(($Data.OuTreeLines -join "`n")).FontSize(8).FontFamily("Consolas") | Out-Null
                  $cc.Item().PaddingTop(6).
                    Text("Note: excerpt is truncated for readability. Full OU list is available in ou_list.csv/json.").FontSize(9).FontColor($C_Muted) | Out-Null
                }) | Out-Null
              }
              return $x
            }) | Out-Null
          }

          $col.Item().Element([System.Func[QuestPDF.Fluent.IContainer, QuestPDF.Fluent.IContainer]]{
            param($x)
            & $Section $x "What I need from you" {
              param($sec)
              $sec.Background("White").Border(1).BorderColor($C_Border).Padding(10).Text(
                "• The triage output folder contents (no ZIP required).`n" +
                "• Confirm scope: forest/domain count, regions, and target pain points.`n" +
                "• Any recent changes/incidents and current priorities.`n" +
                "• If approved: expanded ACL capture on key OU branches (admin/domain mgmt/sites)."
              ).FontSize(10) | Out-Null
            }
            return $x
          }) | Out-Null

          $col.Item().Background($C_ChipBg).Border(1).BorderColor("#CFE7D7").Padding(10).Row([System.Action[QuestPDF.Fluent.IRow]]{
            param($r)
            $r.ConstantItem(4).Background($C_Green) | Out-Null
            $r.RelativeItem().PaddingLeft(10).Column([System.Action[QuestPDF.Fluent.IColumn]]{
              param($cc)
              $cc.Item().Text("Privacy-first collection").SemiBold().FontColor($C_ChipText) | Out-Null
              $cc.Item().Text("Designed to minimize sensitive data: no passwords, no mailbox content, no network dumps. ACL/delegation visibility depends on permissions; you can redact names before sharing.").FontSize(10).FontColor($C_Text) | Out-Null
            }) | Out-Null
          }) | Out-Null
        }) | Out-Null
      }) | Out-Null

      $page.Footer([System.Action[QuestPDF.Fluent.IContainer]]{
        param($f)
        $f.PaddingTop(10).Row([System.Action[QuestPDF.Fluent.IRow]]{
          param($r)
          $r.RelativeItem().Text($CompanyName).FontSize(9).FontColor($C_Muted) | Out-Null
          $r.AutoItem().Text("Confidential. Client-facing triage summary.").FontSize(9).FontColor($C_Muted) | Out-Null
        }) | Out-Null
      }) | Out-Null
    }) | Out-Null
  })

  Write-Info "Generating PDF: $OutFile"
  Invoke-QuestPdfGeneratePdf -Document $Document -OutFile $OutFile
}

if (-not (Test-Path -LiteralPath $InputDir)) { throw "InputDir not found: $InputDir" }
if (-not $OutputDir) { $OutputDir = $InputDir }
Ensure-Dir $OutputDir

Ensure-QuestPdfLoaded

$data = Build-ReportData -Dir $InputDir

$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$outPdf = Join-Path $OutputDir ("VC_AD_Triage_Report_{0}.pdf" -f $ts)

New-PdfReport -Data $data -OutFile $outPdf

Write-Host ""
Write-Host "Done."
Write-Host "PDF: $outPdf"
