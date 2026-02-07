#requires -version 5.1
<#
VC-Triage-AD.ps1
Read-only Active Directory triage collector (no RSAT required).

Designed for:
- Windows 10/11 domain-joined workstation
- No admin rights
- No RSAT / AD module

What it collects:
- Domain + forest basics (best-effort)
- Naming contexts (RootDSE)
- OU inventory and OU tree (recursive)
- Optional OU ACL/delegation snapshot (best-effort; may be limited by permissions)

Outputs (under -OutputDir):
- triage.log
- domain_forest.json
- naming_contexts.json
- ou_list.csv
- ou_list.json
- ou_tree.txt
- ou_acl.csv (if -IncludeAcls)

NOTE: ACL collection can be large in big domains. Use -AclLimit or -MaxOUs to cap.
#>

[CmdletBinding()]
param(
  [string]$OutputDir = (Join-Path (Get-Location).Path ("vc_ad_triage_{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss"))),
  [int]$MaxOUs = 0,              # 0 = no limit
  [int]$MaxDepth = 0,            # 0 = no limit (depth computed from DN)
  [switch]$IncludeAcls,
  [int]$AclLimit = 2000,         # cap number of OUs to ACL-scan (0 = no limit)
  [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Dir([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}

function Write-Log([string]$Msg, [ValidateSet("INFO","WARN","ERROR")][string]$Level="INFO") {
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $line = "[{0}][{1}] {2}" -f $ts,$Level,$Msg
  if (-not $script:Quiet) { Write-Host $line }
  Add-Content -Path $script:LogFile -Value $line
}

function Save-Json([object]$Obj, [string]$Path) {
  $json = $Obj | ConvertTo-Json -Depth 6
  Set-Content -Path $Path -Value $json -Encoding UTF8
}

function Try([scriptblock]$Block, [string]$OnFailMsg) {
  try { & $Block } catch {
    Write-Log ("{0} :: {1}" -f $OnFailMsg, $_.Exception.Message) "WARN"
    return $null
  }
}

function Get-RootDse {
  $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
  $props = $root.Properties
  [pscustomobject]@{
    defaultNamingContext         = [string]$props["defaultNamingContext"][0]
    configurationNamingContext   = [string]$props["configurationNamingContext"][0]
    schemaNamingContext          = [string]$props["schemaNamingContext"][0]
    rootDomainNamingContext      = [string]$props["rootDomainNamingContext"][0]
    dnsHostName                  = [string]$props["dnsHostName"][0]
    serverName                   = [string]$props["serverName"][0]
    supportedLDAPVersion         = @($props["supportedLDAPVersion"])
    supportedSASLMechanisms      = @($props["supportedSASLMechanisms"])
  }
}

function Get-DomainForestBasics {
  $info = [ordered]@{
    computerName   = $env:COMPUTERNAME
    userName       = $env:USERNAME
    userDomain     = $env:USERDOMAIN
    userDnsDomain  = $env:USERDNSDOMAIN
    timestamp      = (Get-Date).ToString("o")
  }

  $domainObj = Try { [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain() } "Could not read Domain via .NET"
  if ($domainObj) {
    $info.domain = [ordered]@{
      name = $domainObj.Name
      forest = $domainObj.Forest.Name
      domainMode = $domainObj.DomainMode.ToString()
      pdcRoleOwner = Try { $domainObj.PdcRoleOwner.Name } "Could not read PDC role owner"
      ridRoleOwner = Try { $domainObj.RidRoleOwner.Name } "Could not read RID role owner"
      infrastructureRoleOwner = Try { $domainObj.InfrastructureRoleOwner.Name } "Could not read Infrastructure role owner"
      domainControllers = Try { @($domainObj.DomainControllers | ForEach-Object { $_.Name }) } "Could not list DCs"
    }

    $forestObj = Try { $domainObj.Forest } "Could not read Forest via .NET"
    if ($forestObj) {
      $info.forest = [ordered]@{
        name = $forestObj.Name
        forestMode = $forestObj.ForestMode.ToString()
        rootDomain = $forestObj.RootDomain.Name
        domains = Try { @($forestObj.Domains | ForEach-Object { $_.Name }) } "Could not list forest domains"
        globalCatalogs = Try { @($forestObj.GlobalCatalogs | ForEach-Object { $_.Name }) } "Could not list GCs"
      }
    }
  } else {
    $info.domain = [ordered]@{ name = $env:USERDNSDOMAIN }
  }

  return [pscustomobject]$info
}

function Get-OUs([string]$BaseDN) {
  $searchRoot = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://{0}" -f $BaseDN))
  $ds = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
  $ds.PageSize = 1000
  $ds.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
  $ds.Filter = "(objectCategory=organizationalUnit)"
  $null = $ds.PropertiesToLoad.Add("distinguishedName")
  $null = $ds.PropertiesToLoad.Add("name")
  $null = $ds.PropertiesToLoad.Add("description")
  $null = $ds.PropertiesToLoad.Add("whenCreated")
  $null = $ds.PropertiesToLoad.Add("whenChanged")

  $results = $ds.FindAll()
  $ous = New-Object System.Collections.Generic.List[object]

  foreach ($r in $results) {
    $p = $r.Properties
    $dn = [string]$p["distinguishedname"][0]
    $name = if ($p["name"].Count -gt 0) { [string]$p["name"][0] } else { "" }

    $parent = ""
    if ($dn -match "^[^,]+,(.+)$") { $parent = $matches[1] }

    $ou = [pscustomobject]@{
      Name = $name
      DN = $dn
      ParentDN = $parent
      Description = if ($p["description"].Count -gt 0) { [string]$p["description"][0] } else { "" }
      WhenCreated = if ($p["whencreated"].Count -gt 0) { [string]$p["whencreated"][0] } else { "" }
      WhenChanged = if ($p["whenchanged"].Count -gt 0) { [string]$p["whenchanged"][0] } else { "" }
    }
    $ous.Add($ou) | Out-Null

    if ($MaxOUs -gt 0 -and $ous.Count -ge $MaxOUs) { break }
  }

  return $ous
}

function Get-DNDepth([string]$DN, [string]$BaseDN) {
  $dnLower = $DN.ToLowerInvariant()
  $baseLower = $BaseDN.ToLowerInvariant()
  if (-not $dnLower.EndsWith($baseLower)) { return 0 }

  $prefix = $dnLower.Substring(0, $dnLower.Length - $baseLower.Length).TrimEnd(",")
  if ([string]::IsNullOrWhiteSpace($prefix)) { return 0 }

  $parts = $prefix.Split(",")
  $ouCount = 0
  foreach ($p in $parts) {
    if ($p.Trim().StartsWith("ou=")) { $ouCount++ }
  }
  return $ouCount
}

function Build-OUTreeText([object[]]$OUs, [string]$BaseDN, [int]$MaxDepth) {
  $byParent = @{}
  foreach ($ou in $OUs) {
    if (-not $byParent.ContainsKey($ou.ParentDN)) { $byParent[$ou.ParentDN] = New-Object System.Collections.Generic.List[object] }
    $byParent[$ou.ParentDN].Add($ou) | Out-Null
  }

  function Walk([string]$ParentDN, [int]$Indent) {
    if (-not $byParent.ContainsKey($ParentDN)) { return @() }
    $children = $byParent[$ParentDN] | Sort-Object Name
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($c in $children) {
      $depth = Get-DNDepth -DN $c.DN -BaseDN $BaseDN
      if ($MaxDepth -gt 0 -and $depth -gt $MaxDepth) { continue }
      $lines.Add(("{0}{1}" -f ("  " * $Indent), $c.Name)) | Out-Null
      foreach ($ln in (Walk -ParentDN $c.DN -Indent ($Indent + 1))) { $lines.Add($ln) | Out-Null }
    }
    return $lines
  }

  $header = @(
    ("BaseDN: {0}" -f $BaseDN),
    ("Generated: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")),
    ""
  )

  $rootLines = Walk -ParentDN $BaseDN -Indent 0
  return @($header + $rootLines)
}

function Export-OUList([object[]]$OUs, [string]$CsvPath, [string]$JsonPath) {
  $OUs | Select-Object Name,DN,ParentDN,Description,WhenCreated,WhenChanged | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
  Save-Json -Obj $OUs -Path $JsonPath
}

function Export-OUAcls([object[]]$OUs, [string]$CsvPath, [int]$AclLimit) {
  "OUName,OUDN,IdentityReference,AccessControlType,ActiveDirectoryRights,IsInherited,InheritanceType,ObjectType,InheritedObjectType" |
    Set-Content -Path $CsvPath -Encoding UTF8

  $count = 0
  foreach ($ou in ($OUs | Sort-Object DN)) {
    $count++
    if ($AclLimit -gt 0 -and $count -gt $AclLimit) {
      Write-Log ("ACL scan limit reached: {0}" -f $AclLimit) "WARN"
      break
    }

    $entry = Try { New-Object System.DirectoryServices.DirectoryEntry(("LDAP://{0}" -f $ou.DN)) } ("ACL read failed (bind) for {0}" -f $ou.DN)
    if (-not $entry) { continue }

    $sec = Try { $entry.ObjectSecurity } ("ACL read failed (ObjectSecurity) for {0}" -f $ou.DN)
    if (-not $sec) { continue }

    $rules = Try { $sec.GetAccessRules($true, $true, [System.Security.Principal.NTAccount]) } ("ACL read failed (GetAccessRules) for {0}" -f $ou.DN)
    if (-not $rules) { continue }

    foreach ($r in $rules) {
      $line = '""{0}"",""{1}"",""{2}"",""{3}"",""{4}"",""{5}"",""{6}"",""{7}"",""{8}""' -f `
        ($ou.Name -replace '"','""'),
        ($ou.DN -replace '"','""'),
        ($r.IdentityReference.Value -replace '"','""'),
        ($r.AccessControlType.ToString() -replace '"','""'),
        ($r.ActiveDirectoryRights.ToString() -replace '"','""'),
        ($r.IsInherited.ToString() -replace '"','""'),
        ($r.InheritanceType.ToString() -replace '"','""'),
        ($r.ObjectType.ToString() -replace '"','""'),
        ($r.InheritedObjectType.ToString() -replace '"','""')
      Add-Content -Path $CsvPath -Value $line
    }
  }
}

# ---- MAIN ----
$script:Quiet = [bool]$Quiet
Ensure-Dir $OutputDir
$script:LogFile = Join-Path $OutputDir "triage.log"

Write-Log "Starting AD triage (read-only)."

$root = Get-RootDse
Write-Log ("RootDSE defaultNamingContext: {0}" -f $root.defaultNamingContext)
Save-Json -Obj $root -Path (Join-Path $OutputDir "naming_contexts.json")

$df = Get-DomainForestBasics
Save-Json -Obj $df -Path (Join-Path $OutputDir "domain_forest.json")

$baseDN = $root.defaultNamingContext
Write-Log "Enumerating OUs..."
$ous = Get-OUs -BaseDN $baseDN
Write-Log ("OUs found (capped): {0}" -f $ous.Count)

if ($MaxDepth -gt 0) {
  $ous = @($ous | Where-Object { (Get-DNDepth -DN $_.DN -BaseDN $baseDN) -le $MaxDepth })
  Write-Log ("OUs after MaxDepth filter: {0}" -f $ous.Count)
}

Export-OUList -OUs $ous -CsvPath (Join-Path $OutputDir "ou_list.csv") -JsonPath (Join-Path $OutputDir "ou_list.json")

$treeLines = Build-OUTreeText -OUs $ous -BaseDN $baseDN -MaxDepth $MaxDepth
Set-Content -Path (Join-Path $OutputDir "ou_tree.txt") -Value $treeLines -Encoding UTF8

if ($IncludeAcls) {
  Write-Log ("Collecting OU ACLs (limit={0})..." -f $AclLimit)
  Export-OUAcls -OUs $ous -CsvPath (Join-Path $OutputDir "ou_acl.csv") -AclLimit $AclLimit
  Write-Log "ACL collection complete."
} else {
  Write-Log "ACL collection skipped (use -IncludeAcls)."
}

Write-Log ("Done. OutputDir: {0}" -f $OutputDir)
Write-Host ""
Write-Host ("OutputDir: {0}" -f $OutputDir)

Write-Host ""
Write-Host "Optional: make PowerShell history persistent (like a real shell). Run once in your profile:"
Write-Host '  Install-Module PSReadLine -Scope CurrentUser -Force'
Write-Host '  New-Item -ItemType Directory -Force -Path "$env:APPDATA\PowerShell" | Out-Null'
Write-Host '  Add-Content -Path $PROFILE -Value "Set-PSReadLineOption -HistorySavePath `"$env:APPDATA\PowerShell\PSReadLine_history.txt`" -HistorySaveStyle SaveIncrementally"'
