#requires -version 5.1
<#
01-Create-OUStructure.ps1
Creates a scalable OU model:
- OU=_ORG
  - OU=_Global
    - OU=_GlobalResources (Groups, GroupsProtected, GroupsFSM, PublishedShares)
  - OU=AMERICAS/EMEA/APAC
    - OU=_DomainManagement (Administration, GPO-Staging, Quarantine)
    - OU=Sites
      - OU=<SiteCode>
        - standard leaf OUs (Clients, Servers, Users, Groups, etc.)
- OU=_Admin
  - Tier0/Tier1/Tier2 (AdminUsers, AdminGroups, PAWs, Servers)

Idempotent: does nothing if OUs already exist.
Requires: ActiveDirectory module (run on DC).
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [string[]]$Regions = @("AMERICAS","EMEA","APAC"),

  # If not provided, generates 10 site codes: LAB001..LAB010 (and assigns them across regions)
  [string[]]$SiteCodes = @(),

  [int]$SiteCount = 10,

  [string[]]$SiteLeafOUs = @(
    "Clients",
    "Servers",
    "Users",
    "Groups",
    "UsersAdministrative",
    "GroupsAdministrative",
    "GroupsProtected",
    "PublishedShares"
  ),

  [switch]$CreateTierAdminModel = $true,

  # Optionally protect top-level OUs from accidental deletion
  [switch]$ProtectTopLevelOUs = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Log([string]$Msg, [ValidateSet("INFO","WARN","ERROR")][string]$Level="INFO") {
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host ("[{0}][{1}] {2}" -f $ts,$Level,$Msg)
}

function Require-Module([string]$Name) {
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    throw "Required module '$Name' not found. Run this on a Domain Controller or install RSAT/AD tools."
  }
  Import-Module $Name -ErrorAction Stop
}

function Get-DomainInfo {
  $d = Get-ADDomain
  [pscustomobject]@{
    DNSRoot = $d.DNSRoot
    DistinguishedName = $d.DistinguishedName
  }
}

function Ensure-OU {
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][string]$ParentDN,
    [string]$Description = $null,
    [bool]$ProtectFromAccidentalDeletion = $false
  )

  $ouDn = "OU=$Name,$ParentDN"
  $existing = Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$ouDn)" -ErrorAction SilentlyContinue

  if ($existing) {
    Write-Log "Exists: $ouDn"
    return $ouDn
  }

  if ($PSCmdlet.ShouldProcess($ouDn, "Create OU")) {
    Write-Log "Create: $ouDn"
    $params = @{
      Name = $Name
      Path = $ParentDN
      ProtectedFromAccidentalDeletion = $ProtectFromAccidentalDeletion
    }
    if ($Description) { $params["Description"] = $Description }
    New-ADOrganizationalUnit @params | Out-Null
  }

  return $ouDn
}

function New-SiteCodes([int]$Count) {
  $codes = New-Object System.Collections.Generic.List[string]
  for ($i=1; $i -le $Count; $i++) {
    $codes.Add(("LAB{0:000}" -f $i)) | Out-Null
  }
  $codes
}

# ---- MAIN ----
Require-Module "ActiveDirectory"
$domain = Get-DomainInfo
Write-Log ("Domain: {0} | DN: {1}" -f $domain.DNSRoot, $domain.DistinguishedName)

if (-not $SiteCodes -or $SiteCodes.Count -eq 0) {
  $SiteCodes = @(New-SiteCodes -Count $SiteCount)
  Write-Log ("Generated {0} site codes: {1}" -f $SiteCodes.Count, ($SiteCodes -join ", "))
} else {
  if ($SiteCodes.Count -gt 10) {
    Write-Log "You provided more than 10 site codes; that's fine, but you said 'up to 10'. Continuing anyway." "WARN"
  }
}

# Top-level OUs
$orgRoot   = Ensure-OU -Name "_ORG"   -ParentDN $domain.DistinguishedName -Description "Organization boundary (policy + delegation)" -ProtectFromAccidentalDeletion:$ProtectTopLevelOUs
$adminRoot = Ensure-OU -Name "_Admin" -ParentDN $domain.DistinguishedName -Description "Tiered admin boundary" -ProtectFromAccidentalDeletion:$ProtectTopLevelOUs
$global    = Ensure-OU -Name "_Global" -ParentDN $orgRoot -Description "Shared/global resources" -ProtectFromAccidentalDeletion:$ProtectTopLevelOUs

# Global Resources (single place)
$globalResources = Ensure-OU -Name "_GlobalResources" -ParentDN $global -Description "Global shared groups/resources" -ProtectFromAccidentalDeletion:$ProtectTopLevelOUs
$null = Ensure-OU -Name "Groups"          -ParentDN $globalResources -Description "Global groups"
$null = Ensure-OU -Name "GroupsProtected" -ParentDN $globalResources -Description "Protected groups (high risk)"
$null = Ensure-OU -Name "GroupsFSM"       -ParentDN $globalResources -Description "File share management groups"
$null = Ensure-OU -Name "PublishedShares" -ParentDN $globalResources -Description "Share objects/metadata"

# Distribute site codes across regions (round-robin)
$regionSiteMap = @{}
for ($i=0; $i -lt $Regions.Count; $i++) { $regionSiteMap[$Regions[$i]] = @() }
for ($i=0; $i -lt $SiteCodes.Count; $i++) {
  $r = $Regions[$i % $Regions.Count]
  $regionSiteMap[$r] = @($regionSiteMap[$r] + $SiteCodes[$i])
}

foreach ($region in $Regions) {
  $regionDN = Ensure-OU -Name $region -ParentDN $orgRoot -Description "Region boundary"

  # Region management bucket
  $domainMgmt = Ensure-OU -Name "_DomainManagement" -ParentDN $regionDN -Description "Region admin/GPO staging/quarantine"
  $null = Ensure-OU -Name "Administration" -ParentDN $domainMgmt
  $null = Ensure-OU -Name "GPO-Staging"    -ParentDN $domainMgmt
  $null = Ensure-OU -Name "Quarantine"     -ParentDN $domainMgmt

  $sitesDN = Ensure-OU -Name "Sites" -ParentDN $regionDN -Description "Sites under region"

  $sites = @($regionSiteMap[$region])
  foreach ($site in $sites) {
    $siteDN = Ensure-OU -Name $site -ParentDN $sitesDN -Description "Site container"
    foreach ($leaf in $SiteLeafOUs) {
      $null = Ensure-OU -Name $leaf -ParentDN $siteDN -Description "Standard leaf OU"
    }
  }
}

if ($CreateTierAdminModel) {
  $tier0 = Ensure-OU -Name "Tier0" -ParentDN $adminRoot -Description "Tier0: identity, DCs, PKI"
  $tier1 = Ensure-OU -Name "Tier1" -ParentDN $adminRoot -Description "Tier1: servers"
  $tier2 = Ensure-OU -Name "Tier2" -ParentDN $adminRoot -Description "Tier2: workstations"

  foreach ($tierDN in @($tier0,$tier1,$tier2)) {
    $null = Ensure-OU -Name "AdminUsers"  -ParentDN $tierDN
    $null = Ensure-OU -Name "AdminGroups" -ParentDN $tierDN
    $null = Ensure-OU -Name "PAWs"        -ParentDN $tierDN
    $null = Ensure-OU -Name "Servers"     -ParentDN $tierDN
  }
}

Write-Log "OU structure creation complete."
