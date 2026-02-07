#requires -version 5.1
<#
02-Import-Users-And-Groups.ps1
Imports users from FakeNameGenerator CSV into the OU model created by 01-Create-OUStructure.ps1.

- Idempotent: skips existing users by SamAccountName.
- Random secure passwords (24+ chars) per user, exported to output CSV for lab use.
- Creates a few sane groups and adds users.

Requires: ActiveDirectory module (run on DC as Administrator).
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory=$true)]
  [string]$CsvPath,

  # Max number of users to import from the CSV (default: all rows)
  [int]$MaxUsers = 0,

  # Pick up to this many sites (randomly) to distribute users into
  [int]$MaxSites = 10,

  # If set, update attributes for existing users (still idempotent, but modifies)
  [switch]$UpdateExisting = $false,

  # Output folder for logs and password export
  [string]$OutputDir = (Join-Path (Get-Location).Path ("ad_import_{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss")))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Dir([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}

function Write-Log([string]$Msg, [ValidateSet("INFO","WARN","ERROR")][string]$Level="INFO") {
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $line = "[{0}][{1}] {2}" -f $ts,$Level,$Msg
  Write-Host $line
  Add-Content -Path $script:LogFile -Value $line
}

function Require-Module([string]$Name) {
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    throw "Required module '$Name' not found. Run on a Domain Controller or install RSAT."
  }
  Import-Module $Name -ErrorAction Stop
}

function New-SecurePassword {
  param([int]$Length = 24)

  if ($Length -lt 24) { $Length = 24 }

  $upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
  $lower = "abcdefghijkmnopqrstuvwxyz"
  $digits = "23456789"
  $special = "!@#$%^&*()-_=+[]{}:,.?"

  $all = ($upper + $lower + $digits + $special).ToCharArray()

  # guarantee at least 1 from each set
  $chars = New-Object System.Collections.Generic.List[char]
  $rand = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

  function Pick([string]$set) {
    $bytes = New-Object byte[] 4
    $rand.GetBytes($bytes)
    $idx = [BitConverter]::ToUInt32($bytes,0) % $set.Length
    $set[$idx]
  }

  $chars.Add((Pick $upper)) | Out-Null
  $chars.Add((Pick $lower)) | Out-Null
  $chars.Add((Pick $digits)) | Out-Null
  $chars.Add((Pick $special)) | Out-Null

  while ($chars.Count -lt $Length) {
    $bytes = New-Object byte[] 4
    $rand.GetBytes($bytes)
    $idx = [BitConverter]::ToUInt32($bytes,0) % $all.Length
    $chars.Add($all[$idx]) | Out-Null
  }

  # shuffle
  for ($i = $chars.Count - 1; $i -gt 0; $i--) {
    $bytes = New-Object byte[] 4
    $rand.GetBytes($bytes)
    $j = [BitConverter]::ToUInt32($bytes,0) % ($i + 1)
    $tmp = $chars[$i]
    $chars[$i] = $chars[$j]
    $chars[$j] = $tmp
  }

  -join $chars
}

function Ensure-ADGroup {
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][string]$PathDN,
    [ValidateSet("Global","Universal","DomainLocal")][string]$Scope = "Global",
    [ValidateSet("Security","Distribution")][string]$Category = "Security",
    [string]$Description = $null
  )

  # Search by Name in the intended OU
  $existing = Get-ADGroup -Filter "Name -eq '$Name'" -SearchBase $PathDN -SearchScope OneLevel -Properties DistinguishedName -ErrorAction SilentlyContinue
  if ($existing) {
    Write-Log "Group exists: $Name"
    return [string]$existing.DistinguishedName
  }

  if ($PSCmdlet.ShouldProcess($Name, "Create group in $PathDN")) {
    Write-Log "Create group: $Name (Path=$PathDN)"

    # SamAccountName limit is 20 chars. Keep it deterministic and safe.
    $sam = if ($Name.Length -le 20) { $Name } else { $Name.Substring(0,20) }

    $params = @{
      Name          = $Name
      SamAccountName= $sam
      GroupScope    = $Scope
      GroupCategory = $Category
      Path          = $PathDN
      PassThru      = $true
    }
    if ($Description) { $params["Description"] = $Description }

    $g = New-ADGroup @params
    if (-not $g -or -not $g.DistinguishedName) {
      # Defensive: re-read in case AD cmdlet output is weird
      $g2 = Get-ADGroup -Identity $Name -SearchBase $PathDN -SearchScope Subtree -Properties DistinguishedName -ErrorAction Stop
      return [string]$g2.DistinguishedName
    }

    return [string]$g.DistinguishedName
  }

  return $null
}


# ---- MAIN ----
if (-not (Test-Path -LiteralPath $CsvPath)) { throw "CSV not found: $CsvPath" }

Ensure-Dir $OutputDir
$script:LogFile = Join-Path $OutputDir "import.log"
$pwOut = Join-Path $OutputDir "created_users_passwords.csv"
$resultsOut = Join-Path $OutputDir "import_results.csv"

Require-Module "ActiveDirectory"

$domain = Get-ADDomain
$domainDN = $domain.DistinguishedName
$dnsRoot = $domain.DNSRoot

Write-Log ("Domain: {0} | DN: {1}" -f $dnsRoot, $domainDN)

# Locate the OU model root
$orgRootDN = "OU=_ORG,$domainDN"
$globalResourcesDN = "OU=_GlobalResources,OU=_Global,$orgRootDN"
$globalGroupsDN = "OU=Groups,$globalResourcesDN"

# Find site "Users" OUs by name, then filter by DN pattern in PowerShell (LDAP wildcards in DN are not a thing)
$siteUsersOUs = Get-ADOrganizationalUnit -SearchBase $orgRootDN -SearchScope Subtree -Filter 'Name -eq "Users"' -ErrorAction SilentlyContinue |
  Where-Object { $_.DistinguishedName -like "OU=Users,OU=*,OU=Sites,OU=*,OU=_ORG,*" }


if (-not $siteUsersOUs -or $siteUsersOUs.Count -eq 0) {
  throw "No site Users OUs found under $orgRootDN. Run 01-Create-OUStructure.ps1 first."
}

# Pick up to MaxSites randomly
$rand = New-Object System.Random
$siteUsersOUs = @($siteUsersOUs | Sort-Object DistinguishedName)
$pickCount = [Math]::Min($MaxSites, $siteUsersOUs.Count)
$selectedSites = @($siteUsersOUs | Get-Random -Count $pickCount)

Write-Log ("Found site Users OUs: {0} | Selected: {1}" -f $siteUsersOUs.Count, $selectedSites.Count)

# Create global groups
Ensure-Dir $OutputDir
$gAllEmployees = Ensure-ADGroup -Name "ALL-EMPLOYEES" -PathDN $globalGroupsDN -Description "Lab: all users"
$gVpnUsers     = Ensure-ADGroup -Name "VPN-USERS"     -PathDN $globalGroupsDN -Description "Lab: VPN users"

# Create per-site groups and map site -> group DN
$siteGroupMap = @{}
foreach ($ou in $selectedSites) {
  # Extract site code from DN: OU=Users,OU=<Site>,OU=Sites,...
  $dnParts = $ou.DistinguishedName -split ","
  $sitePart = $dnParts[1] # OU=<Site>
  $siteCode = $sitePart -replace "^OU=",""

  $siteDn = $dnParts[1..($dnParts.Length-1)] -join "," # not used
  # Site Groups OU is sibling of Users: OU=Groups,OU=<Site>,...
  $siteGroupsDN = "OU=Groups,OU=$siteCode,OU=Sites," + ($dnParts[3..($dnParts.Length-1)] -join ",")  # OU=Sites,OU=Region,OU=_ORG,DC=...

  # Ensure site Groups OU exists (it should from script A)
  $siteGroupsOU = Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$siteGroupsDN)" -ErrorAction SilentlyContinue
  if (-not $siteGroupsOU) {
    Write-Log "WARNING: Expected site Groups OU missing: $siteGroupsDN. Skipping site groups for $siteCode" "WARN"
    continue
  }

  $siteAll = Ensure-ADGroup -Name ("SITE-{0}-ALLUSERS" -f $siteCode) -PathDN $siteGroupsDN -Description "Lab: all users in site $siteCode"
  $siteHd  = Ensure-ADGroup -Name ("SITE-{0}-HELPDESK" -f $siteCode) -PathDN $siteGroupsDN -Description "Lab: helpdesk for site $siteCode"

  $siteGroupMap[$ou.DistinguishedName] = @{
    SiteCode = $siteCode
    AllUsersGroupDN = $siteAll
    HelpdeskGroupDN = $siteHd
  }
}

# Load CSV
Write-Log "Loading CSV..."
$rows = Import-Csv -Path $CsvPath
if ($MaxUsers -gt 0) { $rows = @($rows | Select-Object -First $MaxUsers) }

Write-Log ("CSV rows loaded: {0}" -f (($rows | Measure-Object).Count))

# Preload existing users (for fast idempotency)
Write-Log "Preloading existing SamAccountNames (may take a moment)..."
$existingSams = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
Get-ADUser -Filter * -Properties SamAccountName -ResultSetSize $null | ForEach-Object {
  if ($_.SamAccountName) { [void]$existingSams.Add($_.SamAccountName) }
}
Write-Log ("Existing users indexed: {0}" -f $existingSams.Count)

# Prepare outputs
"SamAccountName,UserPrincipalName,Enabled,TargetOU,Password,Action,Message" | Set-Content -Path $pwOut -Encoding UTF8
"SamAccountName,Action,Message" | Set-Content -Path $resultsOut -Encoding UTF8

# Import loop
$userCount = 0
foreach ($r in $rows) {
  $userCount++
  if ($userCount % 2000 -eq 0) { Write-Log ("Progress: {0}" -f $userCount) }

  $sam = [string]$r.Username
  if ([string]::IsNullOrWhiteSpace($sam)) {
    Add-Content -Path $resultsOut -Value ",SKIP,Missing Username"
    continue
  }

  # Choose a site OU randomly from selectedSites
  $targetUsersOU = $selectedSites[$rand.Next(0, $selectedSites.Count)].DistinguishedName
  $siteMeta = $siteGroupMap[$targetUsersOU]

  $email = [string]$r.EmailAddress
  $upn = if ($email -and $email.Contains("@")) { $email } else { ("{0}@{1}" -f $sam, $dnsRoot) }

  $displayName = ("{0} {1}" -f $r.GivenName, $r.Surname).Trim()
  $name = if ($displayName) { $displayName } else { $sam }

  $pwdPlain = New-SecurePassword -Length 24
  $pwdSecure = ConvertTo-SecureString -String $pwdPlain -AsPlainText -Force

  $exists = $existingSams.Contains($sam)

  if ($exists) {
    if (-not $UpdateExisting) {
      Add-Content -Path $resultsOut -Value ("{0},SKIP,User exists" -f $sam)
      continue
    }

    # Update basic attributes (non-destructive)
    try {
      Set-ADUser -Identity $sam `
        -DisplayName $displayName `
        -GivenName $r.GivenName `
        -Surname $r.Surname `
        -Initial $r.MiddleInitial `
        -Title $r.Title `
        -Company $r.Company `
        -EmailAddress $email `
        -StreetAddress $r.StreetAddress `
        -City $r.City `
        -State $r.State `
        -PostalCode $r.ZipCode `
        -Country $r.Country `
        -OfficePhone $r.TelephoneNumber `
        -Description ("Occupation={0}; Vehicle={1}" -f $r.Occupation, $r.Vehicle) `
        -ErrorAction Stop

      Add-Content -Path $resultsOut -Value ("{0},UPDATE,Updated attributes" -f $sam)
    } catch {
      Add-Content -Path $resultsOut -Value ("{0},ERROR,{1}" -f $sam, ($_.Exception.Message -replace ",",";"))
    }

    continue
  }

  # Create user
  try {
    $params = @{
      Name = $name
      SamAccountName = $sam
      UserPrincipalName = $upn
      Enabled = $true
      AccountPassword = $pwdSecure
      Path = $targetUsersOU
      GivenName = $r.GivenName
      Surname = $r.Surname
      DisplayName = $displayName
      EmailAddress = $email
      StreetAddress = $r.StreetAddress
      City = $r.City
      State = $r.State
      PostalCode = $r.ZipCode
      Country = $r.Country
      OfficePhone = $r.TelephoneNumber
      Title = $r.Title
      Company = $r.Company
      Description = ("Occupation={0}; MothersMaiden={1}; Birthday={2}" -f $r.Occupation, $r.MothersMaiden, $r.Birthday)
      ChangePasswordAtLogon = $false
      PasswordNeverExpires = $false
    }

    if ($PSCmdlet.ShouldProcess($sam, "Create AD user in $targetUsersOU")) {
      New-ADUser @params | Out-Null
      [void]$existingSams.Add($sam)

      # Group memberships (safe, simple)
      if ($gAllEmployees) { Add-ADGroupMember -Identity $gAllEmployees -Members $sam -ErrorAction SilentlyContinue }
      if ($gVpnUsers)     { Add-ADGroupMember -Identity $gVpnUsers     -Members $sam -ErrorAction SilentlyContinue }

      if ($siteMeta -and $siteMeta.AllUsersGroupDN) {
        Add-ADGroupMember -Identity $siteMeta.AllUsersGroupDN -Members $sam -ErrorAction SilentlyContinue
      }

      # Export password for lab use
      Add-Content -Path $pwOut -Value ("{0},{1},True,""{2}"",""{3}"",CREATE,OK" -f $sam,$upn,$targetUsersOU,$pwdPlain)
      Add-Content -Path $resultsOut -Value ("{0},CREATE,OK" -f $sam)
    }
  } catch {
    $msg = $_.Exception.Message -replace ",",";"
    Add-Content -Path $resultsOut -Value ("{0},ERROR,{1}" -f $sam,$msg)
  }
}

Write-Log ("Done. Imported processed rows: {0}" -f $userCount)
Write-Log ("Outputs: {0} | {1}" -f $pwOut, $resultsOut)
Write-Host ""
Write-Host "OutputDir: $OutputDir"
