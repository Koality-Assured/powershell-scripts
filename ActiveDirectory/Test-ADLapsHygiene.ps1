<#
.SYNOPSIS
    Audits Local Administrator Password Solution (legacy LAPS and Windows LAPS) deployment, encryption, and ACL hygiene.

.DESCRIPTION
    Test-ADLapsHygiene evaluates Active Directory environments for LAPS implementation gaps, security misconfigurations,
    and excessive read permissions over local administrator password attributes:
    - LAPS Coverage & Operational Status (MITRE ATT&CK T1003, T1078.002):
      Discovers computer objects missing LAPS management or exhibiting stale/expired passwords indicative of client processing failures.
    - Legacy Cleartext LAPS vs Modern Windows LAPS:
      Identifies usage of legacy ms-Mcs-AdmPwd (cleartext password stored in AD) versus Windows LAPS msLAPS-EncryptedPassword.
    - Windows LAPS Unencrypted Storage Detection:
      Flags Windows LAPS deployments where passwords are saved in plaintext msLAPS-Password instead of DPAPI-NG encrypted msLAPS-EncryptedPassword.
    - Excessive Read & Decryption Delegation:
      Audits DACL Access Control Entries (ACEs) on Computer objects and OUs to detect unprivileged principals (e.g. Authenticated Users,
      Domain Users) possessing read rights over legacy ms-Mcs-AdmPwd or decryption rights over Windows LAPS.

.PARAMETER Domain
    The Fully Qualified Domain Name (FQDN) of the target Active Directory domain. Defaults to the current domain.

.PARAMETER Server
    Active Directory Domain Controller to query.

.PARAMETER Credential
    PSCredential object containing alternate authentication credentials.

.PARAMETER SearchBase
    Specific Organizational Unit Distinguished Name to scope the computer account and delegation search.

.PARAMETER AuthorizedDecryptorSids
    List of security principal SIDs authorized to read or decrypt LAPS passwords (defaults to Domain Admins and Enterprise Admins).

.PARAMETER ExportCsv
    Optional file path to output findings as CSV.

.PARAMETER ExportJson
    Optional file path to output findings as structured JSON.

.EXAMPLE
    PS C:\> .\ActiveDirectory\Test-ADLapsHygiene.ps1 -Domain "contoso.local"

    Scans the domain for LAPS hygiene, encryption settings, and unauthorized read permissions.

.EXAMPLE
    PS C:\> .\ActiveDirectory\Test-ADLapsHygiene.ps1 -SearchBase "OU=Workstations,DC=contoso,DC=local" -ExportJson ".\laps-audit.json"

    Audits LAPS configuration within the Workstations OU and exports findings to JSON.

.NOTES
    Author: Koality Assured Security Operations
    Reference: MITRE ATT&CK T1003 (OS Credential Dumping), T1078.002 (Domain Accounts)
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SearchBase,

    [Parameter()]
    [string[]]$AuthorizedDecryptorSids,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportCsv,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Extended Right Schema GUIDs
$GUID_LEGACY_LAPS_PWD         = 'bf9679c0-0de6-11d0-a285-00aa003049e2' # ms-Mcs-AdmPwd
$GUID_ALL_EXTENDED_RIGHTS     = '00299570-246d-11d0-a768-00aa006e0529'
$GUID_WINDOWS_LAPS_DECRYPT    = 'f3531ec6-6330-4f8e-8d39-7a671fbac605' # ms-LAPS-Encrypted-Password-Attributes

# Known Low-Privilege / Dangerous Trustees for LAPS Passwords
$LOW_PRIV_SIDS = @(
    'S-1-1-0',         # Everyone
    'S-1-5-7',         # Anonymous
    'S-1-5-11',        # Authenticated Users
    'S-1-5-32-545'     # Users
)

Write-Verbose "Initializing ActiveDirectory module connectivity..."
if (-not (Get-Module -Name ActiveDirectory)) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Error "The ActiveDirectory PowerShell module is required. Please install RSAT or run in an environment with AD cmdlets."
        throw
    }
}

$adSessionParams = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $adSessionParams['Server'] = $Server
}
elseif (-not [string]::IsNullOrWhiteSpace($Domain)) {
    $adSessionParams['Server'] = $Domain
}
if ($null -ne $Credential) {
    $adSessionParams['Credential'] = $Credential
}

# Resolve RootDSE and Domain Context
try {
    $rootDse = Get-ADRootDSE @adSessionParams
    $domainDn = $rootDse.defaultNamingContext
    Write-Verbose "Connected to Domain Controller: $($rootDse.dnsHostName) (Domain: $domainDn)"
}
catch {
    Write-Error "Failed to query Active Directory RootDSE: $_"
    throw
}

$effectiveSearchBase = if (-not [string]::IsNullOrWhiteSpace($SearchBase)) { $SearchBase } else { $domainDn }

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function New-LapsFinding {
    param(
        [string]$ControlId,
        [string]$Category,
        [string]$TargetObject,
        [string]$sAMAccountName,
        [string]$Status,
        [string]$Severity,
        [string]$ObservedValue,
        [string]$ExpectedValue,
        [string]$MitreAttackId,
        [string]$RemediationGuidance,
        [string]$RemediationCommand
    )

    return [PSCustomObject]@{
        Timestamp           = [DateTime]::UtcNow.ToString('o')
        Category            = $Category
        ControlId           = $ControlId
        TargetObject        = $TargetObject
        sAMAccountName      = $sAMAccountName
        Status              = $Status
        Severity            = $Severity
        ObservedValue       = $ObservedValue
        ExpectedValue       = $ExpectedValue
        MitreAttackId       = $MitreAttackId
        RemediationGuidance = $RemediationGuidance
        RemediationCommand  = $RemediationCommand
    }
}

# 1. Enumerate Computer Accounts & LAPS Attributes
Write-Verbose "Querying computer objects in '$effectiveSearchBase' for LAPS status..."

$lapsProperties = @(
    'sAMAccountName',
    'distinguishedName',
    'ms-Mcs-AdmPwd',
    'ms-Mcs-AdmPwdExpirationTime',
    'msLAPS-Password',
    'msLAPS-EncryptedPassword',
    'msLAPS-PasswordExpirationTime',
    'operatingsystem'
)

$computers = try {
    Get-ADComputer -Filter * -SearchBase $effectiveSearchBase -Properties $lapsProperties @adSessionParams
}
catch {
    Write-Warning "Could not enumerate computers in '$effectiveSearchBase': $_"
    @()
}

$now = [DateTime]::UtcNow

foreach ($comp in $computers) {
    $sam = [string]$comp.sAMAccountName
    $dn = [string]$comp.distinguishedName

    $hasLegacyLaps = ($null -ne $comp.'ms-Mcs-AdmPwd' -or $null -ne $comp.'ms-Mcs-AdmPwdExpirationTime')
    $hasWinLapsPlain = ($null -ne $comp.'msLAPS-Password')
    $hasWinLapsEnc = ($null -ne $comp.'msLAPS-EncryptedPassword')
    $hasWinLaps = ($hasWinLapsPlain -or $hasWinLapsEnc)

    # 1A. Computer Missing LAPS Management
    if (-not $hasLegacyLaps -and -not $hasWinLaps) {
        $finding = New-LapsFinding `
            -ControlId 'AD-LAPS-001' `
            -Category 'LAPS.Coverage.Missing' `
            -TargetObject $dn `
            -sAMAccountName $sam `
            -Status 'NonCompliant' `
            -Severity 'High' `
            -ObservedValue 'No legacy or Windows LAPS attributes populated on computer object' `
            -ExpectedValue 'All domain member computers must be managed by Windows LAPS with active password rotation' `
            -MitreAttackId 'T1078.002' `
            -RemediationGuidance 'Deploy Windows LAPS via Group Policy or Intune to manage the local Administrator password.' `
            -RemediationCommand "Set-ADComputer -Identity '$sam' -Description 'Requires LAPS deployment'"

        $findings.Add($finding)
    }

    # 1B. Windows LAPS storing Cleartext Passwords
    if ($hasWinLapsPlain -and -not $hasWinLapsEnc) {
        $finding = New-LapsFinding `
            -ControlId 'AD-LAPS-002' `
            -Category 'LAPS.Encryption.Plaintext' `
            -TargetObject $dn `
            -sAMAccountName $sam `
            -Status 'NonCompliant' `
            -Severity 'Critical' `
            -ObservedValue 'Windows LAPS is storing local admin password in cleartext (msLAPS-Password)' `
            -ExpectedValue 'Windows LAPS must enforce DPAPI-NG password encryption (msLAPS-EncryptedPassword)' `
            -MitreAttackId 'T1003' `
            -RemediationGuidance 'Configure Windows LAPS GPO policy: Enable "Password Encryption" to protect credentials with domain keys.' `
            -RemediationCommand "# Configure GPO: Computer Configuration > Administrative Templates > System > LAPS > Enable password encryption"

        $findings.Add($finding)
    }

    # 1C. Legacy LAPS Cleartext Storage Usage
    if ($hasLegacyLaps -and -not $hasWinLapsEnc) {
        $finding = New-LapsFinding `
            -ControlId 'AD-LAPS-003' `
            -Category 'LAPS.Legacy.Cleartext' `
            -TargetObject $dn `
            -sAMAccountName $sam `
            -Status 'NonCompliant' `
            -Severity 'Medium' `
            -ObservedValue 'Endpoint utilizes legacy Microsoft LAPS (ms-Mcs-AdmPwd) stored in cleartext' `
            -ExpectedValue 'Migrate legacy Microsoft LAPS to modern Windows LAPS with DPAPI-NG encryption' `
            -MitreAttackId 'T1003' `
            -RemediationGuidance 'Upgrade endpoints to modern Windows LAPS and deprecate legacy LAPS AdmPwd.dll.' `
            -RemediationCommand "# Deploy Windows LAPS and decommission legacy ms-Mcs-AdmPwd attributes"

        $findings.Add($finding)
    }

    # 1D. Expired Password Detection
    $isExpired = $false
    if ($null -ne $comp.'msLAPS-PasswordExpirationTime' -and $comp.'msLAPS-PasswordExpirationTime' -gt 0) {
        $expDate = [DateTime]::FromFileTimeUtc($comp.'msLAPS-PasswordExpirationTime')
        if ($expDate -lt $now) { $isExpired = $true }
    }
    elseif ($null -ne $comp.'ms-Mcs-AdmPwdExpirationTime' -and $comp.'ms-Mcs-AdmPwdExpirationTime' -gt 0) {
        $expDate = [DateTime]::FromFileTimeUtc([int64]$comp.'ms-Mcs-AdmPwdExpirationTime')
        if ($expDate -lt $now) { $isExpired = $true }
    }

    if ($isExpired) {
        $finding = New-LapsFinding `
            -ControlId 'AD-LAPS-004' `
            -Category 'LAPS.Operations.ExpiredPassword' `
            -TargetObject $dn `
            -sAMAccountName $sam `
            -Status 'NonCompliant' `
            -Severity 'High' `
            -ObservedValue "LAPS password expiration timestamp is in the past ($expDate). Password rotation failing." `
            -ExpectedValue 'LAPS client service on endpoint must rotate password before expiration' `
            -MitreAttackId 'T1078.002' `
            -RemediationGuidance 'Investigate endpoint event logs (Event ID 10001+ in Applications and Services Logs > Microsoft > Windows > LAPS).' `
            -RemediationCommand "Reset-LapsPassword -Identity '$sam'"

        $findings.Add($finding)
    }
}

# 2. Audit DACL Permissions on Target Scope / OUs
Write-Verbose "Auditing ACL permissions for unauthorized LAPS password readers on '$effectiveSearchBase'..."

try {
    $scopeAcl = Get-Acl -Path ('AD:\{0}' -f $effectiveSearchBase)

    foreach ($ace in $scopeAcl.Access) {
        if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            continue
        }

        $sid = $ace.SecurityIdentifier.Value
        $identity = $ace.IdentityReference.Value
        $objectType = $ace.ObjectType.ToString()

        $isDangerousTrustee = ($LOW_PRIV_SIDS -contains $sid)
        if (-not $isDangerousTrustee -and $sid -match '^S-1-5-21-.*-513$') {
            $isDangerousTrustee = $true # Domain Users
        }

        # Check for Legacy LAPS or Windows LAPS Decryption Right
        $exposesLaps = ($objectType -eq $GUID_LEGACY_LAPS_PWD -or $objectType -eq $GUID_WINDOWS_LAPS_DECRYPT -or $objectType -eq $GUID_ALL_EXTENDED_RIGHTS)

        if ($isDangerousTrustee -and $exposesLaps) {
            $finding = New-LapsFinding `
                -ControlId 'AD-LAPS-005' `
                -Category 'LAPS.DACL.UnauthorizedReader' `
                -TargetObject $effectiveSearchBase `
                -sAMAccountName $identity `
                -Status 'NonCompliant' `
                -Severity 'Critical' `
                -ObservedValue "Low-privileged principal '$identity' ($sid) granted LAPS read/decrypt permission ($objectType)" `
                -ExpectedValue 'LAPS password read and decryption rights must be strictly limited to Tier 0 administrators' `
                -MitreAttackId 'T1003' `
                -RemediationGuidance 'Remove the unauthorized ACE from the OU or Computer container immediately.' `
                -RemediationCommand "dsacls '$effectiveSearchBase' /R '$identity'"

            $findings.Add($finding)
        }
    }
}
catch {
    Write-Warning "Could not read DACL for '$effectiveSearchBase': $_"
}

Write-Verbose "Audit complete. Identified $($findings.Count) LAPS hygiene finding(s)."

# Export CSV
if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
    try {
        $findings | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
        Write-Verbose "Exported LAPS findings to CSV: $ExportCsv"
    }
    catch {
        Write-Error "Failed exporting CSV to '$ExportCsv': $_"
    }
}

# Export JSON
if (-not [string]::IsNullOrWhiteSpace($ExportJson)) {
    try {
        $jsonPayload = $findings | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText($ExportJson, $jsonPayload, [System.Text.Encoding]::UTF8)
        Write-Verbose "Exported LAPS findings to JSON: $ExportJson"
    }
    catch {
        Write-Error "Failed exporting JSON to '$ExportJson': $_"
    }
}

$findings
