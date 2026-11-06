<#
.SYNOPSIS
    Audits Active Directory user accounts for AS-REP Roasting and Kerberoasting attack surface exposures.

.DESCRIPTION
    Test-ADRoastingExposure scans Active Directory user accounts to identify credential exposure risks
    associated with Kerberos pre-authentication and ticket-granting vulnerabilities:
    - AS-REP Roasting (MITRE ATT&CK T1558.004):
      Accounts configured with DONT_REQ_PREAUTH (0x400000), allowing adversaries to request Kerberos AS-REP
      messages without prior authentication and extract password hashes for offline cracking.
    - Kerberoasting (MITRE ATT&CK T1558.003):
      User accounts with configured Service Principal Names (SPNs), enabling any authenticated domain user
      to request TGS service tickets encrypted with the target account's NTLM/RC4 hash.
    - Legacy Encryption Type Negotiation:
      Audits msDS-SupportedEncryptionTypes to flag service accounts limited to RC4/DES or missing AES 128/256.
    - Privileged Account Exposure:
      Flags administrative accounts (adminCount=1) with configured SPNs, representing critical lateral movement targets.
    - Stale Service Account Passwords:
      Identifies SPN accounts whose passwords have not been rotated within the configured threshold.

.PARAMETER Domain
    The Fully Qualified Domain Name (FQDN) of the target Active Directory domain. Defaults to the current domain.

.PARAMETER Server
    Active Directory Domain Controller to query.

.PARAMETER Credential
    PSCredential object containing alternate authentication credentials.

.PARAMETER Identity
    Optional specific user sAMAccountName or DistinguishedName to inspect.

.PARAMETER MaxPasswordAgeDays
    The threshold in calendar days beyond which an SPN account's password is considered stale. Default: 90 days.

.PARAMETER Remediate
    Switch to remediate AS-REP roasting exposures under -WhatIf / -Confirm by re-enabling pre-authentication.

.PARAMETER ExportCsv
    Optional file path to output findings as CSV.

.PARAMETER ExportJson
    Optional file path to output findings as structured JSON.

.EXAMPLE
    PS C:\> .\ActiveDirectory\Test-ADRoastingExposure.ps1 -Domain "contoso.local"

    Scans the domain for AS-REP and Kerberoasting vulnerabilities.

.EXAMPLE
    PS C:\> .\ActiveDirectory\Test-ADRoastingExposure.ps1 -MaxPasswordAgeDays 60 -ExportJson ".\roasting-audit.json"

    Audits roasting exposure with a 60-day password freshness threshold and exports findings to JSON.

.EXAMPLE
    PS C:\> .\ActiveDirectory\Test-ADRoastingExposure.ps1 -Remediate -WhatIf

    Simulates remediation to re-enable Kerberos pre-authentication on vulnerable accounts.

.NOTES
    Author: Koality Assured Security Operations
    Reference: MITRE ATT&CK T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting)
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
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
    [string]$Identity,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$MaxPasswordAgeDays = 90,

    [Parameter()]
    [switch]$Remediate,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportCsv,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# UserAccountControl Bitwise Constants
$UAC_ACCOUNTDISABLE     = 0x00000002
$UAC_DONT_REQ_PREAUTH   = 0x00400000 # 4194304

# Kerberos Encryption Types (msDS-SupportedEncryptionTypes)
$ENC_DES_CBC_CRC        = 0x00000001
$ENC_DES_CBC_MD5        = 0x00000002
$ENC_RC4_HMAC           = 0x00000004
$ENC_AES128_CTS_HMAC    = 0x00000008
$ENC_AES256_CTS_HMAC    = 0x00000010

Write-Verbose "Initializing ActiveDirectory connectivity..."
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

# Resolve RootDSE
try {
    $rootDse = Get-ADRootDSE @adSessionParams
    Write-Verbose "Connected to Domain Controller: $($rootDse.dnsHostName)"
}
catch {
    Write-Error "Failed to query Active Directory RootDSE: $_"
    throw
}

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function New-RoastingFinding {
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

$userProperties = @(
    'sAMAccountName',
    'distinguishedName',
    'userAccountControl',
    'servicePrincipalName',
    'adminCount',
    'pwdLastSet',
    'msDS-SupportedEncryptionTypes'
)

# 1. AS-REP Roasting Audit
Write-Verbose "Auditing accounts for AS-REP Roasting (DONT_REQ_PREAUTH)..."

$asrepLdap = if (-not [string]::IsNullOrWhiteSpace($Identity)) {
    "(&(objectCategory=person)(objectClass=user)(sAMAccountName={0})(userAccountControl:1.2.840.113556.1.4.803:={1})(!(userAccountControl:1.2.840.113556.1.4.803:={2})))" -f $Identity, $UAC_DONT_REQ_PREAUTH, $UAC_ACCOUNTDISABLE
} else {
    "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:={0})(!(userAccountControl:1.2.840.113556.1.4.803:={1})))" -f $UAC_DONT_REQ_PREAUTH, $UAC_ACCOUNTDISABLE
}

try {
    $asrepUsers = Get-ADUser -LDAPFilter $asrepLdap -Properties $userProperties @adSessionParams
    if ($null -ne $asrepUsers) {
        foreach ($user in $asrepUsers) {
            $sam = [string]$user.sAMAccountName
            $dn = [string]$user.distinguishedName
            $isAdmin = ($user.adminCount -eq 1)
            $severity = if ($isAdmin) { 'Critical' } else { 'High' }

            $finding = New-RoastingFinding `
                -ControlId 'AD-ROAST-001' `
                -Category 'Kerberos.Roasting.AS-REP' `
                -TargetObject $dn `
                -sAMAccountName $sam `
                -Status 'NonCompliant' `
                -Severity $severity `
                -ObservedValue "DONT_REQ_PREAUTH is enabled (Pre-Authentication Not Required). adminCount: $($user.adminCount)" `
                -ExpectedValue 'Kerberos Pre-Authentication must be enforced on all domain user accounts' `
                -MitreAttackId 'T1558.004' `
                -RemediationGuidance 'Enable Kerberos Pre-Authentication to prevent offline extraction of AS-REP password hashes.' `
                -RemediationCommand "Set-ADAccountControl -Identity '$sam' -DoesNotRequirePreAuth `$false"

            $findings.Add($finding)

            if ($Remediate) {
                if ($PSCmdlet.ShouldProcess($sam, "Re-enable Kerberos Pre-Authentication (clear DONT_REQ_PREAUTH)")) {
                    try {
                        Set-ADAccountControl -Identity $sam -DoesNotRequirePreAuth $false @adSessionParams
                        Write-Host "Successfully enabled pre-authentication on $($sam)" -ForegroundColor Green
                    }
                    catch {
                        Write-Error "Failed to remediate pre-authentication on $($sam): $_"
                    }
                }
            }
        }
    }
}
catch {
    Write-Warning "AS-REP Roasting query encountered an error: $_"
}

# 2. Kerberoasting Audit (Users with SPNs)
Write-Verbose "Auditing accounts for Kerberoasting exposure (servicePrincipalName)..."

$kerbLdap = if (-not [string]::IsNullOrWhiteSpace($Identity)) {
    "(&(objectCategory=person)(objectClass=user)(sAMAccountName={0})(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:={1})))" -f $Identity, $UAC_ACCOUNTDISABLE
} else {
    "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:={0})))" -f $UAC_ACCOUNTDISABLE
}

try {
    $kerbUsers = Get-ADUser -LDAPFilter $kerbLdap -Properties $userProperties @adSessionParams
    if ($null -ne $kerbUsers) {
        $now = [DateTime]::UtcNow
        foreach ($user in $kerbUsers) {
            $sam = [string]$user.sAMAccountName
            $dn = [string]$user.distinguishedName
            $isAdmin = ($user.adminCount -eq 1)
            $spnList = ($user.servicePrincipalName -join ', ')
            $rawEnc = $user.'msDS-SupportedEncryptionTypes'
            $encTypes = if ($null -ne $rawEnc) { [int]$rawEnc } else { 0 }

            # Check for Privileged Kerberoastable Account
            if ($isAdmin) {
                $finding = New-RoastingFinding `
                    -ControlId 'AD-ROAST-002' `
                    -Category 'Kerberos.Roasting.PrivilegedSPN' `
                    -TargetObject $dn `
                    -sAMAccountName $sam `
                    -Status 'NonCompliant' `
                    -Severity 'Critical' `
                    -ObservedValue "Privileged account (adminCount=1) has active SPN(s): $spnList" `
                    -ExpectedValue 'Administrative and Tier 0 accounts must never possess Service Principal Names' `
                    -MitreAttackId 'T1558.003' `
                    -RemediationGuidance 'Migrate service execution to a Group Managed Service Account (gMSA) and clear SPNs from administrative users.' `
                    -RemediationCommand "Set-ADUser -Identity '$sam' -Clear servicePrincipalName"

                $findings.Add($finding)
            }

            # Check Encryption Types (RC4 vs AES)
            $hasAes = (($encTypes -band ($ENC_AES128_CTS_HMAC -bor $ENC_AES256_CTS_HMAC)) -ne 0)
            if (-not $hasAes) {
                $finding = New-RoastingFinding `
                    -ControlId 'AD-ROAST-003' `
                    -Category 'Kerberos.Roasting.WeakCrypto' `
                    -TargetObject $dn `
                    -sAMAccountName $sam `
                    -Status 'NonCompliant' `
                    -Severity 'High' `
                    -ObservedValue "SPN account does not advertise AES support (msDS-SupportedEncryptionTypes: $encTypes). Negotiates RC4-HMAC." `
                    -ExpectedValue 'Service accounts must enforce AES-128 and AES-256 Kerberos encryption' `
                    -MitreAttackId 'T1558.003' `
                    -RemediationGuidance 'Configure msDS-SupportedEncryptionTypes to 0x18 (24) to mandate AES-128 and AES-256 ticket encryption.' `
                    -RemediationCommand "Set-ADUser -Identity '$sam' -Replace @{'msDS-SupportedEncryptionTypes' = 24}"

                $findings.Add($finding)
            }

            # Check Stale Password on SPN Account
            if ($null -ne $user.pwdLastSet -and $user.pwdLastSet -gt 0) {
                $pwdDate = [DateTime]::FromFileTimeUtc($user.pwdLastSet)
                $pwdAgeDays = [Math]::Floor(($now - $pwdDate).TotalDays)
                if ($pwdAgeDays -gt $MaxPasswordAgeDays) {
                    $finding = New-RoastingFinding `
                        -ControlId 'AD-ROAST-004' `
                        -Category 'Kerberos.Roasting.StalePassword' `
                        -TargetObject $dn `
                        -sAMAccountName $sam `
                        -Status 'NonCompliant' `
                        -Severity 'Medium' `
                        -ObservedValue "SPN account password has not been rotated in $pwdAgeDays days (Threshold: $MaxPasswordAgeDays days)" `
                        -ExpectedValue "Kerberoastable service accounts must rotate passwords at least every $MaxPasswordAgeDays days" `
                        -MitreAttackId 'T1558.003' `
                        -RemediationGuidance 'Rotate the service account password with a strong 30+ character passphrase, or migrate to a gMSA.' `
                        -RemediationCommand "Set-ADAccountPassword -Identity '$sam' -Reset"

                    $findings.Add($finding)
                }
            }
        }
    }
}
catch {
    Write-Warning "Kerberoasting query encountered an error: $_"
}

Write-Verbose "Audit complete. Identified $($findings.Count) roasting finding(s)."

# Export CSV
if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
    try {
        $findings | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
        Write-Verbose "Exported roasting findings to CSV: $ExportCsv"
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
        Write-Verbose "Exported roasting findings to JSON: $ExportJson"
    }
    catch {
        Write-Error "Failed exporting JSON to '$ExportJson': $_"
    }
}

$findings
