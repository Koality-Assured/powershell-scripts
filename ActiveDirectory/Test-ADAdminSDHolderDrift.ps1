<#
.SYNOPSIS
    Audits AdminSDHolder DACL security and detects orphaned adminCount privilege drift across Active Directory.

.DESCRIPTION
    Test-ADAdminSDHolderDrift identifies security drift and persistence vulnerabilities surrounding the Active Directory
    Security Descriptor Propagator (SDProp) and AdminSDHolder architecture:
    - AdminSDHolder Template Poisoning (MITRE ATT&CK T1484):
      Audits the Access Control List (ACL) on 'CN=AdminSDHolder,CN=System,...' to detect non-standard Access Control Entries
      (ACEs) granting unprivileged principals write, reset password, or generic access over all protected objects.
    - Orphaned adminCount=1 Accounts (MITRE ATT&CK T1078.002, T1098):
      When an account is removed from a privileged protected group, Active Directory does not automatically reset adminCount
      or re-enable ACL inheritance. These orphaned accounts remain excluded from delegated OU security controls.
    - Broken ACL Inheritance (SE_DACL_PROTECTED):
      Detects accounts marked as protected from inheritance despite no longer holding Tier 0 group memberships.

.PARAMETER Domain
    The Fully Qualified Domain Name (FQDN) of the target Active Directory domain. Defaults to the current domain.

.PARAMETER Server
    Active Directory Domain Controller to query.

.PARAMETER Credential
    PSCredential object containing alternate authentication credentials.

.PARAMETER AuditAdminSDHolderAcl
    Switch specifying whether to inspect the DACL on the AdminSDHolder container object (default: $true).

.PARAMETER Remediate
    Switch to remediate orphaned accounts under -WhatIf / -Confirm:
    - Sets adminCount = 0 on orphaned accounts.
    - Re-enables ACL inheritance from parent OU.

.PARAMETER ExportCsv
    Optional file path to output findings as CSV.

.PARAMETER ExportJson
    Optional file path to output findings as structured JSON.

.EXAMPLE
    PS C:\> .\ActiveDirectory\Test-ADAdminSDHolderDrift.ps1 -Domain "contoso.local"

    Scans the domain for orphaned adminCount accounts and audits AdminSDHolder template permissions.

.EXAMPLE
    PS C:\> .\ActiveDirectory\Test-ADAdminSDHolderDrift.ps1 -Remediate -WhatIf

    Simulates remediation to clear adminCount and restore inheritance on orphaned accounts.

.NOTES
    Author: Koality Assured Security Operations
    Reference: MITRE ATT&CK T1484 (Domain Policy Modification), T1078.002 (Domain Accounts), T1098 (Account Manipulation)
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
    [bool]$AuditAdminSDHolderAcl = $true,

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
    Write-Verbose "Connected to Domain Controller: $($rootDse.dnsHostName)"
}
catch {
    Write-Error "Failed to query Active Directory RootDSE: $_"
    throw
}

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function New-AdminSDHolderFinding {
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

# 1. Audit AdminSDHolder Container DACL
if ($AuditAdminSDHolderAcl) {
    $adminSDHolderDn = "CN=AdminSDHolder,CN=System,$domainDn"
    Write-Verbose "Auditing AdminSDHolder DACL at: $adminSDHolderDn"

    try {
        $acl = Get-Acl -Path "AD:\$($adminSDHolderDn)"

        # Authorized standard well-known trustees on AdminSDHolder
        $standardTrusteeSids = @(
            'S-1-5-18',        # NT AUTHORITY\SYSTEM
            'S-1-5-32-544',    # BUILTIN\Administrators
            'S-1-5-32-548',    # BUILTIN\Account Operators
            'S-1-5-32-549',    # BUILTIN\Server Operators
            'S-1-5-32-550',    # BUILTIN\Print Operators
            'S-1-5-32-551'     # BUILTIN\Backup Operators
        )

        foreach ($ace in $acl.Access) {
            $sid = $ace.SecurityIdentifier.Value
            $identity = $ace.IdentityReference.Value
            $rights = $ace.ActiveDirectoryRights.ToString()

            # Ignore standard read permissions and inherited entries
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
                continue
            }
            if ($rights -eq 'ReadControl' -or $rights -eq 'GenericRead') {
                continue
            }

            $isStandard = ($standardTrusteeSids -contains $sid)
            if (-not $isStandard -and $sid -match '^S-1-5-21-.*-(512|519)$') {
                $isStandard = $true # Domain Admins / Enterprise Admins
            }

            if (-not $isStandard) {
                $finding = New-AdminSDHolderFinding `
                    -ControlId 'AD-SDPROP-001' `
                    -Category 'AdminSDHolder.DACL.AnomalousACE' `
                    -TargetObject $adminSDHolderDn `
                    -sAMAccountName 'AdminSDHolder' `
                    -Status 'NonCompliant' `
                    -Severity 'Critical' `
                    -ObservedValue "Non-default trustee '$identity' ($sid) granted '$rights' on AdminSDHolder" `
                    -ExpectedValue 'AdminSDHolder container DACL must only contain default built-in administrative principals' `
                    -MitreAttackId 'T1484' `
                    -RemediationGuidance 'Audit the anomalous ACE. Malicious additions to AdminSDHolder propagate to all Tier 0 objects automatically.' `
                    -RemediationCommand "dsacls '$adminSDHolderDn' /R '$identity'"

                $findings.Add($finding)
            }
        }
    }
    catch {
        Write-Warning "Could not inspect AdminSDHolder DACL: $_"
    }
}

# 2. Audit Orphaned adminCount=1 Accounts
Write-Verbose "Enumerating built-in protected groups and nested members..."

# Protected groups protected by SDProp
$protectedGroupNames = @(
    'Administrators',
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Account Operators',
    'Backup Operators',
    'Server Operators',
    'Print Operators',
    'Cert Publishers',
    'Domain Controllers',
    'Read-only Domain Controllers',
    'Enterprise Read-only Domain Controllers',
    'Key Admins',
    'Enterprise Key Admins'
)

$protectedMembersDns = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($grpName in $protectedGroupNames) {
    try {
        $grp = Get-ADGroup -Filter "Name -eq '$grpName'" @adSessionParams
        if ($null -ne $grp) {
            $protectedMembersDns.Add($grp.DistinguishedName) | Out-Null
            $members = Get-ADGroupMember -Identity $grp.DistinguishedName -Recursive @adSessionParams
            if ($null -ne $members) {
                foreach ($m in $members) {
                    $protectedMembersDns.Add($m.distinguishedName) | Out-Null
                }
            }
        }
    }
    catch {
        Write-Verbose "Protected group '$grpName' not present or query skipped: $_"
    }
}

Write-Verbose "Identified $($protectedMembersDns.Count) legitimate protected principals across all protected groups."

# Enumerate all objects with adminCount=1
Write-Verbose "Searching for accounts with adminCount = 1..."
try {
    $adminCountObjects = Get-ADObject -LDAPFilter "(adminCount=1)" -Properties sAMAccountName, distinguishedName, adminCount, objectClass @adSessionParams
    if ($null -ne $adminCountObjects) {
        foreach ($obj in $adminCountObjects) {
            $dn = [string]$obj.distinguishedName
            $sam = [string]$obj.sAMAccountName

            # Skip the protected groups themselves
            if ($protectedMembersDns.Contains($dn)) {
                continue
            }

            # Check ACL inheritance state
            $isInheritanceBroken = $false
            try {
                $objAcl = Get-Acl -Path "AD:\$($dn)"
                $isInheritanceBroken = $objAcl.AreAccessRulesProtected
            }
            catch {
                Write-Verbose "Could not read ACL for $($dn): $_"
            }

            $finding = New-AdminSDHolderFinding `
                -ControlId 'AD-SDPROP-002' `
                -Category 'AdminSDHolder.Drift.OrphanedAdminCount' `
                -TargetObject $dn `
                -sAMAccountName $sam `
                -Status 'NonCompliant' `
                -Severity 'Medium' `
                -ObservedValue "Account has adminCount=1 but is no longer in any protected group. InheritanceBroken: $isInheritanceBroken" `
                -ExpectedValue 'Non-administrative accounts must have adminCount=0 and inherit permissions from parent OU' `
                -MitreAttackId 'T1078.002' `
                -RemediationGuidance 'Reset adminCount to 0 and re-enable ACL inheritance so standard security delegations apply.' `
                -RemediationCommand "Set-ADObject -Identity '$dn' -Replace @{adminCount=0}"

            $findings.Add($finding)

            if ($Remediate) {
                if ($PSCmdlet.ShouldProcess($sam, "Clear adminCount (set to 0) and restore ACL inheritance on $($dn)")) {
                    try {
                        Set-ADObject -Identity $dn -Replace @{adminCount = 0} @adSessionParams
                        if ($isInheritanceBroken) {
                            $targetAcl = Get-Acl -Path "AD:\$($dn)"
                            $targetAcl.SetAccessRuleProtection($false, $true)
                            Set-Acl -Path "AD:\$($dn)" -AclObject $targetAcl
                        }
                        Write-Host "Successfully restored governance on $($sam)" -ForegroundColor Green
                    }
                    catch {
                        Write-Error "Failed to remediate $($sam): $_"
                    }
                }
            }
        }
    }
}
catch {
    Write-Warning "Failed querying accounts with adminCount=1: $_"
}

Write-Verbose "Audit complete. Identified $($findings.Count) AdminSDHolder finding(s)."

# Export CSV
if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
    try {
        $findings | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
        Write-Verbose "Exported AdminSDHolder findings to CSV: $ExportCsv"
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
        Write-Verbose "Exported AdminSDHolder findings to JSON: $ExportJson"
    }
    catch {
        Write-Error "Failed exporting JSON to '$ExportJson': $_"
    }
}

$findings
