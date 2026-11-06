<#
.SYNOPSIS
    Audits Active Directory accounts for dangerous Kerberos delegation configurations (Unconstrained, Constrained, and RBCD).

.DESCRIPTION
    Test-ADKerberosDelegation audits user and computer accounts across an Active Directory domain
    to identify privilege escalation and lateral movement attack surfaces stemming from Kerberos delegation:
    - Unconstrained Delegation (TRUSTED_FOR_DELEGATION on non-Domain-Controllers, MITRE ATT&CK T1558):
      Allows compromised servers to capture and harvest Ticket Granting Tickets (TGTs) of connecting users.
    - Constrained Delegation with Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION / S4U2Self):
      Allows a service to impersonate arbitrary users to configured SPNs without requiring Kerberos pre-authentication.
    - Resource-Based Constrained Delegation (RBCD):
      Evaluates msDS-AllowedToActOnBehalfOfOtherIdentity security descriptors for anomalous trustee permissions.
    - Sensitive Privileged Accounts Missing Delegation Protection:
      Identifies Tier 0 and administrative accounts lacking the 'Account is sensitive and cannot be delegated'
      (NOT_DELEGATED) protection flag.

.PARAMETER Domain
    The Fully Qualified Domain Name (FQDN) of the target Active Directory domain. Defaults to the current domain.

.PARAMETER Server
    Specific Active Directory Domain Controller to query.

.PARAMETER Credential
    PSCredential object containing alternate authentication credentials.

.PARAMETER Identity
    Optional specific user or computer sAMAccountName or DistinguishedName to inspect.

.PARAMETER IncludeRBCD
    Switch specifying whether to inspect and decode msDS-AllowedToActOnBehalfOfOtherIdentity security descriptors.

.PARAMETER Remediate
    Switch to remediate detected vulnerabilities under -WhatIf / -Confirm:
    - Clears TRUSTED_FOR_DELEGATION on non-DC computers.
    - Enforces NOT_DELEGATED (AccountNotDelegated) on privileged Tier 0 accounts.

.PARAMETER ExportCsv
    Optional file path to export findings as CSV.

.PARAMETER ExportJson
    Optional file path to export findings as structured JSON.

.EXAMPLE
    PS C:\> .\ActiveDirectory\Test-ADKerberosDelegation.ps1 -Domain "contoso.local"

    Scans the domain contoso.local for all Kerberos delegation exposures and reports findings.

.EXAMPLE
    PS C:\> .\ActiveDirectory\Test-ADKerberosDelegation.ps1 -IncludeRBCD -ExportJson ".\delegation-audit.json"

    Performs domain-wide delegation sweep including RBCD analysis and exports results to JSON.

.EXAMPLE
    PS C:\> .\ActiveDirectory\Test-ADKerberosDelegation.ps1 -Identity "SRV-APPS-01" -Remediate -WhatIf

    Simulates remediation for unconstrained delegation on SRV-APPS-01 using -WhatIf.

.NOTES
    Author: Koality Assured Security Operations
    Reference: MITRE ATT&CK T1558 (Steal or Forge Kerberos Tickets), T1558.003 (Kerberoasting), T1134 (Access Token Manipulation)
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
    [switch]$IncludeRBCD,

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
$UAC_ACCOUNTDISABLE                = 0x00000002
$UAC_TRUSTED_FOR_DELEGATION        = 0x00080000 # 524288
$UAC_NOT_DELEGATED                 = 0x00100000 # 1048576
$UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000 # 16777216

$DOMAIN_CONTROLLER_PRIMARY_GROUP_ID = 516

Write-Verbose "Initializing ActiveDirectory module connectivity..."
if (-not (Get-Module -Name ActiveDirectory)) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Error "The ActiveDirectory PowerShell module is required. Please install RSAT or run on a system with AD cmdlets available."
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
    Write-Verbose "Connected to Domain Controller: $($rootDse.dnsHostName) (Domain DN: $domainDn)"
}
catch {
    Write-Error "Failed to query Active Directory RootDSE: $_"
    throw
}

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function New-DelegationFinding {
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

# Build query filter
$accountProperties = @(
    'sAMAccountName',
    'distinguishedName',
    'objectClass',
    'userAccountControl',
    'primaryGroupID',
    'msDS-AllowedToDelegateTo',
    'msDS-AllowedToActOnBehalfOfOtherIdentity',
    'adminCount',
    'servicePrincipalName'
)

Write-Verbose "Enumerating Active Directory accounts for delegation analysis..."

$queryFilters = if (-not [string]::IsNullOrWhiteSpace($Identity)) {
    @("(&(sAMAccountName={0})(!(userAccountControl:1.2.840.113556.1.4.803:={1})))" -f $Identity, $UAC_ACCOUNTDISABLE)
} else {
    @(
        "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:={0})))" -f $UAC_ACCOUNTDISABLE,
        "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:={0})))" -f $UAC_ACCOUNTDISABLE
    )
}

$accounts = [System.Collections.Generic.List[Microsoft.ActiveDirectory.Management.ADAccount]]::new()

foreach ($qf in $queryFilters) {
    try {
        $results = Get-ADObject -LDAPFilter $qf -Properties $accountProperties @adSessionParams
        if ($null -ne $results) {
            foreach ($acc in $results) {
                $accounts.Add($acc)
            }
        }
    }
    catch {
        Write-Warning "Failed executing query filter '$qf': $_"
    }
}

Write-Verbose "Auditing $($accounts.Count) active accounts..."

foreach ($acc in $accounts) {
    $uac = [int]$acc.userAccountControl
    $dn = [string]$acc.distinguishedName
    $sam = [string]$acc.sAMAccountName
    $isDC = ($acc.primaryGroupID -eq $DOMAIN_CONTROLLER_PRIMARY_GROUP_ID)
    $isAdmin = ($acc.adminCount -eq 1)

    # 1. Unconstrained Delegation Audit
    $isUnconstrained = (($uac -band $UAC_TRUSTED_FOR_DELEGATION) -ne 0)
    if ($isUnconstrained -and -not $isDC) {
        $finding = New-DelegationFinding `
            -ControlId 'AD-DELEG-001' `
            -Category 'Kerberos.Delegation.Unconstrained' `
            -TargetObject $dn `
            -sAMAccountName $sam `
            -Status 'NonCompliant' `
            -Severity 'Critical' `
            -ObservedValue "TRUSTED_FOR_DELEGATION enabled on non-Domain Controller account (UAC: $uac)" `
            -ExpectedValue 'Unconstrained Delegation restricted strictly to Domain Controllers' `
            -MitreAttackId 'T1558' `
            -RemediationGuidance 'Revoke unconstrained delegation and migrate service to Resource-Based Constrained Delegation (RBCD).' `
            -RemediationCommand "Set-ADAccountControl -Identity '$sam' -TrustedForDelegation `$false"

        $findings.Add($finding)

        if ($Remediate) {
            if ($PSCmdlet.ShouldProcess($sam, "Revoke TRUSTED_FOR_DELEGATION (Unconstrained Delegation)")) {
                try {
                    Set-ADAccountControl -Identity $sam -TrustedForDelegation $false @adSessionParams
                    Write-Host "Successfully revoked Unconstrained Delegation on $sam" -ForegroundColor Green
                }
                catch {
                    Write-Error "Failed to remediate Unconstrained Delegation on $($sam): $_"
                }
            }
        }
    }

    # 2. Constrained Delegation with Protocol Transition (S4U2Self)
    $allowedToDelegateTo = $acc.'msDS-AllowedToDelegateTo'
    $hasProtocolTransition = (($uac -band $UAC_TRUSTED_TO_AUTH_FOR_DELEGATION) -ne 0)

    if ($null -ne $allowedToDelegateTo -and $allowedToDelegateTo.Count -gt 0) {
        if ($hasProtocolTransition) {
            $targets = ($allowedToDelegateTo -join ', ')
            $finding = New-DelegationFinding `
                -ControlId 'AD-DELEG-002' `
                -Category 'Kerberos.Delegation.ConstrainedWithTransition' `
                -TargetObject $dn `
                -sAMAccountName $sam `
                -Status 'NonCompliant' `
                -Severity 'High' `
                -ObservedValue "Constrained Delegation with Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION). Targets: $targets" `
                -ExpectedValue 'Use Kerberos-only Constrained Delegation without Protocol Transition where possible' `
                -MitreAttackId 'T1558' `
                -RemediationGuidance 'Disable Protocol Transition (UseKerberosOnly) if backend services support native Kerberos authentication.' `
                -RemediationCommand "Set-ADAccountControl -Identity '$sam' -TrustedToAuthForDelegation `$false"

            $findings.Add($finding)
        }
    }

    # 3. Privileged Accounts Missing NOT_DELEGATED Protection
    $isNotDelegated = (($uac -band $UAC_NOT_DELEGATED) -ne 0)
    if ($isAdmin -and -not $isNotDelegated -and -not $isDC) {
        $finding = New-DelegationFinding `
            -ControlId 'AD-DELEG-003' `
            -Category 'Kerberos.Delegation.SensitiveAccountNotProtected' `
            -TargetObject $dn `
            -sAMAccountName $sam `
            -Status 'NonCompliant' `
            -Severity 'High' `
            -ObservedValue "Tier 0 / Privileged Account (adminCount=1) is missing NOT_DELEGATED flag (AccountNotDelegated = `$false)" `
            -ExpectedValue 'Sensitive and privileged accounts must have AccountNotDelegated = $true to prevent TGT delegation' `
            -MitreAttackId 'T1558' `
            -RemediationGuidance 'Enforce "Account is sensitive and cannot be delegated" in Active Directory Users and Computers.' `
            -RemediationCommand "Set-ADUser -Identity '$sam' -AccountNotDelegated `$true"

        $findings.Add($finding)

        if ($Remediate) {
            if ($PSCmdlet.ShouldProcess($sam, "Set AccountNotDelegated = `$true (NOT_DELEGATED flag)")) {
                try {
                    Set-ADAccountControl -Identity $sam -AccountNotDelegated $true @adSessionParams
                    Write-Host "Successfully protected $sam against Kerberos delegation" -ForegroundColor Green
                }
                catch {
                    Write-Error "Failed to set AccountNotDelegated on $($sam): $_"
                }
            }
        }
    }

    # 4. Resource-Based Constrained Delegation (RBCD) Inspection
    if ($IncludeRBCD) {
        $rbcdBytes = $acc.'msDS-AllowedToActOnBehalfOfOtherIdentity'
        if ($null -ne $rbcdBytes -and $rbcdBytes.Count -gt 0) {
            try {
                $secDesc = [System.Security.AccessControl.CommonSecurityDescriptor]::new($false, $false, $rbcdBytes, 0)
                $dacl = $secDesc.DiscretionaryAcl
                if ($null -ne $dacl -and $dacl.Count -gt 0) {
                    $trustees = [System.Collections.Generic.List[string]]::new()
                    foreach ($ace in $dacl) {
                        $sid = $ace.SecurityIdentifier.Value
                        $trusteeName = try {
                            (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
                        }
                        catch {
                            $sid
                        }
                        $trustees.Add("$trusteeName ($sid)")
                    }

                    $trusteesStr = ($trustees -join '; ')
                    $finding = New-DelegationFinding `
                        -ControlId 'AD-DELEG-004' `
                        -Category 'Kerberos.Delegation.RBCD' `
                        -TargetObject $dn `
                        -sAMAccountName $sam `
                        -Status 'NonCompliant' `
                        -Severity 'Medium' `
                        -ObservedValue "RBCD configured on target. Principals allowed to act on behalf: $trusteesStr" `
                        -ExpectedValue 'RBCD security descriptors must only contain authorized management or gMSA identities' `
                        -MitreAttackId 'T1134' `
                        -RemediationGuidance 'Verify if trustees granted RBCD write authority are authorized. Unauthorized RBCD rights represent lateral movement backdoors.' `
                        -RemediationCommand "Set-ADComputer -Identity '$sam' -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'"

                    $findings.Add($finding)
                }
            }
            catch {
                Write-Warning "Could not parse msDS-AllowedToActOnBehalfOfOtherIdentity on $($sam): $_"
            }
        }
    }
}

Write-Verbose "Audit complete. Identified $($findings.Count) delegation finding(s)."

# Export CSV
if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
    try {
        $findings | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
        Write-Verbose "Exported delegation findings to CSV: $ExportCsv"
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
        Write-Verbose "Exported delegation findings to JSON: $ExportJson"
    }
    catch {
        Write-Error "Failed exporting JSON to '$ExportJson': $_"
    }
}

# Emit pipeline objects
$findings
