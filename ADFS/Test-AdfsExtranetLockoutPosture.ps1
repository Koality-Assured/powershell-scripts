<#
.SYNOPSIS
    Audits Active Directory Federation Services (ADFS) Extranet Smart Lockout (ESL) against Active Directory domain lockout policies.

.DESCRIPTION
    Test-AdfsExtranetLockoutPosture evaluates the ADFS Extranet Smart Lockout configuration against Active Directory
    domain password and lockout policies to mitigate external brute force and Denial of Service (DoS) risks:
    - External Account Lockout Denial of Service (MITRE ATT&CK T1498, T1110.001):
      Password spraying attacks targeted at external federation endpoints can trigger internal Active Directory account
      lockouts unless Extranet Smart Lockout (ESL) is strictly configured.
    - Extranet Lockout Mode Validation:
      Detects whether the farm uses legacy lockout (ADFSOldFallback) or detection-only (ADFSSmartLockoutLogOnly),
      rather than hardened enforcement (ADFSSmartLockoutEnforce).
    - Threshold Ratio Alignment:
      Verifies that the ADFS ExtranetLockoutThreshold is strictly less than the Active Directory domain lockoutThreshold.
      If the ADFS threshold is equal to or greater than the AD threshold, on-premises accounts will lock before ESL intervenes.

.PARAMETER AdfsServer
    FQDN or computer name of the primary ADFS server in the farm. Defaults to the local host.

.PARAMETER Domain
    The Fully Qualified Domain Name (FQDN) of the Active Directory domain. Defaults to the current domain.

.PARAMETER Credential
    PSCredential object containing alternate authentication credentials.

.PARAMETER Remediate
    Switch to remediate ESL configuration under -WhatIf / -Confirm:
    - Enforces ADFSSmartLockoutEnforce mode.
    - Automatically aligns the threshold below the Active Directory lockout policy.

.PARAMETER ExportCsv
    Optional file path to output findings as CSV.

.PARAMETER ExportJson
    Optional file path to output findings as structured JSON.

.EXAMPLE
    PS C:\> .\ADFS\Test-AdfsExtranetLockoutPosture.ps1

    Audits Extranet Lockout settings and compares against default domain password policy.

.EXAMPLE
    PS C:\> .\ADFS\Test-AdfsExtranetLockoutPosture.ps1 -Remediate -WhatIf

    Simulates remediation to enforce Smart Lockout and align threshold with domain policies.

.NOTES
    Author: Koality Assured Security Operations
    Reference: MITRE ATT&CK T1498 (Network Denial of Service), T1110.001 (Password Guessing)
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$AdfsServer = $env:COMPUTERNAME,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

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

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function New-EslFinding {
    param(
        [string]$ControlId,
        [string]$Category,
        [string]$TargetHost,
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
        TargetHost          = $TargetHost
        Status              = $Status
        Severity            = $Severity
        ObservedValue       = $ObservedValue
        ExpectedValue       = $ExpectedValue
        MitreAttackId       = $MitreAttackId
        RemediationGuidance = $RemediationGuidance
        RemediationCommand  = $RemediationCommand
    }
}

Write-Verbose "Querying ADFS properties and AD password policies..."

# 1. Query ADFS Properties
$adfsProps = $null
if (Get-Command -Name Get-AdfsProperties -ErrorAction SilentlyContinue) {
    try {
        $adfsProps = Get-AdfsProperties -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not query Get-AdfsProperties: $_"
    }
}

# 2. Query Active Directory Domain Password Policy
$adLockoutThreshold = $null
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    try {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        $adParams = @{}
        if (-not [string]::IsNullOrWhiteSpace($Domain)) { $adParams['Server'] = $Domain }
        if ($null -ne $Credential) { $adParams['Credential'] = $Credential }

        $domPolicy = Get-ADDefaultDomainPasswordPolicy @adParams -ErrorAction SilentlyContinue
        if ($null -ne $domPolicy) {
            $adLockoutThreshold = $domPolicy.LockoutThreshold
        }
    }
    catch {
        Write-Verbose "Could not retrieve AD default domain password policy: $_"
    }
}

if ($null -ne $adfsProps) {
    $eslMode = [string]$adfsProps.ExtranetLockoutMode
    $eslThreshold = [int]$adfsProps.ExtranetLockoutThreshold
    $eslObsWindow = $adfsProps.ExtranetObservationWindow

    # 1. Audit Extranet Lockout Mode
    if ($eslMode -ne 'ADFSSmartLockoutEnforce') {
        $severity = if ($eslMode -eq 'ADFSOldFallback') { 'Critical' } else { 'High' }
        $finding = New-EslFinding `
            -ControlId 'ADFS-ESL-001' `
            -Category 'ADFS.ESL.ModeNotEnforcing' `
            -TargetHost $AdfsServer `
            -Status 'NonCompliant' `
            -Severity $severity `
            -ObservedValue "ExtranetLockoutMode is configured to '$eslMode'" `
            -ExpectedValue 'ExtranetLockoutMode must be set to ADFSSmartLockoutEnforce' `
            -MitreAttackId 'T1498' `
            -RemediationGuidance 'Enforce Extranet Smart Lockout to prevent external attacks from locking on-prem AD accounts.' `
            -RemediationCommand 'Set-AdfsProperties -ExtranetLockoutMode ADFSSmartLockoutEnforce'

        $findings.Add($finding)

        if ($Remediate) {
            if ($PSCmdlet.ShouldProcess($AdfsServer, "Set-AdfsProperties -ExtranetLockoutMode ADFSSmartLockoutEnforce")) {
                try {
                    Set-AdfsProperties -ExtranetLockoutMode ADFSSmartLockoutEnforce
                    Write-Host "Successfully enabled ADFSSmartLockoutEnforce on $($AdfsServer)" -ForegroundColor Green
                }
                catch {
                    Write-Error "Failed setting ESL mode on $($AdfsServer): $_"
                }
            }
        }
    }

    # 2. Audit Threshold Ratio Against AD Domain Policy
    if ($null -ne $adLockoutThreshold -and $adLockoutThreshold -gt 0) {
        if ($eslThreshold -ge $adLockoutThreshold) {
            $recommendedThreshold = [Math]::Max(1, $adLockoutThreshold - 1)
            $finding = New-EslFinding `
                -ControlId 'ADFS-ESL-002' `
                -Category 'ADFS.ESL.ThresholdRatioFlawed' `
                -TargetHost $AdfsServer `
                -Status 'NonCompliant' `
                -Severity 'Critical' `
                -ObservedValue "ADFS threshold ($eslThreshold) is >= Active Directory threshold ($adLockoutThreshold)" `
                -ExpectedValue "ADFS ExtranetLockoutThreshold must be strictly less than AD LockoutThreshold (e.g. <= $recommendedThreshold)" `
                -MitreAttackId 'T1498' `
                -RemediationGuidance 'Reduce ExtranetLockoutThreshold below the Active Directory domain lockout threshold to ensure ESL locks bad IPs before AD locks user accounts.' `
                -RemediationCommand "Set-AdfsProperties -ExtranetLockoutThreshold $recommendedThreshold"

            $findings.Add($finding)

            if ($Remediate) {
                if ($PSCmdlet.ShouldProcess($AdfsServer, "Set-AdfsProperties -ExtranetLockoutThreshold $recommendedThreshold")) {
                    try {
                        Set-AdfsProperties -ExtranetLockoutThreshold $recommendedThreshold
                        Write-Host "Successfully adjusted ExtranetLockoutThreshold to $recommendedThreshold" -ForegroundColor Green
                    }
                    catch {
                        Write-Error "Failed adjusting ExtranetLockoutThreshold: $_"
                    }
                }
            }
        }
    }

    # 3. Audit Observation Window
    if ($null -ne $eslObsWindow -and $eslObsWindow.TotalMinutes -lt 30) {
        $finding = New-EslFinding `
            -ControlId 'ADFS-ESL-003' `
            -Category 'ADFS.ESL.ObservationWindowShort' `
            -TargetHost $AdfsServer `
            -Status 'NonCompliant' `
            -Severity 'Low' `
            -ObservedValue "ExtranetObservationWindow is only $($eslObsWindow.TotalMinutes) minutes" `
            -ExpectedValue 'ExtranetObservationWindow should be at least 30 minutes to mitigate distributed slow password spraying' `
            -MitreAttackId 'T1110.001' `
            -RemediationGuidance 'Increase ExtranetObservationWindow to at least 30 minutes.' `
            -RemediationCommand 'Set-AdfsProperties -ExtranetObservationWindow (New-TimeSpan -Minutes 30)'

        $findings.Add($finding)
    }
}

Write-Verbose "Audit complete. Identified $($findings.Count) ESL finding(s)."

# Export CSV
if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
    try {
        $findings | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
        Write-Verbose "Exported ESL findings to CSV: $ExportCsv"
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
        Write-Verbose "Exported ESL findings to JSON: $ExportJson"
    }
    catch {
        Write-Error "Failed exporting JSON to '$ExportJson': $_"
    }
}

$findings
