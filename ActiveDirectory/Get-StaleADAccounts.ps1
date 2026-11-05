<#
.SYNOPSIS
    Discovers dormant, inactive, or never-logged-in user and computer accounts in Active Directory.

.DESCRIPTION
    Get-StaleADAccounts queries Active Directory using native Microsoft cmdlets (replacing deprecated Quest
    ActiveRoles snap-ins) to identify dormant accounts exceeding an inactivity threshold (default: 90 days).

    Accurately evaluates replicated 'lastLogonTimestamp', 'pwdLastSet', and 'whenCreated' attributes.
    Supports filtering by account type (User, Computer, All), scoping to specific Organizational Units (OUs),
    and executing automated remediation (ReportOnly, Disable, MoveToOU) with complete ShouldProcess (-WhatIf)
    safety controls.

.PARAMETER AccountType
    The category of Active Directory accounts to inspect. Valid options: 'User', 'Computer', 'All'. Default: 'All'.

.PARAMETER InactivityDays
    The threshold in calendar days without authentication or logon activity. Default: 90.

.PARAMETER SearchBase
    LDAP Distinguished Name of the container or OU to scope the search. Default: Domain root.

.PARAMETER IncludeDisabled
    When specified, includes accounts that are already disabled. Default: $false (focuses on active dormant accounts).

.PARAMETER NeverLoggedInOnly
    Filters specifically for accounts created more than InactivityDays ago that have never registered a logon event.

.PARAMETER Action
    Automated remediation action to execute against discovered stale accounts:
    - 'ReportOnly' (Default): Generates audit data without modifying directory state.
    - 'Disable': Disables identified stale accounts.
    - 'MoveToOU': Relocates identified stale accounts to the destination specified by TargetOU.

.PARAMETER TargetOU
    Destination Organizational Unit Distinguished Name when using -Action MoveToOU.

.PARAMETER Domain
    Target Active Directory domain FQDN.

.PARAMETER Server
    Domain Controller FQDN to query directly.

.PARAMETER Credential
    PSCredential object containing alternate authentication credentials.

.PARAMETER ExportCsv
    Optional file path to export discovery findings to CSV.

.PARAMETER ExportJson
    Optional file path to export discovery findings to JSON.

.EXAMPLE
    PS C:\> .\Get-StaleADAccounts.ps1 -AccountType User -InactivityDays 90 -SearchBase "OU=Staff,DC=contoso,DC=local"

    Discovers all enabled user accounts in the Staff OU that have not logged in for 90+ days.

.EXAMPLE
    PS C:\> .\Get-StaleADAccounts.ps1 -AccountType Computer -InactivityDays 120 -Action Disable -WhatIf

    Simulates disabling all computer accounts dormant for over 120 days.

.NOTES
    Author: Koality Assured Security Operations
    Security Reference: CIS Microsoft Windows Server Benchmark (Dormant Account Management)
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Position = 0)]
    [ValidateSet('User', 'Computer', 'All')]
    [string]$AccountType = 'All',

    [Parameter(Position = 1)]
    [ValidateRange(1, 3650)]
    [int]$InactivityDays = 90,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SearchBase,

    [Parameter()]
    [switch]$IncludeDisabled,

    [Parameter()]
    [switch]$NeverLoggedInOnly,

    [Parameter()]
    [switch]$CrossCheckDomainControllers,

    [Parameter()]
    [ValidateSet('ReportOnly', 'Disable', 'MoveToOU')]
    [string]$Action = 'ReportOnly',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TargetOU,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportCsv,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Action -eq 'MoveToOU' -and [string]::IsNullOrWhiteSpace($TargetOU)) {
    throw "Parameter -TargetOU is required when -Action is set to 'MoveToOU'."
}

Write-Verbose "Importing ActiveDirectory module..."
if (-not (Get-Module -Name ActiveDirectory)) {
    Import-Module ActiveDirectory -ErrorAction Stop
}

$adParams = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $adParams['Server'] = $Server
}
elseif (-not [string]::IsNullOrWhiteSpace($Domain)) {
    $adParams['Server'] = $Domain
}
if ($null -ne $Credential) {
    $adParams['Credential'] = $Credential
}
if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
    $adParams['SearchBase'] = $SearchBase
}

$cutoffDate = (Get-Date).AddDays(-$InactivityDays)
$cutoffFileTime = $cutoffDate.ToFileTimeUtc()
Write-Verbose "Calculated dormancy cutoff date: $cutoffDate (FileTimeUtc: $cutoffFileTime)"

# Active Directory Replication Lag Warning:
# 'lastLogonTimestamp' is replicated with an intentional randomized delay of up to 14 days
# (governed by ms-DS-Logon-Time-Sync-Interval). To prevent false positives on accounts authenticated
# within the last 14 days, -CrossCheckDomainControllers queries the exact 'lastLogon' attribute across all DCs.
Write-Verbose "AD Replication Notice: 'lastLogonTimestamp' exhibits a 9-14 day replication sync interval. Use -CrossCheckDomainControllers to cross-verify authentications across all domain controllers."

$domainControllers = @()
if ($CrossCheckDomainControllers.IsPresent) {
    try {
        Write-Verbose "Discovering active Domain Controllers for cross-replication authentication audit..."
        $dcParams = @{}
        if ($adParams.ContainsKey('Server')) { $dcParams['Server'] = $adParams['Server'] }
        if ($adParams.ContainsKey('Credential')) { $dcParams['Credential'] = $adParams['Credential'] }
        $domainControllers = @(Get-ADDomainController -Filter * @dcParams)
        Write-Verbose "Discovered $($domainControllers.Count) Domain Controllers for live lastLogon verification."
    }
    catch {
        Write-Warning "Failed to discover domain controllers for cross-checking: $_"
    }
}

function Get-LatestCrossDcLogon {
    param([string]$AccountDn, [string]$Type)
    $maxFileTime = 0
    foreach ($dc in $domainControllers) {
        try {
            $dcHost = $dc.HostName
            $rawVal = if ($Type -eq 'User') {
                (Get-ADUser -Identity $AccountDn -Server $dcHost -Properties lastLogon -ErrorAction SilentlyContinue).lastLogon
            } else {
                (Get-ADComputer -Identity $AccountDn -Server $dcHost -Properties lastLogon -ErrorAction SilentlyContinue).lastLogon
            }
            if ($rawVal -and $rawVal -gt $maxFileTime) {
                $maxFileTime = $rawVal
            }
        }
        catch {}
    }
    return $maxFileTime
}

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

# Query Users
if ($AccountType -in @('User', 'All')) {
    Write-Verbose "Querying Active Directory for dormant user accounts..."
    $userProps = @('SamAccountName', 'DisplayName', 'DistinguishedName', 'Enabled', 'lastLogonTimestamp', 'pwdLastSet', 'whenCreated', 'Description', 'UserPrincipalName')

    $userFilter = if ($IncludeDisabled.IsPresent) { '*' } else { 'Enabled -eq $true' }
    $users = Get-ADUser -Filter $userFilter -Properties $userProps @adParams

    foreach ($u in $users) {
        $lastLogon = $null
        $daysInactive = [int]::MaxValue

        $effectiveLogonFileTime = $u.lastLogonTimestamp
        if ($CrossCheckDomainControllers.IsPresent -and $domainControllers.Count -gt 0) {
            $crossDcLogon = Get-LatestCrossDcLogon -AccountDn $u.DistinguishedName -Type 'User'
            if ($crossDcLogon -gt $effectiveLogonFileTime) {
                $effectiveLogonFileTime = $crossDcLogon
            }
        }

        if ($effectiveLogonFileTime) {
            $lastLogon = [DateTime]::FromFileTimeUtc($effectiveLogonFileTime)
            $daysInactive = [Math]::Floor(((Get-Date) - $lastLogon).TotalDays)
        }

        $createdDate = $u.whenCreated
        $daysSinceCreation = if ($createdDate) { [Math]::Floor(((Get-Date) - $createdDate).TotalDays) } else { 0 }

        $isStale = $false
        if ($NeverLoggedInOnly.IsPresent) {
            if ($null -eq $lastLogon -and $daysSinceCreation -ge $InactivityDays) {
                $isStale = $true
            }
        }
        else {
            if ($null -eq $lastLogon) {
                if ($daysSinceCreation -ge $InactivityDays) {
                    $isStale = $true
                }
            }
            elseif ($daysInactive -ge $InactivityDays) {
                $isStale = $true
            }
        }

        if (-not $isStale) {
            continue
        }

        $actionTaken = 'Audited'
        if ($Action -eq 'Disable' -and $u.Enabled) {
            if ($PSCmdlet.ShouldProcess("User Account: $($u.SamAccountName)", "Disable Inactive Account")) {
                Set-ADUser -Identity $u.DistinguishedName -Enabled $false @adParams
                $actionTaken = 'Disabled'
                Write-Verbose "Disabled inactive user account: $($u.SamAccountName)"
            }
        }
        elseif ($Action -eq 'MoveToOU') {
            if ($PSCmdlet.ShouldProcess("User Account: $($u.SamAccountName) to $TargetOU", "Relocate Stale Account")) {
                Move-ADObject -Identity $u.DistinguishedName -TargetPath $TargetOU @adParams
                $actionTaken = "Moved to $TargetOU"
                Write-Verbose "Relocated user account: $($u.SamAccountName)"
            }
        }

        $pwdLastSetDate = if ($u.pwdLastSet -and $u.pwdLastSet -gt 0) { [DateTime]::FromFileTimeUtc($u.pwdLastSet) } else { $null }

        $results.Add([PSCustomObject]@{
            AccountType       = 'User'
            SamAccountName    = $u.SamAccountName
            DisplayName       = $u.DisplayName
            DistinguishedName = $u.DistinguishedName
            Enabled           = $u.Enabled
            LastLogonDate     = if ($lastLogon) { $lastLogon.ToString('o') } else { 'Never' }
            DaysInactive      = if ($lastLogon) { $daysInactive } else { $daysSinceCreation }
            PasswordLastSet   = if ($pwdLastSetDate) { $pwdLastSetDate.ToString('o') } else { 'Never' }
            WhenCreated       = if ($createdDate) { $createdDate.ToString('o') } else { $null }
            OperatingSystem   = $null
            Description       = $u.Description
            ActionTaken       = $actionTaken
        })
    }
}

# Query Computers
if ($AccountType -in @('Computer', 'All')) {
    Write-Verbose "Querying Active Directory for dormant computer accounts..."
    $compProps = @('SamAccountName', 'Name', 'DistinguishedName', 'Enabled', 'lastLogonTimestamp', 'pwdLastSet', 'whenCreated', 'Description', 'OperatingSystem')

    $compFilter = if ($IncludeDisabled.IsPresent) { '*' } else { 'Enabled -eq $true' }
    $computers = Get-ADComputer -Filter $compFilter -Properties $compProps @adParams

    foreach ($c in $computers) {
        $lastLogon = $null
        $daysInactive = [int]::MaxValue

        $effectiveLogonFileTime = $c.lastLogonTimestamp
        if ($CrossCheckDomainControllers.IsPresent -and $domainControllers.Count -gt 0) {
            $crossDcLogon = Get-LatestCrossDcLogon -AccountDn $c.DistinguishedName -Type 'Computer'
            if ($crossDcLogon -gt $effectiveLogonFileTime) {
                $effectiveLogonFileTime = $crossDcLogon
            }
        }

        if ($effectiveLogonFileTime) {
            $lastLogon = [DateTime]::FromFileTimeUtc($effectiveLogonFileTime)
            $daysInactive = [Math]::Floor(((Get-Date) - $lastLogon).TotalDays)
        }

        $createdDate = $c.whenCreated
        $daysSinceCreation = if ($createdDate) { [Math]::Floor(((Get-Date) - $createdDate).TotalDays) } else { 0 }

        $isStale = $false
        if ($NeverLoggedInOnly.IsPresent) {
            if ($null -eq $lastLogon -and $daysSinceCreation -ge $InactivityDays) {
                $isStale = $true
            }
        }
        else {
            if ($null -eq $lastLogon) {
                if ($daysSinceCreation -ge $InactivityDays) {
                    $isStale = $true
                }
            }
            elseif ($daysInactive -ge $InactivityDays) {
                $isStale = $true
            }
        }

        if (-not $isStale) {
            continue
        }

        $actionTaken = 'Audited'
        if ($Action -eq 'Disable' -and $c.Enabled) {
            if ($PSCmdlet.ShouldProcess("Computer Account: $($c.Name)", "Disable Inactive Account")) {
                Set-ADComputer -Identity $c.DistinguishedName -Enabled $false @adParams
                $actionTaken = 'Disabled'
                Write-Verbose "Disabled inactive computer account: $($c.Name)"
            }
        }
        elseif ($Action -eq 'MoveToOU') {
            if ($PSCmdlet.ShouldProcess("Computer Account: $($c.Name) to $TargetOU", "Relocate Stale Account")) {
                Move-ADObject -Identity $c.DistinguishedName -TargetPath $TargetOU @adParams
                $actionTaken = "Moved to $TargetOU"
                Write-Verbose "Relocated computer account: $($c.Name)"
            }
        }

        $pwdLastSetDate = if ($c.pwdLastSet -and $c.pwdLastSet -gt 0) { [DateTime]::FromFileTimeUtc($c.pwdLastSet) } else { $null }

        $results.Add([PSCustomObject]@{
            AccountType       = 'Computer'
            SamAccountName    = $c.SamAccountName
            DisplayName       = $c.Name
            DistinguishedName = $c.DistinguishedName
            Enabled           = $c.Enabled
            LastLogonDate     = if ($lastLogon) { $lastLogon.ToString('o') } else { 'Never' }
            DaysInactive      = if ($lastLogon) { $daysInactive } else { $daysSinceCreation }
            PasswordLastSet   = if ($pwdLastSetDate) { $pwdLastSetDate.ToString('o') } else { 'Never' }
            WhenCreated       = if ($createdDate) { $createdDate.ToString('o') } else { $null }
            OperatingSystem   = $c.OperatingSystem
            Description       = $c.Description
            ActionTaken       = $actionTaken
        })
    }
}

Write-Verbose "Discovered $($results.Count) stale Active Directory accounts."

if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
    Write-Verbose "Exporting stale accounts to CSV: $ExportCsv"
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
}

if (-not [string]::IsNullOrWhiteSpace($ExportJson)) {
    Write-Verbose "Exporting stale accounts to JSON: $ExportJson"
    $results | ConvertTo-Json -Depth 4 | Set-Content -Path $ExportJson -Encoding utf8
}

return $results
