<#
.SYNOPSIS
    Audits members of the local Administrators group (S-1-5-32-544) across domain systems via CIM/WMI sessions.

.DESCRIPTION
    Get-LocalAdminMembers audits local group membership for the well-known Builtin Administrators group
    (SID: S-1-5-32-544) across local or remote Windows systems. It identifies direct members (local users,
    local groups, domain users, domain groups) and optionally recurses into Active Directory domain groups
    to discover effective administrative users.

    Designed for PowerShell 7+ and Windows PowerShell 5.1 using CIM sessions (WS-Management/DCOM) rather
    than deprecated WMI cmdlets. Supports pipelined computer names, credential injection, and structured
    JSON/CSV exporting.

.PARAMETER ComputerName
    One or more hostnames or IP addresses to audit. Accepts pipeline input. Defaults to $env:COMPUTERNAME.

.PARAMETER CimSession
    Existing CIM session(s) to utilize for remote querying.

.PARAMETER Credential
    PSCredential object containing administrative credentials for remote system authentication.

.PARAMETER RecurseDomainGroups
    When specified, queries Active Directory to expand nested domain groups found in the local Administrators
    group, surfacing all effective domain user accounts.

.PARAMETER ThrottleLimit
    Maximum number of concurrent CIM connections. Default: 16.

.PARAMETER ExportCsv
    Optional file path to export membership results to CSV format.

.PARAMETER ExportJson
    Optional file path to export membership results to JSON format.

.EXAMPLE
    PS C:\> "SRV-APP-01", "SRV-DB-01" | .\Get-LocalAdminMembers.ps1 -RecurseDomainGroups

    Audits the local Administrators group on SRV-APP-01 and SRV-DB-01, expanding nested Active Directory groups.

.EXAMPLE
    PS C:\> .\Get-LocalAdminMembers.ps1 -ComputerName "SRV-NODE-01" -ExportJson ".\admin-audit.json"

    Audits SRV-NODE-01 and exports structured results to JSON.

.NOTES
    Author: Koality Assured Systems Engineering
    Security Reference: CIS Microsoft Windows Benchmark (Local Administrator Group Auditing)
#>

[CmdletBinding(DefaultParameterSetName = 'ComputerName')]
param(
    [Parameter(ParameterSetName = 'ComputerName', Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter(ParameterSetName = 'CimSession')]
    [Microsoft.Management.Infrastructure.CimSession[]]$CimSession,

    [Parameter(ParameterSetName = 'ComputerName')]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [switch]$RecurseDomainGroups,

    [Parameter()]
    [ValidateRange(1, 128)]
    [int]$ThrottleLimit = 16,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 15,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportCsv,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportJson
)

begin {
    Set-StrictMode -Version Latest
    $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $adminGroupSid = 'S-1-5-32-544'

    # Cache for resolved domain groups to prevent redundant AD queries
    $domainGroupMemberCache = @{}

    function Get-ExpandedDomainGroupMembers {
        param([string]$GroupIdentifier)

        if ($domainGroupMemberCache.ContainsKey($GroupIdentifier)) {
            return $domainGroupMemberCache[$GroupIdentifier]
        }

        $members = @()
        try {
            if (-not (Get-Module -Name ActiveDirectory)) {
                Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            }
            if (Get-Module -Name ActiveDirectory) {
                # Attempt standard recursive expansion
                $adMembers = Get-ADGroupMember -Identity $GroupIdentifier -Recursive -ErrorAction Stop |
                    Where-Object { $_.objectClass -eq 'user' }
                $members = @($adMembers)
            }
        }
        catch {
            # FSP / Cross-Forest Handling: Get-ADGroupMember throws "An operations error occurred"
            # when encountering Foreign Security Principals (FSPs) from external trusted domains.
            Write-Verbose "Get-ADGroupMember encountered error on '$GroupIdentifier' (likely contains Foreign Security Principals). Falling back to direct member resolution..."
            try {
                $groupObj = Get-ADGroup -Identity $GroupIdentifier -Properties members -ErrorAction Stop
                foreach ($memberDn in $groupObj.members) {
                    if ($memberDn -match 'CN=([^,]+),CN=ForeignSecurityPrincipals') {
                        $fspSid = $Matches[1]
                        $fspName = $fspSid
                        try {
                            $ntAccount = (New-Object System.Security.Principal.SecurityIdentifier($fspSid)).Translate([System.Security.Principal.NTAccount])
                            $fspName = $ntAccount.Value
                        }
                        catch {
                            # Unresolvable foreign SID across trusts
                        }

                        $members += [PSCustomObject]@{
                            SamAccountName = $fspName
                            SID            = [PSCustomObject]@{ Value = $fspSid }
                            objectClass    = 'foreignSecurityPrincipal'
                        }
                    }
                    else {
                        try {
                            $subMember = Get-ADObject -Identity $memberDn -Properties SamAccountName, objectClass -ErrorAction SilentlyContinue
                            if ($subMember -and $subMember.objectClass -eq 'user') {
                                $members += $subMember
                            }
                        }
                        catch {
                            # Skip unresolvable child
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Could not expand domain group '$GroupIdentifier': $_"
            }
        }

        $domainGroupMemberCache[$GroupIdentifier] = $members
        return $members
    }
}

process {
    $sessionsToQuery = @()
    $createdSessions = @()

    if ($PSCmdlet.ParameterSetName -eq 'CimSession') {
        $sessionsToQuery = $CimSession
    }
    else {
        foreach ($target in $ComputerName) {
            try {
                $cimOption = New-CimSessionOption -Protocol Wsman
                $cimOption.OperationTimeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
                $sessionParams = @{
                    ComputerName  = $target
                    SessionOption = $cimOption
                    ErrorAction   = 'Stop'
                }
                if ($null -ne $Credential) {
                    $sessionParams['Credential'] = $Credential
                }
                $sess = New-CimSession @sessionParams
                $createdSessions += $sess
                $sessionsToQuery += $sess
            }
            catch {
                Write-Warning "Failed to establish CIM session to '$target': $_"
                $errObj = [PSCustomObject]@{
                    ComputerName       = $target
                    GroupName          = $null
                    GroupSID           = $adminGroupSid
                    MemberDomain       = $null
                    MemberName         = $null
                    MemberFullName     = $null
                    MemberSID          = $null
                    PrincipalSource    = 'Error'
                    IsDirectMember     = $false
                    ExpandedViaGroup   = $null
                    Status             = 'ConnectionFailed'
                    ErrorDetails       = $_.Exception.Message
                    AuditTimestamp     = (Get-Date).ToUniversalTime()
                }
                $allResults.Add($errObj)
                $errObj
            }
        }
    }

    foreach ($session in $sessionsToQuery) {
        $targetHost = $session.ComputerName
        Write-Verbose "Querying local Administrators group on [$targetHost] via CIM..."

        try {
            # 1. Discover localized name of Administrators group by SID S-1-5-32-544
            $groupQuery = Get-CimInstance -CimSession $session -ClassName Win32_Group -Filter "SID = '$adminGroupSid'" -ErrorAction Stop
            $localAdminGroupName = if ($groupQuery) { $groupQuery.Name } else { 'Administrators' }

            # 2. Query Group-User association
            $assocQuery = "ASSOCIATORS OF {Win32_Group.Domain='$targetHost',Name='$localAdminGroupName'} WHERE AssocClass=Win32_GroupUser"
            $members = Get-CimInstance -CimSession $session -Query $assocQuery -ErrorAction Stop

            if (-not $members -or $members.Count -eq 0) {
                # Fallback: query all Win32_GroupUser instances for group
                $allGroupUsers = Get-CimInstance -CimSession $session -ClassName Win32_GroupUser -ErrorAction SilentlyContinue
                $targetGroupPath = "Name=`"$localAdminGroupName`""
                $members = $allGroupUsers | Where-Object { $_.GroupComponent -like "*$targetGroupPath*" } | ForEach-Object {
                    # Extract PartComponent
                    if ($_.PartComponent -match 'Domain="([^"]+)",Name="([^"]+)"') {
                        [PSCustomObject]@{
                            Domain = $Matches[1]
                            Name   = $Matches[2]
                            SID    = $null
                        }
                    }
                }
            }

            foreach ($member in $members) {
                $memberDomain = if ($member.Domain) { $member.Domain } else { $targetHost }
                $memberName = $member.Name
                $memberSid = if ($member.SID) { $member.SID } else { $null }
                $memberFullName = "$memberDomain\$memberName"

                # Classify source principal type
                $principalSource = 'Unknown'
                $isLocal = ($memberDomain.ToUpper() -eq $targetHost.ToUpper() -or $memberDomain -eq '.')

                if ($member.CimClass.CimClassName -match 'Win32_Account|Win32_UserAccount') {
                    $principalSource = if ($isLocal) { 'LocalUser' } else { 'DomainUser' }
                }
                elseif ($member.CimClass.CimClassName -match 'Win32_Group') {
                    $principalSource = if ($isLocal) { 'LocalGroup' } else { 'DomainGroup' }
                }
                else {
                    $principalSource = if ($isLocal) { 'LocalPrincipal' } else { 'DomainPrincipal' }
                }

                $record = [PSCustomObject]@{
                    ComputerName       = $targetHost
                    GroupName          = $localAdminGroupName
                    GroupSID           = $adminGroupSid
                    MemberDomain       = $memberDomain
                    MemberName         = $memberName
                    MemberFullName     = $memberFullName
                    MemberSID          = $memberSid
                    PrincipalSource    = $principalSource
                    IsDirectMember     = $true
                    ExpandedViaGroup   = $null
                    Status             = 'Active'
                    ErrorDetails       = $null
                    AuditTimestamp     = (Get-Date).ToUniversalTime()
                }

                $allResults.Add($record)
                $record

                # Recursively expand Active Directory domain groups if requested
                if ($RecurseDomainGroups -and (-not $isLocal) -and ($principalSource -in @('DomainGroup', 'DomainPrincipal'))) {
                    Write-Verbose "Recursively expanding domain group [$memberFullName]..."
                    $expandedUsers = Get-ExpandedDomainGroupMembers -GroupIdentifier $memberName
                    foreach ($adUser in $expandedUsers) {
                        $nestedRecord = [PSCustomObject]@{
                            ComputerName       = $targetHost
                            GroupName          = $localAdminGroupName
                            GroupSID           = $adminGroupSid
                            MemberDomain       = $memberDomain
                            MemberName         = $adUser.SamAccountName
                            MemberFullName     = "$memberDomain\$($adUser.SamAccountName)"
                            MemberSID          = $adUser.SID.Value
                            PrincipalSource    = 'DomainUser'
                            IsDirectMember     = $false
                            ExpandedViaGroup   = $memberFullName
                            Status             = 'Active'
                            ErrorDetails       = $null
                            AuditTimestamp     = (Get-Date).ToUniversalTime()
                        }
                        $allResults.Add($nestedRecord)
                        $nestedRecord
                    }
                }
            }
        }
        catch {
            Write-Warning "Error auditing Administrators on [$targetHost]: $_"
            $errObj = [PSCustomObject]@{
                ComputerName       = $targetHost
                GroupName          = $null
                GroupSID           = $adminGroupSid
                MemberDomain       = $null
                MemberName         = $null
                MemberFullName     = $null
                MemberSID          = $null
                PrincipalSource    = 'Error'
                IsDirectMember     = $false
                ExpandedViaGroup   = $null
                Status             = 'QueryFailed'
                ErrorDetails       = $_.Exception.Message
                AuditTimestamp     = (Get-Date).ToUniversalTime()
            }
            $allResults.Add($errObj)
            $errObj
        }
    }

    # Clean up temporarily created CIM sessions
    foreach ($sess in $createdSessions) {
        Remove-CimSession -CimSession $sess -ErrorAction SilentlyContinue
    }
}

end {
    if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
        Write-Verbose "Writing results to CSV: $ExportCsv"
        $allResults | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
    }

    if (-not [string]::IsNullOrWhiteSpace($ExportJson)) {
        Write-Verbose "Writing results to JSON: $ExportJson"
        $allResults | ConvertTo-Json -Depth 4 | Set-Content -Path $ExportJson -Encoding utf8
    }
}
