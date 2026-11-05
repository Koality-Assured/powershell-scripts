<#
.SYNOPSIS
    Pre-stages Active Directory computer accounts with delegated permissions or joins systems to a domain.

.DESCRIPTION
    Manage-ADComputer provides automated lifecycle management for Windows domain computer objects.
    It supports two distinct operational modes:
    1. 'Create' (Default): Pre-stages an Active Directory computer account in a specified Organizational
       Unit (OU), sets descriptive metadata, and configures the ManagedBy property or delegated join permissions.
    2. 'Join': Assesses domain membership and joins the local or a remote system to an Active Directory domain
       utilizing pre-staged computer objects or dynamic creation credentials.

    Built for PowerShell 7+ and Windows PowerShell 5.1 environments, utilizing modern CIM sessions rather than
    deprecated WMI cmdlets.

.PARAMETER ComputerName
    The NetBIOS name of the computer object to create or join (1-15 alphanumeric characters).
    Required for the 'Create' parameter set.

.PARAMETER OUDistinguishedName
    The LDAP Distinguished Name (DN) of the destination Organizational Unit.
    Required for 'Create', optional for 'Join'. Example: 'OU=Workstations,OU=Devices,DC=contoso,DC=local'

.PARAMETER Domain
    The Fully Qualified Domain Name (FQDN) of the Active Directory domain (e.g., 'contoso.local').
    If omitted during 'Create', the domain is automatically derived from the OUDistinguishedName.

.PARAMETER Description
    Informational description stored on the Active Directory computer object.

.PARAMETER Manager
    The sAMAccountName or Distinguished Name of the user or group delegated to join the host to the domain.
    Mapped to the Active Directory 'ManagedBy' attribute.

.PARAMETER Credential
    PSCredential object containing administrative credentials to authenticate against Active Directory.

.PARAMETER Server
    Specific Active Directory Domain Controller FQDN to direct the LDAP operations toward.

.PARAMETER TargetComputer
    The target computer system to join to the domain. Defaults to the local host ($env:COMPUTERNAME).

.PARAMETER Restart
    Automatically reboots the host upon successful domain join completion.

.PARAMETER Force
    Suppresses confirmation prompts during domain join operations.

.PARAMETER PassThru
    Outputs a PSCustomObject containing the created or joined computer status details.

.EXAMPLE
    PS C:\> .\Manage-ADComputer.ps1 -ComputerName "WKSTN-SEC-01" -OUDistinguishedName "OU=Workstations,DC=contoso,DC=local" -Description "SecOps Analyst Workstation" -Manager "SecOps-Deployment-Team"

    Pre-stages the computer object 'WKSTN-SEC-01' in the specified OU with delegated join rights.

.EXAMPLE
    PS C:\> $cred = Get-Credential
    PS C:\> .\Manage-ADComputer.ps1 -Action Join -Domain "contoso.local" -Credential $cred -Restart

    Joins the local computer to 'contoso.local' using specified credentials and triggers a reboot.

.NOTES
    Author: Koality Assured Systems Engineering
    Standard: RFC 2606 / RFC 6761 compliant naming conventions.
#>

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Create')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Create', Position = 0, HelpMessage = 'Name of the computer account (1-15 characters).')]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(1, 15)]
    [ValidatePattern('^[a-zA-Z0-9\-_]+$')]
    [Alias('Name', 'CN')]
    [string]$ComputerName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Create', Position = 1, HelpMessage = 'Distinguished Name of the destination OU.')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Join')]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^(OU|CN)=.+,DC=.+$')]
    [Alias('OU', 'Path', 'DistinguishedName')]
    [string]$OUDistinguishedName,

    [Parameter(Mandatory = $false, ParameterSetName = 'Create')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Join', Position = 0, HelpMessage = 'FQDN of the Active Directory domain.')]
    [ValidateNotNullOrEmpty()]
    [Alias('DomainName', 'ADDomain')]
    [string]$Domain,

    [Parameter(Mandatory = $false, ParameterSetName = 'Create')]
    [ValidateLength(0, 1024)]
    [Alias('Desc')]
    [string]$Description,

    [Parameter(Mandatory = $false, ParameterSetName = 'Create')]
    [ValidateNotNullOrEmpty()]
    [Alias('ManagedBy', 'DelegatedPrincipal')]
    [string]$Manager,

    [Parameter(Mandatory = $false, ParameterSetName = 'Create')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Join')]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false, ParameterSetName = 'Create')]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter(Mandatory = $false, ParameterSetName = 'Join')]
    [ValidateNotNullOrEmpty()]
    [string]$TargetComputer = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false, ParameterSetName = 'Join')]
    [switch]$Restart,

    [Parameter(Mandatory = $false, ParameterSetName = 'Join')]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-DomainFromDistinguishedName {
    param([string]$DistinguishedName)
    $dcParts = ($DistinguishedName -split ',' | Where-Object { $_ -match '^(?i)DC=' }) -replace '^(?i)DC=', ''
    if ($dcParts) {
        return ($dcParts -join '.')
    }
    return $null
}

if ($PSCmdlet.ParameterSetName -eq 'Create') {
    if ([string]::IsNullOrWhiteSpace($Domain)) {
        $Domain = Get-DomainFromDistinguishedName -DistinguishedName $OUDistinguishedName
        Write-Verbose "Derived target domain [$Domain] from Organizational Unit distinguished name."
    }

    if ($PSCmdlet.ShouldProcess("Computer: $ComputerName in OU: $OUDistinguishedName", "Pre-stage Active Directory Computer Account")) {
        Write-Verbose "Importing ActiveDirectory module..."
        if (-not (Get-Module -Name ActiveDirectory)) {
            Import-Module ActiveDirectory -ErrorAction Stop
        }

        $computerSplat = @{
            Name           = $ComputerName
            SamAccountName = "$ComputerName$"
            DisplayName    = $ComputerName
            Path           = $OUDistinguishedName
            Enabled        = $true
        }

        if (-not [string]::IsNullOrWhiteSpace($Description)) {
            $computerSplat['Description'] = $Description
        }

        if (-not [string]::IsNullOrWhiteSpace($Domain)) {
            $computerSplat['Server'] = if (-not [string]::IsNullOrWhiteSpace($Server)) { $Server } else { $Domain }
        }

        if (-not [string]::IsNullOrWhiteSpace($Manager)) {
            $computerSplat['ManagedBy'] = $Manager
        }

        if ($null -ne $Credential) {
            $computerSplat['Credential'] = $Credential
        }

        try {
            New-ADComputer @computerSplat -Verbose:$VerbosePreference
            Write-Verbose "Successfully pre-staged computer account: $ComputerName in $OUDistinguishedName"

            $result = [PSCustomObject]@{
                ComputerName        = $ComputerName
                SamAccountName      = "$ComputerName$"
                DistinguishedName   = "CN=$ComputerName,$OUDistinguishedName"
                OUDistinguishedName = $OUDistinguishedName
                Domain              = $Domain
                ManagedBy           = $Manager
                Status              = 'Pre-Staged'
                Timestamp           = (Get-Date).ToUniversalTime()
            }

            if ($PassThru) {
                return $result
            }
            else {
                Write-Host "Computer account '$ComputerName' successfully pre-staged in '$OUDistinguishedName'." -ForegroundColor Green
            }
        }
        catch {
            Write-Error "Failed to create Active Directory computer object '$ComputerName': $_"
            throw
        }
    }
}
elseif ($PSCmdlet.ParameterSetName -eq 'Join') {
    if ($PSCmdlet.ShouldProcess("Target System: $TargetComputer to Domain: $Domain", "Join Computer to Domain")) {
        Write-Verbose "Assessing current domain membership for $TargetComputer via CIM..."
        try {
            $cimParam = @{ ClassName = 'Win32_ComputerSystem' }
            if ($TargetComputer -ne $env:COMPUTERNAME -and $TargetComputer -ne 'localhost' -and $TargetComputer -ne '127.0.0.1') {
                $cimParam['ComputerName'] = $TargetComputer
                if ($null -ne $Credential) {
                    $cimParam['Credential'] = $Credential
                }
            }

            $compSystem = Get-CimInstance @cimParam -ErrorAction Stop
            if ($compSystem.PartOfDomain) {
                Write-Warning "Target computer '$TargetComputer' is already joined to domain: $($compSystem.Domain)"
                $result = [PSCustomObject]@{
                    TargetComputer = $TargetComputer
                    Domain         = $compSystem.Domain
                    Status         = 'AlreadyJoined'
                    Timestamp      = (Get-Date).ToUniversalTime()
                }
                if ($PassThru) { return $result }
                return
            }
        }
        catch {
            Write-Warning "Could not verify existing domain membership via CIM: $_. Proceeding with Add-Computer."
        }

        $addComputerSplat = @{
            DomainName = $Domain
            Credential = $Credential
            Force      = $Force.IsPresent
        }

        if ($TargetComputer -ne $env:COMPUTERNAME) {
            $addComputerSplat['ComputerName'] = $TargetComputer
        }

        if (-not [string]::IsNullOrWhiteSpace($OUDistinguishedName)) {
            $addComputerSplat['OUPath'] = $OUDistinguishedName
        }

        if ($Server) {
            $addComputerSplat['Server'] = $Server
        }

        if ($Restart.IsPresent) {
            $addComputerSplat['Restart'] = $true
        }

        try {
            Write-Verbose "Executing Add-Computer operation for $TargetComputer..."
            Add-Computer @addComputerSplat -Verbose:$VerbosePreference

            $result = [PSCustomObject]@{
                TargetComputer      = $TargetComputer
                Domain              = $Domain
                OUDistinguishedName = $OUDistinguishedName
                Status              = 'Joined'
                RestartPending      = $Restart.IsPresent
                Timestamp           = (Get-Date).ToUniversalTime()
            }

            if ($PassThru) {
                return $result
            }
            else {
                Write-Host "Computer '$TargetComputer' successfully joined to domain '$Domain'." -ForegroundColor Green
            }
        }
        catch {
            Write-Error "Failed to join computer '$TargetComputer' to domain '$Domain': $_"
            throw
        }
    }
}
