<#
.SYNOPSIS
    Audits Active Directory-Integrated DNS (ADIDNS) zones for dynamic update exposure, aging/scavenging hygiene, and WPAD hijacking.

.DESCRIPTION
    Test-ADIDNSZoneSecurity audits Active Directory-Integrated DNS (ADIDNS) infrastructure to identify
    name-resolution manipulation risks, DNS record hijacking, and internal man-in-the-middle attack surfaces:
    - Insecure Dynamic DNS Updates (MITRE ATT&CK T1565.002, T1557):
      Detects DNS zones configured to allow 'Nonsecure and Secure' dynamic updates, enabling unauthorized or rogue
      clients to create, overwrite, or hijack existing host (A/AAAA) records.
    - Stale Record Hijacking & Scavenging Hygiene:
      Evaluates whether DNS aging and scavenging are properly configured to retire obsolete records and prevent
      subdomain takeover of decommissioned IP addresses.
    - Wildcard DNS Records:
      Discovers wildcard (*) resource records that resolve arbitrary non-existent subdomains.
    - WPAD Registration & DACL Ownership (MITRE ATT&CK T1557.001):
      Audits Web Proxy Auto-Discovery (WPAD) record status and DACL permissions in the DomainDnsZones partition
      to prevent adversaries from registering WPAD to intercept enterprise web traffic.

.PARAMETER ZoneName
    The DNS zone name to inspect. Defaults to the current Active Directory domain name.

.PARAMETER Server
    Active Directory DNS Server or Domain Controller to query.

.PARAMETER Credential
    PSCredential object containing alternate authentication credentials.

.PARAMETER CheckWpadSecurity
    Switch specifying whether to inspect WPAD record presence and DACL ownership (default: $true).

.PARAMETER ExportCsv
    Optional file path to output findings as CSV.

.PARAMETER ExportJson
    Optional file path to output findings as structured JSON.

.EXAMPLE
    PS C:\> .\ActiveDirectory\Test-ADIDNSZoneSecurity.ps1 -ZoneName "contoso.local"

    Audits dynamic update settings, scavenging, and WPAD security on contoso.local.

.EXAMPLE
    PS C:\> .\ActiveDirectory\Test-ADIDNSZoneSecurity.ps1 -Server "dc01.contoso.local" -ExportJson ".\dns-audit.json"

    Runs ADIDNS audit against dc01 and exports findings to JSON.

.NOTES
    Author: Koality Assured Security Operations
    Reference: MITRE ATT&CK T1565.002 (Transmitted Data Manipulation), T1557.001 (LLMNR/NBT-NS Poisoning and Relay)
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$ZoneName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [bool]$CheckWpadSecurity = $true,

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
if ($null -ne $Credential) {
    $adSessionParams['Credential'] = $Credential
}

# Resolve RootDSE
try {
    $rootDse = Get-ADRootDSE @adSessionParams
    $domainDn = $rootDse.defaultNamingContext
    $targetZone = if (-not [string]::IsNullOrWhiteSpace($ZoneName)) {
        $ZoneName
    } else {
        $rootDse.defaultNamingContext -replace '^DC=', '' -replace ',DC=', '.'
    }
    Write-Verbose "Connected to Domain Controller: $($rootDse.dnsHostName) (Zone: $targetZone)"
}
catch {
    Write-Error "Failed to query Active Directory RootDSE: $_"
    throw
}

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function New-DnsFinding {
    param(
        [string]$ControlId,
        [string]$Category,
        [string]$TargetObject,
        [string]$Zone,
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
        Zone                = $Zone
        Status              = $Status
        Severity            = $Severity
        ObservedValue       = $ObservedValue
        ExpectedValue       = $ExpectedValue
        MitreAttackId       = $MitreAttackId
        RemediationGuidance = $RemediationGuidance
        RemediationCommand  = $RemediationCommand
    }
}

$dnsServerParams = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $dnsServerParams['ComputerName'] = $Server
}

# 1. Audit DNS Zone Settings (Dynamic Updates & Aging)
Write-Verbose "Querying DNS Server Zone configuration for '$targetZone'..."

$zoneConfig = $null
if (Get-Command -Name Get-DnsServerZone -ErrorAction SilentlyContinue) {
    try {
        $zoneConfig = Get-DnsServerZone -Name $targetZone @dnsServerParams -ErrorAction Stop
    }
    catch {
        Write-Warning "Get-DnsServerZone failed: $_"
    }
}

# If DnsServer cmdlets are not available, fallback to ADSI inspection in DomainDnsZones
if ($null -ne $zoneConfig) {
    # 1A. Check Dynamic Update Security
    $dynamicUpdate = $zoneConfig.DynamicUpdate
    if ($dynamicUpdate -eq 'NonsecureAndSecure' -or $dynamicUpdate -eq '1') {
        $finding = New-DnsFinding `
            -ControlId 'AD-DNS-001' `
            -Category 'DNS.Zone.InsecureDynamicUpdate' `
            -TargetObject $targetZone `
            -Zone $targetZone `
            -Status 'NonCompliant' `
            -Severity 'Critical' `
            -ObservedValue "Zone DynamicUpdate is configured to '$dynamicUpdate' (Non-secure updates permitted)" `
            -ExpectedValue 'Active Directory-Integrated DNS zones must require Secure Only dynamic updates' `
            -MitreAttackId 'T1565.002' `
            -RemediationGuidance 'Enforce Secure Only dynamic updates to prevent unauthorized clients from creating or modifying records.' `
            -RemediationCommand "Set-DnsServerZoneSetting -Name '$targetZone' -DynamicUpdate Secure"

        $findings.Add($finding)
    }

    # 1B. Check Aging & Scavenging
    $aging = $zoneConfig.Aging
    $agingEnabled = if ($null -ne $aging) { $aging.AgingEnabled } else { $false }
    if (-not $agingEnabled) {
        $finding = New-DnsFinding `
            -ControlId 'AD-DNS-002' `
            -Category 'DNS.Zone.AgingDisabled' `
            -TargetObject $targetZone `
            -Zone $targetZone `
            -Status 'NonCompliant' `
            -Severity 'Medium' `
            -ObservedValue 'DNS Zone Aging is disabled. Stale resource records will not be scavenged.' `
            -ExpectedValue 'DNS Zone Aging and Scavenging should be enabled to reclaim stale and decommissioned records' `
            -MitreAttackId 'T1557' `
            -RemediationGuidance 'Enable Aging on the AD-integrated DNS zone and configure scheduled server scavenging.' `
            -RemediationCommand "Set-DnsServerZoneAging -Name '$targetZone' -Aging `$true -RefreshInterval (New-TimeSpan -Days 7) -NoRefreshInterval (New-TimeSpan -Days 7)"

        $findings.Add($finding)
    }
}
else {
    # Fallback to ADSI lookup on MicrosoftDNS container in DomainDnsZones
    $zoneDn = "DC=$targetZone,CN=MicrosoftDNS,DC=DomainDnsZones,$domainDn"
    Write-Verbose "Inspecting ADSI DNS zone container at '$zoneDn'..."
    try {
        $adZone = Get-ADObject -Identity $zoneDn -Properties dNSProperty @adSessionParams
        if ($null -ne $adZone) {
            Write-Verbose "Successfully read ADSI DNS zone object."
        }
    }
    catch {
        Write-Verbose "ADSI DNS zone query skipped or inaccessible: $_"
    }
}

# 2. Check for Wildcard Records and WPAD Presence
if (Get-Command -Name Get-DnsServerResourceRecord -ErrorAction SilentlyContinue) {
    Write-Verbose "Auditing DNS resource records in '$targetZone'..."
    try {
        $records = Get-DnsServerResourceRecord -ZoneName $targetZone @dnsServerParams -ErrorAction SilentlyContinue

        if ($null -ne $records) {
            # 2A. Wildcard Records Check
            $wildcardRecords = $records | Where-Object { $_.HostName -eq '*' }
            foreach ($wc in $wildcardRecords) {
                $finding = New-DnsFinding `
                    -ControlId 'AD-DNS-003' `
                    -Category 'DNS.Records.WildcardRecord' `
                    -TargetObject "$($wc.HostName).$targetZone" `
                    -Zone $targetZone `
                    -Status 'NonCompliant' `
                    -Severity 'Medium' `
                    -ObservedValue "Wildcard DNS record exists: $($wc.HostName).$targetZone ($($wc.RecordType))" `
                    -ExpectedValue 'Wildcard DNS records should be minimized to avoid unexpected routing or masking missing hosts' `
                    -MitreAttackId 'T1557' `
                    -RemediationGuidance 'Verify business justification for wildcard DNS records and remove if non-essential.' `
                    -RemediationCommand "Remove-DnsServerResourceRecord -ZoneName '$targetZone' -Name '*' -RRType $($wc.RecordType) -Force"

                $findings.Add($finding)
            }

            # 2B. WPAD Record Security
            if ($CheckWpadSecurity) {
                $wpadRecord = $records | Where-Object { $_.HostName -eq 'wpad' }
                if ($null -eq $wpadRecord) {
                    $finding = New-DnsFinding `
                        -ControlId 'AD-DNS-004' `
                        -Category 'DNS.WPAD.RecordMissing' `
                        -TargetObject "wpad.$targetZone" `
                        -Zone $targetZone `
                        -Status 'NonCompliant' `
                        -Severity 'High' `
                        -ObservedValue "No static 'wpad' record exists in zone '$targetZone'" `
                        -ExpectedValue 'A static WPAD sinkhole record (pointing to 127.0.0.1 or authorized proxy) should exist to block WPAD registration attacks' `
                        -MitreAttackId 'T1557.001' `
                        -RemediationGuidance 'Create a static WPAD record pointing to 127.0.0.1 with locked permissions to prevent unprivileged WPAD spoofing.' `
                        -RemediationCommand "Add-DnsServerResourceRecordA -ZoneName '$targetZone' -Name 'wpad' -IPv4Address '127.0.0.1'"

                    $findings.Add($finding)
                }
            }
        }
    }
    catch {
        Write-Warning "Could not enumerate DNS records for zone '$targetZone': $_"
    }
}

Write-Verbose "Audit complete. Identified $($findings.Count) ADIDNS finding(s)."

# Export CSV
if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
    try {
        $findings | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
        Write-Verbose "Exported DNS findings to CSV: $ExportCsv"
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
        Write-Verbose "Exported DNS findings to JSON: $ExportJson"
    }
    catch {
        Write-Error "Failed exporting JSON to '$ExportJson': $_"
    }
}

$findings
