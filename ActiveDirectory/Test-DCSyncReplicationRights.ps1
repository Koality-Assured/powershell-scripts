<#
.SYNOPSIS
    Threat hunting and auditing tool that detects dangerous Active Directory replication rights (DCSync) on partition heads.

.DESCRIPTION
    Test-DCSyncReplicationRights audits Access Control Entries (ACEs) on Active Directory partition heads
    (Domain, Configuration, Schema) to detect principals granted directory replication rights.
    Specifically checks for:
    - DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
    - DS-Replication-Get-Changes (89e95b76-444d-4c62-991a-0facbeda640c)
    - DS-Replication-Get-Changes-In-Filtered-Set (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
    - GenericAll / WriteDacl on partition root objects

    Any non-Domain-Controller principal possessing these rights can leverage directory replication protocols
    (MS-DRSR, commonly via Mimikatz lsadump::dcsync) to remotely extract password hashes (including KRBTGT)
    without executing code on a Domain Controller.

.PARAMETER Domain
    The Fully Qualified Domain Name (FQDN) of the target Active Directory domain. Defaults to the current domain.

.PARAMETER Server
    Active Directory Domain Controller FQDN to query.

.PARAMETER Credential
    PSCredential object containing alternate authentication credentials.

.PARAMETER Partition
    The Active Directory partition(s) to inspect. Valid options: 'Domain', 'Configuration', 'Schema', 'All'.
    Default: 'Domain'.

.PARAMETER ExcludeDefaultPrincipals
    When specified (default: $true), suppresses standard Microsoft built-in administrative principals
    (Domain Controllers, Enterprise Domain Controllers, Builtin Administrators, SYSTEM) to highlight anomalous grants.

.PARAMETER IncludeGenericAll
    Audits principals possessing FullControl (GenericAll) or WriteDacl over partition heads, which indirectly grants DCSync capability.

.PARAMETER ExportCsv
    Optional file path to output discovered replication right findings as CSV.

.PARAMETER ExportJson
    Optional file path to output discovered replication right findings as structured JSON.

.EXAMPLE
    PS C:\> .\Test-DCSyncReplicationRights.ps1 -Domain "contoso.local"

    Scans the domain partition head of 'contoso.local', reporting any anomalous principals with DCSync rights.

.EXAMPLE
    PS C:\> .\Test-DCSyncReplicationRights.ps1 -Partition All -ExcludeDefaultPrincipals:$false -ExportJson ".\dcsync-audit.json"

    Scans all naming contexts, includes default administrative principals, and exports findings to JSON.

.NOTES
    Author: Koality Assured Security Operations
    Reference: MITRE ATT&CK T1003.006 (OS Credential Dumping: DCSync)
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
    [ValidateSet('Domain', 'Configuration', 'Schema', 'All')]
    [string]$Partition = 'Domain',

    [Parameter()]
    [bool]$ExcludeDefaultPrincipals = $true,

    [Parameter()]
    [bool]$IncludeGenericAll = $true,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportCsv,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Extended Replication Rights Schema GUIDs
$REPLICATION_RIGHTS = @{
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes'
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-In-Filtered-Set'
    '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Synchronize'
}

# Known well-known SIDs and RID suffixes that legitimately possess replication rights
$DEFAULT_REPLICATION_SIDS = @(
    'S-1-5-9',         # Enterprise Domain Controllers
    'S-1-5-18',        # Local System
    'S-1-5-32-544'     # Builtin Administrators
)

$DEFAULT_REPLICATION_RIDS = @(
    '512',             # Domain Admins
    '516',             # Domain Controllers
    '519',             # Enterprise Admins
    '498',             # Enterprise Read-only Domain Controllers
    '521'              # Read-only Domain Controllers
)

function Test-IsDefaultPrincipal {
    param(
        [string]$SidString,
        [string]$IdentityName
    )

    if ($DEFAULT_REPLICATION_SIDS -contains $SidString) {
        return $true
    }

    # Match well-known domain group RIDs (last hyphen-delimited chunk)
    if ($SidString -match '^S-1-5-21-.*-(\d+)$') {
        $rid = $Matches[1]
        if ($DEFAULT_REPLICATION_RIDS -contains $rid) {
            return $true
        }
    }

    # Match standard well-known names
    if ($IdentityName -match '(?i)(NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|Enterprise Domain Controllers|Domain Controllers)') {
        return $true
    }

    return $false
}

Write-Verbose "Initializing ActiveDirectory connectivity..."
if (-not (Get-Module -Name ActiveDirectory)) {
    Import-Module ActiveDirectory -ErrorAction Stop
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

# Retrieve RootDSE to identify partition heads
try {
    $rootDse = Get-ADRootDSE @adSessionParams
    Write-Verbose "Connected to Domain Controller: $($rootDse.dnsHostName)"
}
catch {
    Write-Error "Unable to query Active Directory RootDSE: $_"
    throw
}

$targetPartitions = @{}
if ($Partition -in @('Domain', 'All')) {
    $targetPartitions['Domain'] = $rootDse.defaultNamingContext
}
if ($Partition -in @('Configuration', 'All')) {
    $targetPartitions['Configuration'] = $rootDse.configurationNamingContext
}
if ($Partition -in @('Schema', 'All')) {
    $targetPartitions['Schema'] = $rootDse.schemaNamingContext
}

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($partEntry in $targetPartitions.GetEnumerator()) {
    $partName = $partEntry.Key
    $partDn = $partEntry.Value
    Write-Verbose "Auditing partition [$partName]: $partDn"

    try {
        $adObject = Get-ADObject -Identity $partDn @adSessionParams
        $adSecurity = Get-Acl -Path "AD:\$partDn"
    }
    catch {
        # Fallback via DirectoryEntry if AD PSDrive not mounted
        try {
            $dePath = "LDAP://$partDn"
            if ($adSessionParams.ContainsKey('Server')) {
                $dePath = "LDAP://$($adSessionParams['Server'])/$partDn"
            }
            $dirEntry = New-Object System.DirectoryServices.DirectoryEntry($dePath)
            $adSecurity = $dirEntry.ObjectSecurity
        }
        catch {
            Write-Warning "Could not retrieve ACL for partition head ${partDn}: $_"
            continue
        }
    }

    $rules = $adSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    $sidCache = @{}

    foreach ($rule in $rules) {
        $objectTypeGuid = $rule.ObjectType.ToString()
        $sidString = $rule.IdentityReference.Value

        # Pre-filter: Check for replication extended rights or full control BEFORE expensive LSA SID resolution.
        # In enterprise directories with thousands of ACLs, filtering first avoids thousands of blocking RPC lookups.
        $isReplicationRight = $REPLICATION_RIGHTS.ContainsKey($objectTypeGuid)
        $isGenericAll = ($IncludeGenericAll -and ($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)
        $isWriteDacl = ($IncludeGenericAll -and ($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -eq [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)

        if (-not ($isReplicationRight -or $isGenericAll -or $isWriteDacl)) {
            continue
        }

        # Fast-path well-known SID filter
        if ($ExcludeDefaultPrincipals -and ($DEFAULT_REPLICATION_SIDS -contains $sidString)) {
            continue
        }

        # Resolve friendly identity name with in-memory cache
        $identityName = $sidString
        if ($sidCache.ContainsKey($sidString)) {
            $identityName = $sidCache[$sidString]
        }
        else {
            try {
                $ntAccount = (New-Object System.Security.Principal.SecurityIdentifier($sidString)).Translate([System.Security.Principal.NTAccount])
                $identityName = $ntAccount.Value
            }
            catch {
                # Translate failure: Retain raw SID
                $identityName = $sidString
            }
            $sidCache[$sidString] = $identityName
        }

        # Determine RID if domain account
        $rid = $null
        if ($sidString -match '-(\d+)$') {
            $rid = [int]$Matches[1]
        }

        $isDefault = Test-IsDefaultPrincipal -SidString $sidString -IdentityName $identityName

        if ($ExcludeDefaultPrincipals -and $isDefault) {
            continue
        }

        $accessControlType = $rule.AccessControlType.ToString()
        $isInherited = $rule.IsInherited

        $rightName = if ($isReplicationRight) {
            $REPLICATION_RIGHTS[$objectTypeGuid]
        }
        elseif ($isGenericAll) {
            'GenericAll (FullControl)'
        }
        else {
            'WriteDacl (Modify Security)'
        }

        # Calculate Risk Severity
        $riskLevel = 'Low'
        $remediation = 'Legitimate administrative or domain controller assignment.'

        if (-not $isDefault) {
            if ($rightName -eq 'DS-Replication-Get-Changes-All' -or $isGenericAll) {
                $riskLevel = 'Critical'
                $remediation = "IMMEDIATE ACTION: Principal '$identityName' has DCSync or FullControl permissions. Remove unneeded replication ACE immediately to prevent credential dumping."
            }
            elseif ($rightName -eq 'DS-Replication-Get-Changes') {
                $riskLevel = 'High'
                $remediation = "HIGH RISK: Principal '$identityName' has directory replication read rights. If paired with Get-Changes-All or granted to another partition, DCSync is possible."
            }
            else {
                $riskLevel = 'Medium'
                $remediation = "Evaluate whether principal '$identityName' requires extended rights on $partDn."
            }
        }

        $findingObj = [PSCustomObject]@{
            Partition          = $partName
            PartitionDN        = $partDn
            Identity           = $identityName
            SID                = $sidString
            RID                = $rid
            AccessControlType  = $accessControlType
            RightName          = $rightName
            ObjectTypeGUID     = $objectTypeGuid
            IsInherited        = $isInherited
            IsDefaultPrincipal = $isDefault
            RiskLevel          = $riskLevel
            Remediation        = $remediation
        }

        $findings.Add($findingObj)
    }
}

Write-Verbose "Audit complete. Identified $($findings.Count) relevant ACE records."

if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
    Write-Verbose "Exporting findings to CSV: $ExportCsv"
    $findings | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
}

if (-not [string]::IsNullOrWhiteSpace($ExportJson)) {
    Write-Verbose "Exporting findings to JSON: $ExportJson"
    $findings | ConvertTo-Json -Depth 4 | Set-Content -Path $ExportJson -Encoding utf8
}

return $findings
