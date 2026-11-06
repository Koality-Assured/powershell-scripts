<#
.SYNOPSIS
    Audits Active Directory Group Policy Objects (GPOs) for weak permissions, unlinked drift, and embedded cpassword credentials.

.DESCRIPTION
    Test-ADGroupPolicyHygiene performs an in-depth security posture assessment of Group Policy infrastructure:
    - GPO Container & SYSVOL DACL Misconfigurations (MITRE ATT&CK T1484.001):
      Inspects Access Control Lists (ACLs) on both AD groupPolicyContainer objects and SYSVOL file shares to detect
      unprivileged principals possessing Write, WriteOwner, WriteDacl, or FullControl permissions.
    - Unlinked & Abandoned GPOs:
      Correlates all GPO GUIDs against active gPLink attributes across Domains, OUs, and Sites to detect orphaned,
      unlinked GPOs that introduce configuration drift or retain stale attack surface.
    - Legacy Group Policy Preferences cpassword Scanning (MITRE ATT&CK T1552.006):
      Recursively inspects SYSVOL XML preference files (Groups.xml, Services.xml, ScheduledTasks.xml, etc.) for hardcoded
      cpassword attributes and decrypts them using the static Microsoft AES-256 key (MS14-025).

.PARAMETER Domain
    The Fully Qualified Domain Name (FQDN) of the target Active Directory domain. Defaults to the current domain.

.PARAMETER Server
    Active Directory Domain Controller to query.

.PARAMETER Credential
    PSCredential object containing alternate authentication credentials.

.PARAMETER SysvolPath
    Optional explicit path to the SYSVOL Policies share. Defaults to '\\<Domain>\sysvol\<Domain>\Policies'.

.PARAMETER ScanCpassword
    Switch specifying whether to recursively inspect SYSVOL XML files for legacy cpassword credentials (default: $true).

.PARAMETER ExportCsv
    Optional file path to output findings as CSV.

.PARAMETER ExportJson
    Optional file path to output findings as structured JSON.

.EXAMPLE
    PS C:\> .\ActiveDirectory\Test-ADGroupPolicyHygiene.ps1 -Domain "contoso.local"

    Scans the domain contoso.local for weak GPO permissions, unlinked GPOs, and cpasswords in SYSVOL.

.EXAMPLE
    PS C:\> .\ActiveDirectory\Test-ADGroupPolicyHygiene.ps1 -SysvolPath "C:\Windows\SYSVOL\sysvol\contoso.local\Policies"

    Audits GPO hygiene pointing directly to a local SYSVOL replication path.

.NOTES
    Author: Koality Assured Security Operations
    Reference: MITRE ATT&CK T1484.001 (Group Policy Modification), T1552.006 (GPP Password), MS14-025
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
    [string]$SysvolPath,

    [Parameter()]
    [bool]$ScanCpassword = $true,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportCsv,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Microsoft MS14-025 Static AES-256 Key for Group Policy Preferences
[byte[]]$GPP_AES_KEY = @(
    0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
    0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
    0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
    0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b
)

function ConvertFrom-GppCpassword {
    param([string]$Cpassword)

    try {
        # Base64 padding correction
        $mod = $Cpassword.Length % 4
        if ($mod -gt 0) {
            $Cpassword += ('=' * (4 - $mod))
        }

        $encryptedBytes = [System.Convert]::FromBase64String($Cpassword)
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $GPP_AES_KEY
        $aes.IV = [byte[]]::new(16) # 16 null bytes IV

        $decryptor = $aes.CreateDecryptor()
        $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
        return [System.Text.Encoding]::Unicode.GetString($decryptedBytes)
    }
    catch {
        return "<Decryption Failed: $($_.Message)>"
    }
}

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

# Resolve RootDSE
try {
    $rootDse = Get-ADRootDSE @adSessionParams
    $domainDn = $rootDse.defaultNamingContext
    $targetDomain = if (-not [string]::IsNullOrWhiteSpace($Domain)) { $Domain } else { $rootDse.dnsHostName }
    Write-Verbose "Connected to Domain Controller: $($rootDse.dnsHostName) (Domain: $domainDn)"
}
catch {
    Write-Error "Failed to query Active Directory RootDSE: $_"
    throw
}

$effectiveSysvol = if (-not [string]::IsNullOrWhiteSpace($SysvolPath)) {
    $SysvolPath
} else {
    "\\$targetDomain\sysvol\$targetDomain\Policies"
}

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function New-GpoFinding {
    param(
        [string]$ControlId,
        [string]$Category,
        [string]$TargetObject,
        [string]$GpoName,
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
        GpoName             = $GpoName
        Status              = $Status
        Severity            = $Severity
        ObservedValue       = $ObservedValue
        ExpectedValue       = $ExpectedValue
        MitreAttackId       = $MitreAttackId
        RemediationGuidance = $RemediationGuidance
        RemediationCommand  = $RemediationCommand
    }
}

# 1. Enumerate GPOs in Active Directory
Write-Verbose "Enumerating GPO objects from CN=Policies,CN=System,$domainDn..."
$policiesDn = "CN=Policies,CN=System,$domainDn"
$gpos = try {
    Get-ADObject -SearchBase $policiesDn -LDAPFilter "(objectClass=groupPolicyContainer)" -Properties displayName, name, distinguishedName, gPCFileSysPath @adSessionParams
}
catch {
    Write-Warning "Could not enumerate GPO containers in '$policiesDn': $_"
    @()
}

Write-Verbose "Discovered $($gpos.Count) Group Policy Object(s)."

# Standard high-privileged SIDs allowed to modify GPOs
$standardAdminSids = @(
    'S-1-5-18',        # NT AUTHORITY\SYSTEM
    'S-1-5-32-544',    # BUILTIN\Administrators
    'S-1-5-9'          # Enterprise Domain Controllers
)

# 2. Check GPO Container DACLs & SYSVOL Folder Permissions
foreach ($gpo in $gpos) {
    $gpoName = [string]$gpo.displayName
    $gpoGuid = [string]$gpo.name
    $gpoDn = [string]$gpo.distinguishedName

    # Check AD Container DACL
    try {
        $gpoAcl = Get-Acl -Path ('AD:\{0}' -f $gpoDn)
        foreach ($ace in $gpoAcl.Access) {
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
                continue
            }

            $sid = $ace.SecurityIdentifier.Value
            $identity = $ace.IdentityReference.Value
            $rights = $ace.ActiveDirectoryRights.ToString()

            # Ignore read-only rights
            if ($rights -match '^(ReadControl|GenericRead)$') {
                continue
            }

            $isAdmin = ($standardAdminSids -contains $sid)
            if (-not $isAdmin -and $sid -match '^S-1-5-21-.*-(512|519)$') {
                $isAdmin = $true # Domain Admins / Enterprise Admins
            }

            # Check for non-admin modification rights
            $hasModRights = ($rights -match '(GenericAll|WriteDacl|WriteOwner|GenericWrite|CreateChild|DeleteChild)')
            if (-not $isAdmin -and $hasModRights) {
                $finding = New-GpoFinding `
                    -ControlId 'AD-GPO-001' `
                    -Category 'GPO.DACL.WeakADPermissions' `
                    -TargetObject $gpoDn `
                    -GpoName $gpoName `
                    -Status 'NonCompliant' `
                    -Severity 'Critical' `
                    -ObservedValue "Non-admin principal '$identity' ($sid) granted '$rights' on GPO container" `
                    -ExpectedValue 'Only Domain Admins and Enterprise Admins may possess modify rights on GPO objects' `
                    -MitreAttackId 'T1484.001' `
                    -RemediationGuidance 'Revoke write permissions from unprivileged accounts to prevent unauthorized GPO modification.' `
                    -RemediationCommand "dsacls '$gpoDn' /R '$identity'"

                $findings.Add($finding)
            }
        }
    }
    catch {
        Write-Verbose "Could not inspect AD DACL for GPO $($gpoGuid): $_"
    }

    # Check SYSVOL Folder Permissions if accessible
    $sysvolGpoPath = Join-Path $effectiveSysvol $gpoGuid
    if (Test-Path $sysvolGpoPath) {
        try {
            $sysAcl = Get-Acl -Path $sysvolGpoPath
            foreach ($ace in $sysAcl.Access) {
                if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
                    continue
                }

                $sid = $ace.SecurityIdentifier.Value
                $identity = $ace.IdentityReference.Value
                $fileRights = $ace.FileSystemRights.ToString()

                if ($fileRights -match '^(ReadAndExecute|Read|Synchronize)$') {
                    continue
                }

                $isAdmin = ($standardAdminSids -contains $sid)
                if (-not $isAdmin -and $sid -match '^S-1-5-21-.*-(512|519)$') {
                    $isAdmin = $true
                }

                $hasModRights = ($fileRights -match '(FullControl|Modify|Write|TakeOwnership|ChangePermissions)')
                if (-not $isAdmin -and $hasModRights) {
                    $finding = New-GpoFinding `
                        -ControlId 'AD-GPO-002' `
                        -Category 'GPO.SYSVOL.WeakFilePermissions' `
                        -TargetObject $sysvolGpoPath `
                        -GpoName $gpoName `
                        -Status 'NonCompliant' `
                        -Severity 'Critical' `
                        -ObservedValue "Non-admin principal '$identity' ($sid) granted '$fileRights' on SYSVOL GPO directory" `
                        -ExpectedValue 'Only administrators and SYSTEM should possess modify/write rights on SYSVOL policy folders' `
                        -MitreAttackId 'T1484.001' `
                        -RemediationGuidance 'Restore default SYSVOL file permissions using icacls or GPMC.' `
                        -RemediationCommand "icacls '$sysvolGpoPath' /remove '$identity'"

                    $findings.Add($finding)
                }
            }
        }
        catch {
            Write-Verbose "Could not inspect SYSVOL ACL for GPO $($gpoGuid): $_"
        }
    }
}

# 3. Detect Unlinked / Abandoned GPOs
Write-Verbose "Auditing gPLink associations to identify unlinked GPOs..."
$linkedGpoGuids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

try {
    # Query all OUs, Domain root, and Sites for gPLink
    $linkedContainers = Get-ADObject -LDAPFilter "(gPLink=*)" -Properties gPLink @adSessionParams
    if ($null -ne $linkedContainers) {
        foreach ($c in $linkedContainers) {
            $rawLinks = [string]$c.gPLink
            # Format: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;0]
            $matches = [regex]::Matches($rawLinks, '\{([A-Fa-f0-9-]+)\}')
            foreach ($m in $matches) {
                $linkedGpoGuids.Add("{$($m.Groups[1].Value)}") | Out-Null
            }
        }
    }
}
catch {
    Write-Warning "Could not enumerate gPLink attributes across directory: $_"
}

foreach ($gpo in $gpos) {
    $guid = [string]$gpo.name
    $displayName = [string]$gpo.displayName
    if (-not $linkedGpoGuids.Contains($guid)) {
        $finding = New-GpoFinding `
            -ControlId 'AD-GPO-003' `
            -Category 'GPO.Hygiene.UnlinkedGPO' `
            -TargetObject $gpo.distinguishedName `
            -GpoName $displayName `
            -Status 'NonCompliant' `
            -Severity 'Low' `
            -ObservedValue "GPO '$displayName' ($guid) is not linked to any Domain, OU, or Site" `
            -ExpectedValue 'All active GPOs should be linked to relevant scopes; unlinked GPOs should be archived or decommissioned' `
            -MitreAttackId 'T1484.001' `
            -RemediationGuidance 'Verify if this unlinked GPO is obsolete. Stale GPOs present configuration drift risks.' `
            -RemediationCommand "Remove-GPO -Name '$displayName'"

        $findings.Add($finding)
    }
}

# 4. Scan SYSVOL XML files for legacy cpassword (MS14-025)
if ($ScanCpassword -and (Test-Path $effectiveSysvol)) {
    Write-Verbose "Scanning SYSVOL ($effectiveSysvol) for legacy Group Policy Preferences cpassword attributes..."
    try {
        $xmlFiles = Get-ChildItem -Path $effectiveSysvol -Recurse -Filter "*.xml" -ErrorAction SilentlyContinue
        foreach ($file in $xmlFiles) {
            try {
                $content = [System.IO.File]::ReadAllText($file.FullName)
                if ($content -match 'cpassword\s*=\s*"([^"]+)"') {
                    $cpass = $Matches[1]
                    $decrypted = ConvertFrom-GppCpassword -Cpassword $cpass

                    # Extract username if present
                    $userName = if ($content -match 'userName\s*=\s*"([^"]+)"') { $Matches[1] } else { 'Unknown' }

                    $finding = New-GpoFinding `
                        -ControlId 'AD-GPO-004' `
                        -Category 'GPO.Credentials.CpasswordLeak' `
                        -TargetObject $file.FullName `
                        -GpoName (Split-Path (Split-Path $file.FullName -Parent) -Leaf) `
                        -Status 'NonCompliant' `
                        -Severity 'Critical' `
                        -ObservedValue "Found embedded cpassword in $($file.Name) for user '$userName'. Decrypted: $decrypted" `
                        -ExpectedValue 'SYSVOL must never contain XML preference files with cpassword credentials (MS14-025)' `
                        -MitreAttackId 'T1552.006' `
                        -RemediationGuidance 'Delete the XML file immediately and change the password for the affected account on all domain hosts.' `
                        -RemediationCommand "Remove-Item -Path '$($file.FullName)' -Force"

                    $findings.Add($finding)
                }
            }
            catch {
                Write-Verbose "Could not parse file $($file.FullName): $_"
            }
        }
    }
    catch {
        Write-Warning "Could not traverse SYSVOL for cpassword scanning: $_"
    }
}

Write-Verbose "Audit complete. Identified $($findings.Count) GPO finding(s)."

# Export CSV
if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
    try {
        $findings | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
        Write-Verbose "Exported GPO findings to CSV: $ExportCsv"
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
        Write-Verbose "Exported GPO findings to JSON: $ExportJson"
    }
    catch {
        Write-Error "Failed exporting JSON to '$ExportJson': $_"
    }
}

$findings
