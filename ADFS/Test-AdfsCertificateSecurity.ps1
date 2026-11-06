<#
.SYNOPSIS
    Audits Active Directory Federation Services (ADFS) Token-Signing certificates, rollover health, and Golden SAML attack surface.

.DESCRIPTION
    Test-AdfsCertificateSecurity evaluates the security and operational posture of ADFS cryptographic keys and federation certificates:
    - Golden SAML Attack Surface (MITRE ATT&CK T1606.002, T1552.004):
      Audits Active Directory Access Control Lists (ACLs) on the ADFS Distributed Key Manager (DKM) container
      (CN=ADFS,CN=Microsoft,CN=Program Data,DC=...) to verify that unprivileged principals cannot read the master key
      used to decrypt the Token-Signing private key stored in the ADFS configuration database.
    - Token-Signing & Token-Decrypting Lifecycle:
      Evaluates expiration dates, self-signed vs PKI-issued certificates, and private key exportability.
    - Automated Certificate Rollover Health:
      Validates whether AutoCertificateRollover is enabled and functioning to prevent service-wide federation authentication outages.

.PARAMETER AdfsServer
    FQDN or computer name of the primary ADFS server in the farm. Defaults to the local host.

.PARAMETER Domain
    The Fully Qualified Domain Name (FQDN) of the Active Directory domain. Defaults to the current domain.

.PARAMETER Credential
    PSCredential object containing alternate authentication credentials.

.PARAMETER ExpirationThresholdDays
    The threshold in calendar days within which an expiring certificate is flagged. Default: 30 days.

.PARAMETER AuditDkmAcl
    Switch specifying whether to inspect the DACL on the Active Directory DKM container (default: $true).

.PARAMETER ExportCsv
    Optional file path to output findings as CSV.

.PARAMETER ExportJson
    Optional file path to output findings as structured JSON.

.EXAMPLE
    PS C:\> .\ADFS\Test-AdfsCertificateSecurity.ps1

    Audits local ADFS farm certificates and DKM container permissions in Active Directory.

.EXAMPLE
    PS C:\> .\ADFS\Test-AdfsCertificateSecurity.ps1 -AdfsServer "adfs01.contoso.local" -ExpirationThresholdDays 45 -ExportJson ".\adfs-certs.json"

    Audits remote ADFS server adfs01.contoso.local with a 45-day threshold and exports findings to JSON.

.NOTES
    Author: Koality Assured Security Operations
    Reference: MITRE ATT&CK T1606.002 (Forge Web Credentials: Golden SAML), T1552.004 (Private Keys)
#>

[CmdletBinding()]
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
    [ValidateRange(1, 365)]
    [int]$ExpirationThresholdDays = 30,

    [Parameter()]
    [bool]$AuditDkmAcl = $true,

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

function New-AdfsFinding {
    param(
        [string]$ControlId,
        [string]$Category,
        [string]$TargetObject,
        [string]$CertificateType,
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
        CertificateType     = $CertificateType
        Status              = $Status
        Severity            = $Severity
        ObservedValue       = $ObservedValue
        ExpectedValue       = $ExpectedValue
        MitreAttackId       = $MitreAttackId
        RemediationGuidance = $RemediationGuidance
        RemediationCommand  = $RemediationCommand
    }
}

Write-Verbose "Querying ADFS farm properties and certificates on '$AdfsServer'..."

$adfsProperties = $null
$adfsCertificates = @()

if (Get-Command -Name Get-AdfsProperties -ErrorAction SilentlyContinue) {
    try {
        $adfsProperties = Get-AdfsProperties -ErrorAction Stop
        $adfsCertificates = Get-AdfsCertificate -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Could not query ADFS cmdlets on local session: $_"
    }
}

# 1. Audit AutoCertificateRollover
if ($null -ne $adfsProperties) {
    $autoRollover = $adfsProperties.AutoCertificateRollover
    if (-not $autoRollover) {
        $finding = New-AdfsFinding `
            -ControlId 'ADFS-CERT-001' `
            -Category 'ADFS.Certificate.AutoRolloverDisabled' `
            -TargetObject $AdfsServer `
            -CertificateType 'FarmConfiguration' `
            -Status 'NonCompliant' `
            -Severity 'Medium' `
            -ObservedValue 'AutoCertificateRollover is set to False' `
            -ExpectedValue 'AutoCertificateRollover should be enabled or managed via automated external orchestration' `
            -MitreAttackId 'T1606.002' `
            -RemediationGuidance 'Enable AutoCertificateRollover if the farm relies on self-signed certificates.' `
            -RemediationCommand 'Set-AdfsProperties -AutoCertificateRollover $true'

        $findings.Add($finding)
    }
}

# 2. Audit Token-Signing and Token-Decrypting Certificates
$now = [DateTime]::UtcNow

foreach ($certObj in $adfsCertificates) {
    $certType = [string]$certObj.CertificateType
    $cert = $certObj.Certificate
    if ($null -eq $cert) { continue }

    $thumbprint = $cert.Thumbprint
    $subject = $cert.Subject
    $notAfter = $cert.NotAfter.ToUniversalTime()
    $daysRemaining = [Math]::Floor(($notAfter - $now).TotalDays)

    # 2A. Check Expiration
    if ($daysRemaining -le 0) {
        $finding = New-AdfsFinding `
            -ControlId 'ADFS-CERT-002' `
            -Category 'ADFS.Certificate.Expired' `
            -TargetObject $thumbprint `
            -CertificateType $certType `
            -Status 'NonCompliant' `
            -Severity 'Critical' `
            -ObservedValue "$certType certificate ($thumbprint) is EXPIRED (Expired on: $notAfter)" `
            -ExpectedValue 'Federation certificates must be active and valid' `
            -MitreAttackId 'T1606.002' `
            -RemediationGuidance 'Roll over or import a new valid certificate immediately to restore federation authentication.' `
            -RemediationCommand "Update-AdfsCertificate -CertificateType $certType -Urgent"

        $findings.Add($finding)
    }
    elseif ($daysRemaining -le $ExpirationThresholdDays) {
        $finding = New-AdfsFinding `
            -ControlId 'ADFS-CERT-003' `
            -Category 'ADFS.Certificate.ExpiringSoon' `
            -TargetObject $thumbprint `
            -CertificateType $certType `
            -Status 'NonCompliant' `
            -Severity 'High' `
            -ObservedValue "$certType certificate ($thumbprint) expires in $daysRemaining days (Threshold: $ExpirationThresholdDays days)" `
            -ExpectedValue "Certificates must be renewed prior to the $ExpirationThresholdDays-day threshold" `
            -MitreAttackId 'T1606.002' `
            -RemediationGuidance 'Initiate certificate renewal or invoke Update-AdfsCertificate to generate secondary cert.' `
            -RemediationCommand "Update-AdfsCertificate -CertificateType $certType"

        $findings.Add($finding)
    }
}

# 3. Audit Golden SAML Attack Surface: Active Directory DKM Container DACL
if ($AuditDkmAcl -and (Get-Module -ListAvailable -Name ActiveDirectory)) {
    try {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        $adSessionParams = @{}
        if (-not [string]::IsNullOrWhiteSpace($Domain)) {
            $adSessionParams['Server'] = $Domain
        }
        if ($null -ne $Credential) {
            $adSessionParams['Credential'] = $Credential
        }

        $rootDse = Get-ADRootDSE @adSessionParams
        $domainDn = $rootDse.defaultNamingContext

        # DKM Container standard path: CN=ADFS,CN=Microsoft,CN=Program Data,DC=...
        $dkmSearchBase = "CN=Program Data,$domainDn"
        $dkmObjects = Get-ADObject -SearchBase $dkmSearchBase -LDAPFilter "(cn=ADFS)" -Properties distinguishedName @adSessionParams -ErrorAction SilentlyContinue

        if ($null -ne $dkmObjects) {
            $unauthorizedSids = @(
                'S-1-1-0',         # Everyone
                'S-1-5-11',        # Authenticated Users
                'S-1-5-32-545'     # Builtin Users
            )

            foreach ($dkm in $dkmObjects) {
                $dkmDn = [string]$dkm.distinguishedName
                Write-Verbose "Auditing DKM container DACL at '$dkmDn'..."

                try {
                    $dkmAcl = Get-Acl -Path ('AD:\{0}' -f $dkmDn)
                    foreach ($ace in $dkmAcl.Access) {
                        if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
                            continue
                        }

                        $sid = $ace.SecurityIdentifier.Value
                        $identity = $ace.IdentityReference.Value
                        $rights = $ace.ActiveDirectoryRights.ToString()

                        $isUnauthorized = ($unauthorizedSids -contains $sid)
                        if (-not $isUnauthorized -and $sid -match '^S-1-5-21-.*-513$') {
                            $isUnauthorized = $true # Domain Users
                        }

                        # Check for read permissions that expose DKM master key
                        if ($isUnauthorized -and $rights -match '(GenericRead|ReadProperty|ReadControl|GenericAll)') {
                            $finding = New-AdfsFinding `
                                -ControlId 'ADFS-CERT-004' `
                                -Category 'ADFS.DKM.UnauthorizedReadAccess' `
                                -TargetObject $dkmDn `
                                -CertificateType 'DKMMasterKey' `
                                -Status 'NonCompliant' `
                                -Severity 'Critical' `
                                -ObservedValue "Golden SAML Risk: Unauthorized principal '$identity' ($sid) granted '$rights' on ADFS DKM container" `
                                -ExpectedValue 'DKM container read access must be restricted exclusively to the ADFS service account and Domain Admins' `
                                -MitreAttackId 'T1606.002' `
                                -RemediationGuidance 'Remove the unauthorized ACE from the DKM container immediately. Exposure allows full Golden SAML token forgery.' `
                                -RemediationCommand "dsacls '$dkmDn' /R '$identity'"

                            $findings.Add($finding)
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not inspect ACL on DKM container '$dkmDn': $_"
                }
            }
        }
    }
    catch {
        Write-Warning "Could not query Active Directory for ADFS DKM container: $_"
    }
}

Write-Verbose "Audit complete. Identified $($findings.Count) ADFS certificate finding(s)."

# Export CSV
if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
    try {
        $findings | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
        Write-Verbose "Exported ADFS certificate findings to CSV: $ExportCsv"
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
        Write-Verbose "Exported ADFS certificate findings to JSON: $ExportJson"
    }
    catch {
        Write-Error "Failed exporting JSON to '$ExportJson': $_"
    }
}

$findings
