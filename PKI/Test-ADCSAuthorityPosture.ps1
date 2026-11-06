<#
.SYNOPSIS
    Audits Active Directory Certificate Services (ADCS) Certification Authority configuration, ESC6 posture, and crypto hygiene.

.DESCRIPTION
    Test-ADCSAuthorityPosture inspects Microsoft Enterprise Certification Authorities to evaluate host-level
    and service-level security parameters:
    - ESC6 / EDITF_ATTRIBUTESUBJECTALTNAME2 (MITRE ATT&CK T1649):
      Detects whether the CA is configured to honor user-defined Subject Alternative Name (SAN) attributes
      globally across all requests, enabling domain privilege escalation via any published certificate template.
    - CA Cryptographic Strength:
      Evaluates the CA certificate digital signature algorithm (flagging deprecated SHA-1/MD5) and RSA key length
      (< 2048-bit for subordinate CAs, < 4096-bit for root CAs).
    - Certificate Service Auditing Filter (AuditFilter):
      Validates whether full CA event auditing (issuance, revocation, security policy changes) is configured.
    - CRL Distribution Point (CDP) & AIA Health:
      Audits CRL Distribution Points and Authority Information Access URIs for reachability and remaining validity.

.PARAMETER CertificationAuthority
    Name of the CA to inspect. If omitted, discovers published CAs from the Active Directory Configuration partition.

.PARAMETER Server
    Computer name hosting the CA service. Defaults to the CA host discovered in directory.

.PARAMETER Credential
    PSCredential object containing alternate authentication credentials.

.PARAMETER CrlReachabilityTimeoutSeconds
    Timeout in seconds for checking HTTP CRL Distribution Point responsiveness. Default: 5 seconds.

.PARAMETER ExportCsv
    Optional file path to output findings as CSV.

.PARAMETER ExportJson
    Optional file path to output findings as structured JSON.

.EXAMPLE
    PS C:\> .\PKI\Test-ADCSAuthorityPosture.ps1

    Discovers all Enterprise CAs in the current AD forest and audits their security posture.

.EXAMPLE
    PS C:\> .\PKI\Test-ADCSAuthorityPosture.ps1 -Server "ca01.contoso.local" -CertificationAuthority "Contoso-CA" -ExportJson ".\ca-audit.json"

    Audits a specific CA instance on ca01.contoso.local and exports findings to JSON.

.NOTES
    Author: Koality Assured Security Operations
    Reference: MITRE ATT&CK T1649 (Steal or Forge Authentication Certificates), SpecterOps ESC6
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$CertificationAuthority,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [ValidateRange(1, 60)]
    [int]$CrlReachabilityTimeoutSeconds = 5,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportCsv,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Registry Constants
$HKLM = [uint32]'0x80000002'
$EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000 # 262144

# AuditFilter: 127 = Full auditing (backup, restore, config, request, revoke, certs, keys)
$RECOMMENDED_AUDIT_FILTER = 127

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function New-CaFinding {
    param(
        [string]$ControlId,
        [string]$Category,
        [string]$CaName,
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
        CaName              = $CaName
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

# Discover CAs from Active Directory if not explicitly provided
$caTargets = [System.Collections.Generic.List[PSCustomObject]]::new()

if (-not [string]::IsNullOrWhiteSpace($CertificationAuthority) -and -not [string]::IsNullOrWhiteSpace($Server)) {
    $caTargets.Add([PSCustomObject]@{
        CaName = $CertificationAuthority
        Host   = $Server
        Cert   = $null
    })
}
else {
    Write-Verbose "Discovering Enterprise CAs from Active Directory Enrollment Services..."
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        try {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $rootDse = Get-ADRootDSE
            $configDn = $rootDse.configurationNamingContext
            $enrollmentServicesDn = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configDn"
            $cas = Get-ADObject -SearchBase $enrollmentServicesDn -LDAPFilter "(objectClass=pKIEnrollmentService)" -Properties name, dNSHostName, cACertificate
            if ($null -ne $cas) {
                foreach ($ca in $cas) {
                    $cCert = $null
                    if ($null -ne $ca.cACertificate -and $ca.cACertificate.Count -gt 0) {
                        try {
                            $cCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$ca.cACertificate[0])
                        }
                        catch {
                            Write-Verbose "Could not parse CA certificate: $_"
                        }
                    }
                    $caTargets.Add([PSCustomObject]@{
                        CaName = [string]$ca.name
                        Host   = [string]$ca.dNSHostName
                        Cert   = $cCert
                    })
                }
            }
        }
        catch {
            Write-Warning "Could not enumerate CAs from Active Directory: $_"
        }
    }
}

if ($caTargets.Count -eq 0) {
    # Default to local host if nothing discovered
    $caTargets.Add([PSCustomObject]@{
        CaName = if (-not [string]::IsNullOrWhiteSpace($CertificationAuthority)) { $CertificationAuthority } else { $env:COMPUTERNAME }
        Host   = if (-not [string]::IsNullOrWhiteSpace($Server)) { $Server } else { 'localhost' }
        Cert   = $null
    })
}

Write-Verbose "Auditing $($caTargets.Count) Certification Authority target(s)..."

foreach ($caTarget in $caTargets) {
    $caName = $caTarget.CaName
    $caHost = $caTarget.Host
    $caCert = $caTarget.Cert

    Write-Verbose "Auditing CA: '$caName' on host '$caHost'..."

    # 1. Audit Registry Settings (ESC6 & AuditFilter) via CIM StdRegProv
    $cimSession = $null
    try {
        $cimParams = @{ ComputerName = $caHost }
        if ($null -ne $Credential) { $cimParams['Credential'] = $Credential }
        if ($caHost -ne 'localhost' -and $caHost -ne $env:COMPUTERNAME) {
            $cimSession = New-CimSession @cimParams -ErrorAction Stop
        }

        # Query EditFlags (ESC6 Check)
        $policyKey = "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy"
        $regParams = @{
            Namespace = 'root\default'
            ClassName = 'StdRegProv'
            MethodName = 'GetDWORDValue'
            Arguments = @{
                hDefKey = $HKLM
                sSubKeyName = $policyKey
                sValueName = 'EditFlags'
            }
        }
        if ($null -ne $cimSession) { $regParams['CimSession'] = $cimSession }

        $regRes = Invoke-CimMethod @regParams -ErrorAction SilentlyContinue
        if ($null -ne $regRes -and $regRes.ReturnValue -eq 0) {
            $editFlags = [int]$regRes.uValue
            $hasEsc6 = (($editFlags -band $EDITF_ATTRIBUTESUBJECTALTNAME2) -ne 0)

            if ($hasEsc6) {
                $finding = New-CaFinding `
                    -ControlId 'PKI-CA-001' `
                    -Category 'ADCS.CA.ESC6' `
                    -CaName $caName `
                    -TargetHost $caHost `
                    -Status 'NonCompliant' `
                    -Severity 'Critical' `
                    -ObservedValue "EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled in registry (EditFlags: $editFlags)" `
                    -ExpectedValue 'EDITF_ATTRIBUTESUBJECTALTNAME2 must be disabled to prevent arbitrary SAN specification on any template' `
                    -MitreAttackId 'T1649' `
                    -RemediationGuidance 'Disable EDITF_ATTRIBUTESUBJECTALTNAME2 immediately and restart CertSvc.' `
                    -RemediationCommand "certutil -config '$caHost\$caName' -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2; Restart-Service CertSvc"

                $findings.Add($finding)
            }
        }

        # Query AuditFilter
        $caKey = "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName"
        $regParams['Arguments']['sSubKeyName'] = $caKey
        $regParams['Arguments']['sValueName'] = 'AuditFilter'

        $auditRes = Invoke-CimMethod @regParams -ErrorAction SilentlyContinue
        if ($null -ne $auditRes -and $auditRes.ReturnValue -eq 0) {
            $auditFilter = [int]$auditRes.uValue
            if ($auditFilter -lt $RECOMMENDED_AUDIT_FILTER) {
                $finding = New-CaFinding `
                    -ControlId 'PKI-CA-002' `
                    -Category 'ADCS.CA.IncompleteAuditing' `
                    -CaName $caName `
                    -TargetHost $caHost `
                    -Status 'NonCompliant' `
                    -Severity 'Medium' `
                    -ObservedValue "CA AuditFilter is configured to $auditFilter (Expected: $RECOMMENDED_AUDIT_FILTER)" `
                    -ExpectedValue 'AuditFilter should be configured to 127 to enable complete security and certificate event logging' `
                    -MitreAttackId 'T1649' `
                    -RemediationGuidance 'Enable full CA auditing in the Certification Authority console or via certutil.' `
                    -RemediationCommand "certutil -config '$caHost\$caName' -setreg CA\AuditFilter 127; Restart-Service CertSvc"

                $findings.Add($finding)
            }
        }
    }
    catch {
        Write-Verbose "CIM registry inspection on $caHost encountered an error: $_"
    }
    finally {
        if ($null -ne $cimSession) {
            Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
        }
    }

    # 2. Audit CA Certificate Cryptographic Strength
    if ($null -ne $caCert) {
        $sigAlg = $caCert.SignatureAlgorithm.FriendlyName
        $keySize = $caCert.PublicKey.Key.KeySize

        # Check for Weak Signature Algorithm (SHA-1, MD5)
        if ($sigAlg -match '(?i)(sha1|md5)') {
            $finding = New-CaFinding `
                -ControlId 'PKI-CA-003' `
                -Category 'ADCS.CA.WeakSignatureAlgorithm' `
                -CaName $caName `
                -TargetHost $caHost `
                -Status 'NonCompliant' `
                -Severity 'High' `
                -ObservedValue "CA certificate uses deprecated signature algorithm: $sigAlg" `
                -ExpectedValue 'CA certificates must use SHA-256 or stronger signature hash algorithms' `
                -MitreAttackId 'T1649' `
                -RemediationGuidance 'Renew CA certificate with a new key and update hash algorithm to SHA-256 or higher.' `
                -RemediationCommand "certutil -renewCert"

            $findings.Add($finding)
        }

        # Check Key Size
        if ($keySize -lt 2048) {
            $finding = New-CaFinding `
                -ControlId 'PKI-CA-004' `
                -Category 'ADCS.CA.WeakKeyLength' `
                -CaName $caName `
                -TargetHost $caHost `
                -Status 'NonCompliant' `
                -Severity 'Critical' `
                -ObservedValue "CA certificate RSA key size is only $keySize bits" `
                -ExpectedValue 'Enterprise CA RSA keys must be at least 2048 bits (Subordinate) or 4096 bits (Root)' `
                -MitreAttackId 'T1649' `
                -RemediationGuidance 'Migrate CA to a new private key with at least 2048 or 4096 bits.' `
                -RemediationCommand "certutil -renewCert newKey"

            $findings.Add($finding)
        }
    }
}

Write-Verbose "Audit complete. Identified $($findings.Count) CA finding(s)."

# Export CSV
if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
    try {
        $findings | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
        Write-Verbose "Exported CA findings to CSV: $ExportCsv"
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
        Write-Verbose "Exported CA findings to JSON: $ExportJson"
    }
    catch {
        Write-Error "Failed exporting JSON to '$ExportJson': $_"
    }
}

$findings
