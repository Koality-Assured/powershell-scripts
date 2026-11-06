<#
.SYNOPSIS
    Audits Active Directory Federation Services (ADFS) Relying Party Trusts for permit-all rules, weak crypto, and unencrypted claims.

.DESCRIPTION
    Test-AdfsRelyingPartyTrustPosture evaluates configured Relying Party Trusts (RPTs) on an ADFS farm to detect
    authentication bypass, token interception, and compliance violations:
    - Overly Permissive Issuance Rules (MITRE ATT&CK T1556):
      Detects wildcard "Permit All" issuance authorization rules that lack conditional access, group membership filters,
      or Multi-Factor Authentication (MFA) enforcement.
    - Deprecated Signature Hash Algorithms:
      Flags relying party trusts configured with legacy SHA-1 (rsa-sha1) signatures rather than SHA-256.
    - Unencrypted Claims & Assertions (MITRE ATT&CK T1539, T1557):
      Identifies federation trusts where EncryptClaims is disabled ($false) or missing an encryption certificate,
      allowing SAML assertions to traverse client browsers in plaintext.
    - Cleartext HTTP Endpoints:
      Audits WS-Federation and SAML Assertion Consumer Service (ACS) endpoints for insecure HTTP protocol prefixes.

.PARAMETER Name
    Optional specific Relying Party Trust name(s) to evaluate. If omitted, audits all configured trusts.

.PARAMETER EnforceEncryption
    Switch specifying whether token encryption is mandatory for all active relying parties (default: $true).

.PARAMETER ExportCsv
    Optional file path to output findings as CSV.

.PARAMETER ExportJson
    Optional file path to output findings as structured JSON.

.EXAMPLE
    PS C:\> .\ADFS\Test-AdfsRelyingPartyTrustPosture.ps1

    Audits all relying party trusts on the local ADFS farm.

.EXAMPLE
    PS C:\> .\ADFS\Test-AdfsRelyingPartyTrustPosture.ps1 -Name "Office365", "Salesforce" -ExportJson ".\rpt-audit.json"

    Audits specific relying parties and exports findings to JSON.

.NOTES
    Author: Koality Assured Security Operations
    Reference: MITRE ATT&CK T1556 (Modify Authentication Process), T1539 (Steal Web Session Cookie)
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Name,

    [Parameter()]
    [bool]$EnforceEncryption = $true,

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

function New-RptFinding {
    param(
        [string]$ControlId,
        [string]$Category,
        [string]$RelyingPartyName,
        [string]$Identifier,
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
        RelyingPartyName    = $RelyingPartyName
        Identifier          = $Identifier
        Status              = $Status
        Severity            = $Severity
        ObservedValue       = $ObservedValue
        ExpectedValue       = $ExpectedValue
        MitreAttackId       = $MitreAttackId
        RemediationGuidance = $RemediationGuidance
        RemediationCommand  = $RemediationCommand
    }
}

Write-Verbose "Querying ADFS Relying Party Trusts..."

$trusts = @()
if (Get-Command -Name Get-AdfsRelyingPartyTrust -ErrorAction SilentlyContinue) {
    try {
        $trusts = if ($null -ne $Name -and $Name.Count -gt 0) {
            Get-AdfsRelyingPartyTrust -Name $Name -ErrorAction SilentlyContinue
        } else {
            Get-AdfsRelyingPartyTrust -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Warning "Failed executing Get-AdfsRelyingPartyTrust: $_"
    }
}

Write-Verbose "Evaluating $(@($trusts).Count) Relying Party Trust(s)..."

foreach ($rpt in $trusts) {
    $rptName = [string]$rpt.Name
    $identifier = [string]($rpt.Identifier -join '; ')
    $enabled = $rpt.Enabled

    if (-not $enabled) {
        continue
    }

    # 1. Audit Issuance Authorization Rules (Permit All check)
    $authRules = [string]$rpt.IssuanceAuthorizationRules
    if ($authRules -match '=>\s*issue\s*\(\s*Type\s*=\s*"http://schemas\.microsoft\.com/authorization/claims/permit"\s*,\s*Value\s*=\s*"true"\s*\)\s*;') {
        # Check if there are conditional clauses before the issue statement
        $lines = $authRules -split "`r?`n"
        foreach ($line in $lines) {
            if ($line -match '^\s*=>\s*issue\s*\(\s*Type\s*=\s*"http://schemas\.microsoft\.com/authorization/claims/permit"') {
                $finding = New-RptFinding `
                    -ControlId 'ADFS-RPT-001' `
                    -Category 'ADFS.RPT.PermitAllAuthorization' `
                    -RelyingPartyName $rptName `
                    -Identifier $identifier `
                    -Status 'NonCompliant' `
                    -Severity 'High' `
                    -ObservedValue 'Issuance authorization contains an unconditional "Permit All" rule with no MFA or group conditions' `
                    -ExpectedValue 'Relying parties must enforce conditional access, MFA, or group-based issuance authorization' `
                    -MitreAttackId 'T1556' `
                    -RemediationGuidance 'Update Claim Issuance Authorization Rules to restrict access to authorized security groups or enforce MFA.' `
                    -RemediationCommand "# Configure Issuance Authorization Rules in ADFS Management Console for '$rptName'"

                $findings.Add($finding)
                break
            }
        }
    }

    # 2. Audit Signature Hash Algorithm (SHA-1 Check)
    $sigAlg = [string]$rpt.SignatureAlgorithm
    if ($sigAlg -match '(?i)rsa-sha1|sha1') {
        $finding = New-RptFinding `
            -ControlId 'ADFS-RPT-002' `
            -Category 'ADFS.RPT.WeakSignatureAlgorithm' `
            -RelyingPartyName $rptName `
            -Identifier $identifier `
            -Status 'NonCompliant' `
            -Severity 'High' `
            -ObservedValue "Signature algorithm is configured to SHA-1 ($sigAlg)" `
            -ExpectedValue 'Signature algorithm must be SHA-256 (http://www.w3.org/2001/04/xmldsig-more#rsa-sha256)' `
            -MitreAttackId 'T1556' `
            -RemediationGuidance 'Configure relying party trust to use SHA-256 signature algorithm.' `
            -RemediationCommand "Set-AdfsRelyingPartyTrust -TargetName '$rptName' -SignatureAlgorithm 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'"

        $findings.Add($finding)
    }

    # 3. Audit Encryption of SAML Assertions
    $encryptClaims = $rpt.EncryptClaims
    $hasEncCert = ($null -ne $rpt.EncryptionCertificate)

    if ($EnforceEncryption -and (-not $encryptClaims -or -not $hasEncCert)) {
        $finding = New-RptFinding `
            -ControlId 'ADFS-RPT-003' `
            -Category 'ADFS.RPT.UnencryptedAssertions' `
            -RelyingPartyName $rptName `
            -Identifier $identifier `
            -Status 'NonCompliant' `
            -Severity 'Medium' `
            -ObservedValue "Token encryption is disabled or missing certificate (EncryptClaims: $encryptClaims, HasCert: $hasEncCert)" `
            -ExpectedValue 'SAML assertions should be encrypted to protect identity claims and tokens from interception' `
            -MitreAttackId 'T1539' `
            -RemediationGuidance 'Import the relying party public encryption certificate and enable EncryptClaims.' `
            -RemediationCommand "Set-AdfsRelyingPartyTrust -TargetName '$rptName' -EncryptClaims `$true"

        $findings.Add($finding)
    }

    # 4. Audit Insecure HTTP Endpoints
    $wsFedEndpoint = [string]$rpt.WSFederationEndpoint
    if ($wsFedEndpoint -match '^http://') {
        $finding = New-RptFinding `
            -ControlId 'ADFS-RPT-004' `
            -Category 'ADFS.RPT.InsecureHttpEndpoint' `
            -RelyingPartyName $rptName `
            -Identifier $identifier `
            -Status 'NonCompliant' `
            -Severity 'Critical' `
            -ObservedValue "WS-Federation endpoint uses unencrypted HTTP: $wsFedEndpoint" `
            -ExpectedValue 'All federation endpoints must enforce HTTPS transport encryption' `
            -MitreAttackId 'T1557' `
            -RemediationGuidance 'Update relying party endpoint URL to use HTTPS.' `
            -RemediationCommand "Set-AdfsRelyingPartyTrust -TargetName '$rptName' -WSFederationEndpoint '$($wsFedEndpoint -replace '^http://', 'https://')'"

        $findings.Add($finding)
    }

    $samlEndpoints = @($rpt.SamlEndpoints)
    foreach ($sep in $samlEndpoints) {
        $loc = [string]$sep.Location
        if ($loc -match '^http://') {
            $finding = New-RptFinding `
                -ControlId 'ADFS-RPT-005' `
                -Category 'ADFS.RPT.InsecureHttpEndpoint' `
                -RelyingPartyName $rptName `
                -Identifier $identifier `
                -Status 'NonCompliant' `
                -Severity 'Critical' `
                -ObservedValue "SAML endpoint uses unencrypted HTTP: $loc" `
                -ExpectedValue 'All SAML assertion consumer service (ACS) endpoints must enforce HTTPS' `
                -MitreAttackId 'T1557' `
                -RemediationGuidance 'Update SAML endpoint configuration to mandate HTTPS.' `
                -RemediationCommand "# Update SAML endpoint to HTTPS in Relying Party Trust properties"

            $findings.Add($finding)
        }
    }
}

Write-Verbose "Audit complete. Identified $($findings.Count) Relying Party Trust finding(s)."

# Export CSV
if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
    try {
        $findings | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
        Write-Verbose "Exported RPT findings to CSV: $ExportCsv"
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
        Write-Verbose "Exported RPT findings to JSON: $ExportJson"
    }
    catch {
        Write-Error "Failed exporting JSON to '$ExportJson': $_"
    }
}

$findings
