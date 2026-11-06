<#
.SYNOPSIS
    Audits Active Directory Certificate Services (ADCS) certificate templates for "Certified Pre-Owned" vulnerabilities (ESC1 - ESC4).

.DESCRIPTION
    Test-ADCSCertificateTemplates inspects published and available Active Directory Certificate Templates
    in the Public Key Services configuration container to identify dangerous misconfigurations that allow
    unprivileged domain users to perform privilege escalation or obtain domain persistence:
    - ESC1 (MITRE ATT&CK T1649):
      Client authentication template allows enrollee to supply Subject Alternative Names (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT),
      requires no manager approval or authorized signatures, and is enrollable by low-privileged principals.
    - ESC2:
      Template specifies the Any Purpose EKU (2.5.29.37.0) or SubCA usage with low-privileged enrollment rights.
    - ESC3:
      Template specifies the Certificate Request Agent EKU (1.3.6.1.4.1.311.20.2.1) without enrollment agent restrictions,
      allowing users to act as an enrollment agent and request certificates on behalf of arbitrary domain principals.
    - ESC4:
      Template Access Control List (DACL) grants unprivileged principals write, take-ownership, or write-DACL permissions
      (GenericAll, WriteDacl, WriteOwner, WriteProperty) allowing malicious modification into ESC1.

.PARAMETER Domain
    The Fully Qualified Domain Name (FQDN) of the target Active Directory domain. Defaults to the current domain.

.PARAMETER Server
    Active Directory Domain Controller to query.

.PARAMETER Credential
    PSCredential object containing alternate authentication credentials.

.PARAMETER ConfigurationNC
    Optional explicit Distinguished Name of the Configuration Naming Context.

.PARAMETER PublishedOnly
    Switch specifying whether to restrict evaluation exclusively to templates currently published on active CAs (default: $true).

.PARAMETER ExportCsv
    Optional file path to output findings as CSV.

.PARAMETER ExportJson
    Optional file path to output findings as structured JSON.

.EXAMPLE
    PS C:\> .\PKI\Test-ADCSCertificateTemplates.ps1 -Domain "contoso.local"

    Scans published certificate templates in contoso.local for ESC1-ESC4 vulnerabilities.

.EXAMPLE
    PS C:\> .\PKI\Test-ADCSCertificateTemplates.ps1 -PublishedOnly:$false -ExportJson ".\adcs-template-audit.json"

    Audits all directory certificate templates regardless of publication status and exports findings to JSON.

.NOTES
    Author: Koality Assured Security Operations
    Reference: MITRE ATT&CK T1649 (Steal or Forge Authentication Certificates), SpecterOps "Certified Pre-Owned"
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
    [string]$ConfigurationNC,

    [Parameter()]
    [bool]$PublishedOnly = $true,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportCsv,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# AD CS Name and Enrollment Flags
$CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00010000 # 65536
$CT_FLAG_PEND_ALL_REQUESTS         = 0x00000002 # Manager approval required

# Well-Known EKUs
$EKU_CLIENT_AUTH                   = '1.3.6.1.5.5.7.3.2'
$EKU_SMARTCARD_LOGON               = '1.3.6.1.4.1.311.20.2.2'
$EKU_PKINIT_CLIENT_AUTH            = '1.3.6.1.5.2.3.4'
$EKU_ANY_PURPOSE                   = '2.5.29.37.0'
$EKU_CERT_REQUEST_AGENT            = '1.3.6.1.4.1.311.20.2.1'

# AD CS Extended Rights
$EXTENDED_RIGHT_ENROLL             = '0e10c968-78fb-11d2-90d4-00c04f79befb'
$EXTENDED_RIGHT_AUTOENROLL         = 'a05b8cc2-17bc-402b-a706-e1904e5230f7'

# Low-Privileged Trustee SIDs
$LOW_PRIV_SIDS = @(
    'S-1-1-0',         # Everyone
    'S-1-5-11',        # Authenticated Users
    'S-1-5-32-545'     # Builtin Users
)

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

# Resolve Configuration Naming Context
$configDn = $ConfigurationNC
if ([string]::IsNullOrWhiteSpace($configDn)) {
    try {
        $rootDse = Get-ADRootDSE @adSessionParams
        $configDn = $rootDse.configurationNamingContext
        Write-Verbose "Connected to Domain Controller: $($rootDse.dnsHostName) (Config NC: $configDn)"
    }
    catch {
        Write-Error "Failed to query Active Directory RootDSE: $_"
        throw
    }
}

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function New-TemplateFinding {
    param(
        [string]$ControlId,
        [string]$Category,
        [string]$TemplateName,
        [string]$TargetObject,
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
        TemplateName        = $TemplateName
        TargetObject        = $TargetObject
        Status              = $Status
        Severity            = $Severity
        ObservedValue       = $ObservedValue
        ExpectedValue       = $ExpectedValue
        MitreAttackId       = $MitreAttackId
        RemediationGuidance = $RemediationGuidance
        RemediationCommand  = $RemediationCommand
    }
}

# 1. Discover Published Templates from Enrollment Services
$publishedTemplateNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$enrollmentServicesDn = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configDn"

Write-Verbose "Querying Enrollment Services from '$enrollmentServicesDn'..."
try {
    $cas = Get-ADObject -SearchBase $enrollmentServicesDn -LDAPFilter "(objectClass=pKIEnrollmentService)" -Properties certificateTemplates, dNSHostName @adSessionParams
    if ($null -ne $cas) {
        foreach ($ca in $cas) {
            if ($null -ne $ca.certificateTemplates) {
                foreach ($tName in $ca.certificateTemplates) {
                    $publishedTemplateNames.Add($tName) | Out-Null
                }
            }
        }
    }
    Write-Verbose "Identified $($publishedTemplateNames.Count) distinct published certificate template(s) across $($cas.Count) Enterprise CA(s)."
}
catch {
    Write-Warning "Could not query Enrollment Services container: $_"
}

# 2. Query Certificate Templates
$templatesDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDn"
Write-Verbose "Querying Certificate Templates from '$templatesDn'..."

$templateProperties = @(
    'displayName',
    'name',
    'distinguishedName',
    'msPKI-Certificate-Name-Flag',
    'msPKI-Enrollment-Flag',
    'msPKI-RA-Signature',
    'pKIExtendedKeyUsage',
    'nTSecurityDescriptor'
)

$templates = try {
    Get-ADObject -SearchBase $templatesDn -LDAPFilter "(objectClass=pKICertificateTemplate)" -Properties $templateProperties @adSessionParams
}
catch {
    Write-Error "Failed querying certificate templates from '$templatesDn': $_"
    throw
}

Write-Verbose "Evaluating $($templates.Count) certificate templates..."

foreach ($tmpl in $templates) {
    $tmplName = [string]$tmpl.name
    $tmplDisplayName = [string]$tmpl.displayName
    $tmplDn = [string]$tmpl.distinguishedName

    $isPublished = $publishedTemplateNames.Contains($tmplName)
    if ($PublishedOnly -and -not $isPublished) {
        continue
    }

    $nameFlags = if ($null -ne $tmpl.'msPKI-Certificate-Name-Flag') { [int]$tmpl.'msPKI-Certificate-Name-Flag' } else { 0 }
    $enrollFlags = if ($null -ne $tmpl.'msPKI-Enrollment-Flag') { [int]$tmpl.'msPKI-Enrollment-Flag' } else { 0 }
    $raSignatures = if ($null -ne $tmpl.'msPKI-RA-Signature') { [int]$tmpl.'msPKI-RA-Signature' } else { 0 }
    $ekus = @($tmpl.pKIExtendedKeyUsage)

    $enrolleeSuppliesSan = (($nameFlags -band $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) -ne 0)
    $requiresManagerApproval = (($enrollFlags -band $CT_FLAG_PEND_ALL_REQUESTS) -ne 0)
    $requiresAuthorizedSignature = ($raSignatures -gt 0)

    # Check for Client Authentication EKUs
    $hasClientAuth = ($ekus -contains $EKU_CLIENT_AUTH -or $ekus -contains $EKU_SMARTCARD_LOGON -or $ekus -contains $EKU_PKINIT_CLIENT_AUTH)
    $hasAnyPurpose = ($ekus -contains $EKU_ANY_PURPOSE -or $ekus.Count -eq 0)
    $hasCertAgent = ($ekus -contains $EKU_CERT_REQUEST_AGENT)

    # Inspect Template DACL for Enrollment Rights
    $lowPrivEnrollees = [System.Collections.Generic.List[string]]::new()
    $lowPrivWriteOwners = [System.Collections.Generic.List[string]]::new()

    try {
        $acl = Get-Acl -Path ('AD:\{0}' -f $tmplDn)
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
                continue
            }

            $sid = $ace.SecurityIdentifier.Value
            $identity = $ace.IdentityReference.Value
            $rights = $ace.ActiveDirectoryRights.ToString()
            $objType = $ace.ObjectType.ToString()

            $isLowPriv = ($LOW_PRIV_SIDS -contains $sid)
            if (-not $isLowPriv -and $sid -match '^S-1-5-21-.*-(513|515)$') {
                $isLowPriv = $true # Domain Users or Domain Computers
            }

            if ($isLowPriv) {
                # Check Enrollment Extended Rights
                if ($objType -eq $EXTENDED_RIGHT_ENROLL -or $objType -eq $EXTENDED_RIGHT_AUTOENROLL -or $rights -match 'ExtendedRight|GenericAll') {
                    $lowPrivEnrollees.Add("$identity ($sid)")
                }

                # Check ESC4 Modification Rights
                if ($rights -match '(GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty)') {
                    $lowPrivWriteOwners.Add("$identity ($sid): $rights")
                }
            }
        }
    }
    catch {
        Write-Verbose "Could not inspect ACL for template '$tmplName': $_"
    }

    $canLowPrivEnroll = ($lowPrivEnrollees.Count -gt 0)
    $enrolleeStr = ($lowPrivEnrollees -join '; ')

    # 1. ESC1: Enrollee Supplies Subject + Client Auth + Low-Priv Enrollment + No Approval
    if ($enrolleeSuppliesSan -and ($hasClientAuth -or $hasAnyPurpose) -and -not $requiresManagerApproval -and -not $requiresAuthorizedSignature -and $canLowPrivEnroll) {
        $finding = New-TemplateFinding `
            -ControlId 'PKI-ESC-001' `
            -Category 'ADCS.Templates.ESC1' `
            -TemplateName $tmplName `
            -TargetObject $tmplDn `
            -Status 'NonCompliant' `
            -Severity 'Critical' `
            -ObservedValue "ESC1 Vulnerable: Enrollee supplies SAN (0x10000), ClientAuth/AnyPurpose EKU present, no manager approval, low-priv enrollees: $enrolleeStr" `
            -ExpectedValue 'Templates with client authentication must build subject from Active Directory and require manager approval' `
            -MitreAttackId 'T1649' `
            -RemediationGuidance 'Change Subject Name setting to "Build from this Active Directory information" or enforce CA Certificate Manager approval.' `
            -RemediationCommand "Set-ADObject -Identity '$tmplDn' -Clear 'msPKI-Certificate-Name-Flag'"

        $findings.Add($finding)
    }

    # 2. ESC2: Any Purpose EKU or No EKU + Low-Priv Enrollment + No Approval
    if ($hasAnyPurpose -and -not $requiresManagerApproval -and -not $requiresAuthorizedSignature -and $canLowPrivEnroll) {
        $finding = New-TemplateFinding `
            -ControlId 'PKI-ESC-002' `
            -Category 'ADCS.Templates.ESC2' `
            -TemplateName $tmplName `
            -TargetObject $tmplDn `
            -Status 'NonCompliant' `
            -Severity 'High' `
            -ObservedValue "ESC2 Vulnerable: Template contains Any Purpose EKU (2.5.29.37.0) or empty EKUs with low-priv enrollment: $enrolleeStr" `
            -ExpectedValue 'Templates must define explicit, granular EKUs rather than Any Purpose or SubCA capabilities' `
            -MitreAttackId 'T1649' `
            -RemediationGuidance 'Replace Any Purpose EKU with specific single-purpose EKUs (e.g., Server Authentication or Client Authentication).' `
            -RemediationCommand "# Modify certificate template extensions in Certificate Templates Console"

        $findings.Add($finding)
    }

    # 3. ESC3: Certificate Request Agent EKU (Enrollment Agent)
    if ($hasCertAgent -and -not $requiresManagerApproval -and $canLowPrivEnroll) {
        $finding = New-TemplateFinding `
            -ControlId 'PKI-ESC-003' `
            -Category 'ADCS.Templates.ESC3' `
            -TemplateName $tmplName `
            -TargetObject $tmplDn `
            -Status 'NonCompliant' `
            -Severity 'Critical' `
            -ObservedValue "ESC3 Vulnerable: Template specifies Certificate Request Agent EKU with low-priv enrollment: $enrolleeStr" `
            -ExpectedValue 'Enrollment Agent templates must strictly restrict enrollment to designated PKI administrators' `
            -MitreAttackId 'T1649' `
            -RemediationGuidance 'Restrict enrollment permissions on this template and configure Enrollment Agent Restrictions on the CA.' `
            -RemediationCommand "# Revoke low-privileged enrollment permissions and configure CA Enrollment Agent Restrictions"

        $findings.Add($finding)
    }

    # 4. ESC4: Vulnerable Template DACL (Low-Privilege Write/Modify)
    if ($lowPrivWriteOwners.Count -gt 0) {
        $writeStr = ($lowPrivWriteOwners -join '; ')
        $finding = New-TemplateFinding `
            -ControlId 'PKI-ESC-004' `
            -Category 'ADCS.Templates.ESC4' `
            -TemplateName $tmplName `
            -TargetObject $tmplDn `
            -Status 'NonCompliant' `
            -Severity 'Critical' `
            -ObservedValue "ESC4 Vulnerable: Low-privileged principals have write/modify permissions on template: $writeStr" `
            -ExpectedValue 'Certificate template objects must only be writable by Enterprise Admins and Domain Admins' `
            -MitreAttackId 'T1649' `
            -RemediationGuidance 'Audit template permissions and remove write/modify rights granted to unprivileged identities.' `
            -RemediationCommand "dsacls '$tmplDn' /R '$($lowPrivWriteOwners[0].Split(':')[0])'"

        $findings.Add($finding)
    }
}

Write-Verbose "Audit complete. Identified $($findings.Count) ADCS template finding(s)."

# Export CSV
if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
    try {
        $findings | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
        Write-Verbose "Exported template findings to CSV: $ExportCsv"
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
        Write-Verbose "Exported template findings to JSON: $ExportJson"
    }
    catch {
        Write-Error "Failed exporting JSON to '$ExportJson': $_"
    }
}

$findings
