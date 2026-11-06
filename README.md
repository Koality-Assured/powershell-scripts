<div align="center">

![POWERSHELL SCRIPTS Banner](assets/powershell-scripts-banner.svg)

# Powershell Scripts

<p align="center">
  <img src="assets/powershell-scripts-logo.svg" alt="POWERSHELL SCRIPTS Logo" width="128" height="128" />
</p>

**Production-Grade PowerShell 7+ Automation for Active Directory Threat Hunting, PKI/ADCS Auditing, ADFS Security, and Infrastructure Hardening**

[![CI](https://github.com/Koality-Assured/powershell-scripts/actions/workflows/ci.yml/badge.svg)](https://github.com/Koality-Assured/powershell-scripts/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Domain: powershell--scripts](https://img.shields.io/badge/domain-powershell--scripts-blueviolet.svg)](#)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-yellow.svg)](https://conventionalcommits.org)

</div>

---

## Tool Matrix

| Directory | Script Name | Focus Area | Key Capabilities |
| :--- | :--- | :--- | :--- |
| `ActiveDirectory/` | [`Manage-ADComputer.ps1`](#manage-adcomputerps1) | Identity Lifecycle | Pre-stages AD computer accounts with delegated join rights; joins systems using CIM. |
| `ActiveDirectory/` | [`Test-DCSyncReplicationRights.ps1`](#test-dcsyncreplicationrightsps1) | Threat Hunting | Discovers anomalous principals possessing DCSync replication rights on AD partition heads. |
| `ActiveDirectory/` | [`Get-LocalAdminMembers.ps1`](#get-localadminmembersps1) | Endpoint Auditing | Recursively audits members of local `Administrators` (S-1-5-32-544) via CIM with domain expansion. |
| `ActiveDirectory/` | [`Get-StaleADAccounts.ps1`](#get-staleadaccountsps1) | AD Hygiene | Discovers inactive user/computer accounts using native cmdlets; supports `-WhatIf` remediation. |
| `ActiveDirectory/` | [`Test-ADKerberosDelegation.ps1`](#test-adkerberosdelegationps1) | Threat Hunting | Audits Unconstrained, Constrained (S4U2Self), and RBCD delegation attack surfaces with remediation. |
| `ActiveDirectory/` | [`Test-ADRoastingExposure.ps1`](#test-adroastingexposureps1) | Threat Hunting | Detects AS-REP Roasting (`DONT_REQ_PREAUTH`), Kerberoasting SPNs, and weak RC4 encryption. |
| `ActiveDirectory/` | [`Test-ADAdminSDHolderDrift.ps1`](#test-adadminsdholderdriftps1) | Privilege Hygiene | Audits AdminSDHolder DACL poisoning, orphaned `adminCount=1` accounts, and restores ACL inheritance. |
| `ActiveDirectory/` | [`Test-ADLapsHygiene.ps1`](#test-adlapshygieneps1) | Endpoint Security | Evaluates legacy vs Windows LAPS coverage, plaintext storage (`msLAPS-Password`), and reader ACLs. |
| `ActiveDirectory/` | [`Test-ADGroupPolicyHygiene.ps1`](#test-adgrouppolicyhygieneps1) | Infrastructure | Audits GPO/SYSVOL DACL permissions, detects unlinked GPOs, and scans for legacy `cpassword` leaks. |
| `ActiveDirectory/` | [`Test-ADIDNSZoneSecurity.ps1`](#test-adidnszonesecurityps1) | DNS Security | Detects non-secure dynamic updates, scavenging hygiene, wildcard records, and WPAD spoofing risk. |
| `PKI/` | [`Test-ADCSCertificateTemplates.ps1`](#test-adcscertificatetemplatesps1) | ADCS / PKI | Audits certificate templates for Certified Pre-Owned vulnerabilities (**ESC1**, **ESC2**, **ESC3**, **ESC4**). |
| `PKI/` | [`Test-ADCSAuthorityPosture.ps1`](#test-adcsauthoritypostureps1) | ADCS / PKI | Audits Enterprise CAs for **ESC6** (`EDITF_ATTRIBUTESUBJECTALTNAME2`), weak crypto, and audit filters. |
| `ADFS/` | [`Test-AdfsCertificateSecurity.ps1`](#test-adfscertificatesecurityps1) | ADFS Security | Audits Token-Signing certs, rollover health, and Golden SAML DKM container read permissions. |
| `ADFS/` | [`Test-AdfsRelyingPartyTrustPosture.ps1`](#test-adfsrelyingpartytrustpostureps1) | ADFS Security | Flags permit-all issuance rules, deprecated SHA-1 signatures, unencrypted claims, and HTTP endpoints. |
| `ADFS/` | [`Test-AdfsExtranetLockoutPosture.ps1`](#test-adfsextranetlockoutpostureps1) | ADFS Hardening | Audits Extranet Smart Lockout (ESL) modes and aligns thresholds against AD lockout policy. |
| `Security/` | [`Get-ExpiringCertificates.ps1`](#get-expiringcertificatesps1) | PKI & Monitoring | Scans local/remote stores and Microsoft CAs for expiring certificates; sends Teams/Slack webhooks. |
| `Security/` | [`Set-WindowsTlsHardening.ps1`](#set-windowstlshardeningps1) | Platform Hardening | Enforces TLS 1.2/1.3 in SCHANNEL; disables SSL 2.0/3.0, PCT, and weak ciphers with `-AuditOnly`. |
| `Security/` | [`Test-GraphQLIntrospection.ps1`](#test-graphqlintrospectionps1) | API Security | Evaluates GraphQL API endpoints for schema introspection disclosure and sensitive fields. |
| `Utility/` | [`Convert-YamlToPSCustomObject.ps1`](#convert-yamltopscustomobjectps1) | Data Transformation | Recursively deserializes YAML graphs and hashtables into native `[PSCustomObject]` trees. |
| `Utility/` | [`Compare-WindowsHotfixes.ps1`](#compare-windowshotfixesps1) | Fleet Patching | Headless multi-host patch auditing matrix identifying missing Windows security updates. |

---

## Active Directory Automation

### `Manage-ADComputer.ps1`
Advanced function providing structured pre-staging of Active Directory computer accounts and domain-join orchestration.

- **Parameter Sets**:
  - `Create`: Pre-stages an account in a destination OU, sets description, and delegates join permissions via `ManagedBy`.
  - `Join`: Assesses domain state via CIM (`Win32_ComputerSystem`) and joins the local or remote computer to the domain.
- **Safety**: Fully integrates `SupportsShouldProcess` (`-WhatIf`, `-Confirm`).

```powershell
# Pre-stage a new workstation with delegated join permissions
.\ActiveDirectory\Manage-ADComputer.ps1 -ComputerName "WKSTN-SEC-01" `
    -OUDistinguishedName "OU=Workstations,DC=contoso,DC=local" `
    -Description "SecOps Tier-2 Analyst Workstation" `
    -Manager "SecOps-Deployment-Team"

# Join current machine to domain
$cred = Get-Credential
.\ActiveDirectory\Manage-ADComputer.ps1 -Action Join -Domain "contoso.local" -Credential $cred -Restart
```

### `Test-DCSyncReplicationRights.ps1`
Threat hunting and defensive assessment utility checking Active Directory partition heads (Domain, Configuration, Schema) for dangerous replication rights (MITRE ATT&CK T1003.006).

- **Evaluated Extended Rights**:
  - `DS-Replication-Get-Changes-All` (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`)
  - `DS-Replication-Get-Changes` (`89e95b76-444d-4c62-991a-0facbeda640c`)
  - `GenericAll` / `WriteDacl` on partition root objects
- **Filtering**: Filters legitimate domain controllers and administrative groups to highlight non-default accounts capable of dumping password hashes via Mimikatz / DCSync.

```powershell
# Audit domain head for anomalous DCSync rights
.\ActiveDirectory\Test-DCSyncReplicationRights.ps1 -Domain "contoso.local" -ExportJson ".\dcsync-audit.json"
```

### `Test-ADKerberosDelegation.ps1`
Enterprise Kerberos delegation auditing utility evaluating Unconstrained, Constrained, and Resource-Based Constrained Delegation (RBCD) risks (MITRE ATT&CK T1558, T1134).

- **Evaluated Controls**:
  - `AD-DELEG-001`: Unconstrained delegation (`TRUSTED_FOR_DELEGATION` 0x80000) on non-Domain Controller systems.
  - `AD-DELEG-002`: Constrained delegation with Protocol Transition (`TRUSTED_TO_AUTH_FOR_DELEGATION` / S4U2Self).
  - `AD-DELEG-003`: Administrative accounts (`adminCount=1`) missing the `NOT_DELEGATED` protection flag.
  - `AD-DELEG-004`: Anomalous trustee entries in `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD backdoors).
- **Remediation**: Built-in `-Remediate` switch with `-WhatIf` support to revoke unconstrained delegation and protect privileged accounts.

```powershell
# Audit domain-wide Kerberos delegation posture including RBCD
.\ActiveDirectory\Test-ADKerberosDelegation.ps1 -Domain "contoso.local" -IncludeRBCD -ExportJson ".\delegation-audit.json"

# Remediate unconstrained delegation on a compromised host
.\ActiveDirectory\Test-ADKerberosDelegation.ps1 -Identity "SRV-APPS-01" -Remediate -WhatIf
```

### `Test-ADRoastingExposure.ps1`
Threat hunting tool assessing AS-REP Roasting and Kerberoasting attack surfaces across domain accounts (MITRE ATT&CK T1558.003, T1558.004).

- **Evaluated Controls**:
  - `AD-ROAST-001`: Accounts configured with `DONT_REQ_PREAUTH` (0x400000) enabling offline AS-REP hash cracking.
  - `AD-ROAST-002`: Privileged accounts (`adminCount=1`) with configured Service Principal Names (SPNs).
  - `AD-ROAST-003`: SPN accounts lacking AES encryption support in `msDS-SupportedEncryptionTypes` (forcing RC4-HMAC).
  - `AD-ROAST-004`: Kerberoastable service accounts with stale unrotated passwords exceeding the configured threshold.
- **Remediation**: Re-enforces Kerberos pre-authentication under `-WhatIf`.

```powershell
# Scan for AS-REP and Kerberoastable accounts with a 90-day password freshness threshold
.\ActiveDirectory\Test-ADRoastingExposure.ps1 -Domain "contoso.local" -MaxPasswordAgeDays 90 -ExportCsv ".\roasting-audit.csv"
```

### `Test-ADAdminSDHolderDrift.ps1`
Audits the Security Descriptor Propagator (SDProp) template container and detects orphaned `adminCount=1` accounts (MITRE ATT&CK T1484, T1078.002, T1098).

- **Evaluated Controls**:
  - `AD-SDPROP-001`: Non-standard Access Control Entries on `CN=AdminSDHolder,CN=System,DC=...` (persistence backdoors).
  - `AD-SDPROP-002`: Accounts with `adminCount=1` that no longer belong to any protected group, retaining disabled ACL inheritance (`SE_DACL_PROTECTED`).
- **Remediation**: Resets `adminCount=0` and re-enables parent OU inheritance using `-Remediate`.

```powershell
# Audit AdminSDHolder permissions and detect privilege drift
.\ActiveDirectory\Test-ADAdminSDHolderDrift.ps1 -Domain "contoso.local"

# Restore OU inheritance and reset adminCount on orphaned accounts
.\ActiveDirectory\Test-ADAdminSDHolderDrift.ps1 -Remediate -WhatIf
```

### `Test-ADLapsHygiene.ps1`
Evaluates local administrator password governance, legacy vs Windows LAPS deployment, and attribute ACL exposure (MITRE ATT&CK T1003, T1078.002).

- **Evaluated Controls**:
  - `AD-LAPS-001`: Computer accounts missing both legacy and Windows LAPS management.
  - `AD-LAPS-002`: Windows LAPS configured to store passwords in cleartext (`msLAPS-Password`) instead of encrypted (`msLAPS-EncryptedPassword`).
  - `AD-LAPS-003`: Legacy cleartext LAPS (`ms-Mcs-AdmPwd`) usage.
  - `AD-LAPS-004`: Computer accounts with expired LAPS passwords indicative of client rotation failure.
  - `AD-LAPS-005`: Low-privileged trustees granted read or decryption permissions over LAPS password attributes.

```powershell
# Audit LAPS deployment and permissions within a specific OU
.\ActiveDirectory\Test-ADLapsHygiene.ps1 -Domain "contoso.local" -SearchBase "OU=Workstations,DC=contoso,DC=local"
```

### `Test-ADGroupPolicyHygiene.ps1`
Performs comprehensive posture auditing of Group Policy infrastructure and SYSVOL file storage (MITRE ATT&CK T1484.001, T1552.006).

- **Evaluated Controls**:
  - `AD-GPO-001`: Unprivileged principals granted modify/write permissions on AD `groupPolicyContainer` objects.
  - `AD-GPO-002`: Unprivileged principals granted write permissions on SYSVOL GPO file folders.
  - `AD-GPO-003`: Unlinked and orphaned GPOs retaining stale configuration surface.
  - `AD-GPO-004`: Embedded Group Policy Preferences `cpassword` credentials in SYSVOL XML files (MS14-025) with automated AES decryption.

```powershell
# Audit GPO DACLs and scan SYSVOL for embedded credentials
.\ActiveDirectory\Test-ADGroupPolicyHygiene.ps1 -Domain "contoso.local" -ScanCpassword -ExportJson ".\gpo-hygiene.json"
```

### `Test-ADIDNSZoneSecurity.ps1`
Audits Active Directory-Integrated DNS (ADIDNS) zones for dynamic update exposure, record tampering, and WPAD spoofing (MITRE ATT&CK T1565.002, T1557.001).

- **Evaluated Controls**:
  - `AD-DNS-001`: Insecure dynamic updates enabled (`NonsecureAndSecure`), allowing unauthenticated record overwrites.
  - `AD-DNS-002`: DNS zone aging and scavenging disabled, creating dangling IP takeover risks.
  - `AD-DNS-003`: Wildcard (`*`) DNS records routing non-existent subdomains.
  - `AD-DNS-004`: Absence of static WPAD record sinkhole, allowing unprivileged users to register WPAD for traffic interception.

```powershell
# Audit ADIDNS zone security settings and WPAD posture
.\ActiveDirectory\Test-ADIDNSZoneSecurity.ps1 -ZoneName "contoso.local"
```

### `Get-LocalAdminMembers.ps1`
Audits the local `Administrators` security group across server fleets using the language-independent well-known SID `S-1-5-32-544`.

- **Features**:
  - Uses CIM sessions (`Win32_GroupUser` / `Win32_Group`) to avoid deprecated WMI cmdlets.
  - `-RecurseDomainGroups`: When an Active Directory domain group is present in the local Administrators group, recurses into Active Directory to identify the effective user accounts.
  - Structured pipeline output and JSON/CSV export.

```powershell
# Audit a server fleet and expand domain security groups
"SRV-APP-01", "SRV-APP-02" | .\ActiveDirectory\Get-LocalAdminMembers.ps1 -RecurseDomainGroups -ExportCsv ".\admins.csv"
```

### `Get-StaleADAccounts.ps1`
Replaces legacy Quest ActiveRoles snap-ins with modern native Active Directory cmdlets to discover dormant or never-logged-in user and computer accounts.

- **Capabilities**:
  - Evaluates replicated `lastLogonTimestamp`, `pwdLastSet`, and `whenCreated` attributes.
  - Configurable threshold (e.g. `-InactivityDays 90`).
  - Automated remediation actions (`ReportOnly`, `Disable`, `MoveToOU`) with complete `-WhatIf` protection.

```powershell
# Find user accounts inactive for over 90 days in a specific OU
.\ActiveDirectory\Get-StaleADAccounts.ps1 -AccountType User -InactivityDays 90 -SearchBase "OU=Staff,DC=contoso,DC=local"
```

---

## Public Key Infrastructure (PKI / ADCS)

### `Test-ADCSCertificateTemplates.ps1`
Audits published and configuration-partition Active Directory Certificate Templates for "Certified Pre-Owned" privilege escalation vectors (MITRE ATT&CK T1649).

- **Evaluated Vulnerabilities**:
  - **ESC1**: Client authentication template allowing enrollees to supply custom SAN (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`), requiring no manager approval, with low-privilege enrollment permissions.
  - **ESC2**: Template specifying Any Purpose EKU (`2.5.29.37.0`) or empty EKUs (SubCA capability) with low-privilege enrollment.
  - **ESC3**: Template specifying Certificate Request Agent EKU (`1.3.6.1.4.1.311.20.2.1`) without enrollment agent restrictions.
  - **ESC4**: Template DACL granting unprivileged principals write, take-ownership, or write-DACL rights.

```powershell
# Audit published certificate templates for ESC1-ESC4 vulnerabilities
.\PKI\Test-ADCSCertificateTemplates.ps1 -Domain "contoso.local" -PublishedOnly -ExportJson ".\adcs-audit.json"
```

### `Test-ADCSAuthorityPosture.ps1`
Audits Enterprise Certification Authority host configuration, ESC6 registry posture, and cryptographic health (MITRE ATT&CK T1649).

- **Evaluated Controls**:
  - **PKI-CA-001 (ESC6)**: CA registry configured with `EDITF_ATTRIBUTESUBJECTALTNAME2` (0x40000), globally permitting user-defined SANs on all issued certificates.
  - **PKI-CA-002**: Incomplete CA event auditing (`AuditFilter` < 127).
  - **PKI-CA-003**: Deprecated CA signature algorithms (SHA-1 / MD5).
  - **PKI-CA-004**: Weak RSA key length (< 2048-bit for subordinate CAs, < 4096-bit for root CAs).

```powershell
# Audit all Enterprise CAs discovered in forest
.\PKI\Test-ADCSAuthorityPosture.ps1 -ExportCsv ".\ca-posture.csv"
```

---

## Active Directory Federation Services (ADFS)

### `Test-AdfsCertificateSecurity.ps1`
Audits ADFS token-signing certificates, rollover lifecycle, and Golden SAML attack surface (MITRE ATT&CK T1606.002, T1552.004).

- **Evaluated Controls**:
  - `ADFS-CERT-001`: `AutoCertificateRollover` disabled on farm without external management.
  - `ADFS-CERT-002` / `ADFS-CERT-003`: Expired or soon-to-expire Token-Signing and Token-Decrypting certificates.
  - `ADFS-CERT-004`: Golden SAML attack surface: unauthorized read permissions on Active Directory DKM container (`CN=ADFS,CN=Microsoft,CN=Program Data,DC=...`) exposing the master token encryption key.

```powershell
# Audit ADFS farm certificate health and DKM container permissions
.\ADFS\Test-AdfsCertificateSecurity.ps1 -AdfsServer "adfs01.contoso.local" -ExpirationThresholdDays 30
```

### `Test-AdfsRelyingPartyTrustPosture.ps1`
Evaluates Relying Party Trusts (RPTs) for authentication bypass, weak crypto, and unencrypted claims (MITRE ATT&CK T1556, T1539, T1557).

- **Evaluated Controls**:
  - `ADFS-RPT-001`: Wildcard unconditional "Permit All" issuance authorization rules lacking MFA or group conditions.
  - `ADFS-RPT-002`: Deprecated SHA-1 (`rsa-sha1`) digital signature algorithms.
  - `ADFS-RPT-003`: Unencrypted SAML assertions (`EncryptClaims = $false` or missing encryption certificate).
  - `ADFS-RPT-004` / `ADFS-RPT-005`: Insecure HTTP endpoints in WS-Federation and SAML ACS configurations.

```powershell
# Audit all relying party trusts on local ADFS farm
.\ADFS\Test-AdfsRelyingPartyTrustPosture.ps1 -EnforceEncryption -ExportJson ".\rpt-posture.json"
```

### `Test-AdfsExtranetLockoutPosture.ps1`
Evaluates Extranet Smart Lockout (ESL) configuration against Active Directory domain password and lockout policies (MITRE ATT&CK T1498, T1110.001).

- **Evaluated Controls**:
  - `ADFS-ESL-001`: Insecure lockout mode (`ADFSOldFallback` or `ADFSSmartLockoutLogOnly`) exposing internal accounts to external DoS lockouts.
  - `ADFS-ESL-002`: Flawed threshold ratio: `ExtranetLockoutThreshold` >= Active Directory `lockoutThreshold`.
  - `ADFS-ESL-003`: Short observation window (< 30 minutes).
- **Remediation**: Automatically switches mode to `ADFSSmartLockoutEnforce` and aligns thresholds under `-WhatIf`.

```powershell
# Audit Extranet Smart Lockout and align threshold with AD policy
.\ADFS\Test-AdfsExtranetLockoutPosture.ps1 -Remediate -WhatIf
```

---

## Security & Hardening

### `Get-ExpiringCertificates.ps1`
Automates certificate lifecycle management across local/remote certificate stores and Microsoft Certificate Authorities.

- **Alerting**: Dispatches structured alerts via Microsoft Teams Adaptive Cards or Slack webhooks when certificates approach expiration.
- **Threshold**: Configurable expiration threshold in days (e.g. `-ThresholdDays 30`).

```powershell
# Audit local certificate store and dispatch webhook alert
.\Security\Get-ExpiringCertificates.ps1 -StorePath 'Cert:\LocalMachine\My' -ThresholdDays 30 `
    -WebhookUrl "https://contoso.webhook.office.com/webhookb2/..."
```

### `Set-WindowsTlsHardening.ps1`
Hardens Windows SCHANNEL cryptographic configuration in compliance with NIST SP 800-52r2 and CIS benchmarks.

- **Protections**:
  - Disables: SSL 2.0, SSL 3.0, PCT 1.0, Multi-Protocol Unified Hello, TLS 1.0, TLS 1.1, NULL, DES, 3DES, RC2, RC4, MD5.
  - Enforces: TLS 1.2, TLS 1.3, AES 128/256, SHA-256/384/512, ECDHE forward secrecy cipher suites.
- **Audit Mode**: `-AuditOnly` switch evaluates current registry state against the baseline without modifying the host.
- **Backup**: Automatically exports a `.reg` backup of SCHANNEL before applying modifications.

```powershell
# Check current compliance status without modifying registry
.\Security\Set-WindowsTlsHardening.ps1 -AuditOnly

# Apply hardening with automated registry backup
.\Security\Set-WindowsTlsHardening.ps1 -BackupPath "C:\Backups\PreHardening_SCHANNEL.reg"
```

### `Test-GraphQLIntrospection.ps1`
Defensive security testing tool assessing whether GraphQL endpoints have schema introspection enabled.

- **Features**:
  - Sends schema introspection queries (`__schema`).
  - Discovers total types, queries, mutations, and subscriptions.
  - Analyzes schema for sensitive field keywords (e.g. `password`, `token`, `secret`, `apiKey`, `admin`).
  - Returns structured `[PSCustomObject]` with risk rating and hardening guidance.

```powershell
# Test endpoint for open introspection
.\Security\Test-GraphQLIntrospection.ps1 -Uri "https://api.example.com/graphql" -ExportSchemaPath ".\schema.json"
```

---

## Utility Tools

### `Convert-YamlToPSCustomObject.ps1`
Recursively converts YAML strings, files, or hashtable hierarchies into native PowerShell `[PSCustomObject]` trees.

- **Features**:
  - Solves the limitation where nested YAML mappings remain raw hashtables by deeply traversing all child mappings and lists.
  - Supports dot-notation property traversal (`$config.services.database.host`).
  - Supports file paths (`-Path`), raw strings (`-YamlContent`), or pre-parsed objects (`-InputObject`).

```powershell
# Deserialize YAML configuration into fluent PSCustomObject
$config = .\Utility\Convert-YamlToPSCustomObject.ps1 -Path ".\config.yaml"
Write-Host "Database Host: $($config.database.server)"
```

### `Compare-WindowsHotfixes.ps1`
Automated multi-system hotfix comparison tool identifying missing patches across server fleets.

- **Features**:
  - Headless execution with zero GUI popups.
  - Uses high-speed CIM (`Win32_QuickFixEngineering`).
  - Formats: `PatchSummary` (fleet percentage), `Matrix` (pivot grid), `HostDiscrepancy` (drift from baseline).

```powershell
# Identify missing patches across web servers relative to fleet
"SRV-WEB-01", "SRV-WEB-02", "SRV-WEB-03" | .\Utility\Compare-WindowsHotfixes.ps1 -MissingOnly -Format Matrix
```

---

## Testing & Adversarial Security Gate

This repository enforces an automated adversarial security gate validating cryptographic asset integrity, zero-leak sanitization boundaries, syntax compliance, and functional unit tests.

### Running the Adversarial Review

```powershell
# Run the adversarial review engine
python adversarial_review.py
```

### Running the Test Suites

```powershell
# Run Python verification suite
python -m unittest discover -s tests -p "test_*.py"

# Run PowerShell Pester suite
Invoke-Pester -Path tests/PowershellScripts.Tests.ps1
```

---

## Governance & Contributing

- **License**: [Apache-2.0](LICENSE)
- **Security Policy**: [SECURITY.md](SECURITY.md)
- **Contribution Guidelines**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Agent Operating Rules**: [AGENTS.md](AGENTS.md)
