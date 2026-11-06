<div align="center">

![PowerShell Scripts Banner](assets/powershell-scripts-banner.svg)

# PowerShell Scripts

<p align="center">
  <img src="assets/powershell-scripts-logo.svg" alt="PowerShell Scripts Logo" width="128" height="128" />
</p>

**Production-Grade PowerShell 7+ Automation for Active Directory Threat Hunting & Security Hardening**

[![CI](https://github.com/Koality-Assured/powershell-scripts/actions/workflows/ci.yml/badge.svg)](https://github.com/Koality-Assured/powershell-scripts/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![PowerShell 7.4+](https://img.shields.io/badge/PowerShell-7.4%2B-5391FE.svg)](https://github.com/PowerShell/PowerShell)
[![Domain: Powershell-Scripts](https://img.shields.io/badge/domain-powershell-scripts-blueviolet.svg)]()
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
| `ActiveDirectory/` | [`Test-ADKerberosDelegation.ps1`](#test-adkerberosdelegationps1) | Threat Hunting | Audits Unconstrained, Constrained (S4U2Self), and RBCD delegation attack surfaces. |
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