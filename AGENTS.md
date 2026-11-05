# Repository AGENTS Rules: powershell-scripts

This file defines the normative rules and constraints for AI agents operating within `powershell-scripts`.

## Core Directives

1. **PowerShell 7+ Engineering Standard**:
   - Every script must declare `[CmdletBinding()]` and support pipeline processing where appropriate.
   - Scripts that perform mutating operations (`New-ADComputer`, `Add-Computer`, `Set-WindowsTlsHardening`, `Disable-ADAccount`) MUST implement `SupportsShouldProcess = $true` and respect `-WhatIf` / `-Confirm`.
   - Never introduce deprecated WMI cmdlets (`Get-WmiObject`); always use `Get-CimInstance` or CIM sessions.
   - Use strongly typed parameters, parameter sets, and validation attributes (`[ValidateNotNullOrEmpty()]`, `[ValidateSet()]`, `[ValidateRange()]`).

2. **Sanitization & Anti-Leak Fence (CRITICAL)**:
   - Absolutely ZERO references to legacy corporate names, internal domains, internal server hostnames, or corporate emails.
   - Permitted testing and example domains: `contoso.local`, `example.com`, `ad.example.internal`.
   - Permitted test network CIDRs: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737).

3. **Adversarial Security Gate**:
   - Any modification to repository code must pass `python adversarial_review.py` with 0 violations before declaring complete.
   - Do NOT disable or suppress adversarial checks in `adversarial_review.py`.
   - Maintain 100% test passing rate across Python unittest and Pester suites.
