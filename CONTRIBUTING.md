# Contributing to powershell-scripts

We welcome contributions to the Koality Assured PowerShell Automation repository. To preserve code quality, security posture, and strict sanitization boundaries, all contributions must adhere to the standards outlined below.

## Code Standards

1. **PowerShell 7+ Compatibility**:
   - All scripts must use modern PowerShell 7+ syntax and remain backward-compatible with Windows PowerShell 5.1 where applicable.
   - Scripts must include `[CmdletBinding()]` and declare explicit parameter sets and type constraints.
   - Use `Get-CimInstance` instead of deprecated `Get-WmiObject`.
   - Never suppress errors silently without handling; configure `$ErrorActionPreference = 'Stop'` and use structured `try/catch` blocks.

2. **Help Documentation**:
   - Every script must contain comment-based help including:
     - `.SYNOPSIS`
     - `.DESCRIPTION`
     - `.PARAMETER <Name>` (for each declared parameter)
     - `.EXAMPLE` (at least two realistic examples using RFC documentation domains)
     - `.NOTES`

3. **Strict Sanitization (Zero Tolerance)**:
   - All sample hostnames, domains, and IP addresses must use RFC 2606 / RFC 6761 reserved domains (`example.com`, `contoso.local`, `192.0.2.0/24`).
   - ZERO references to proprietary corporate entities, internal infrastructure names (`ABK-*`, `CORE-*`), or employee email addresses.
   - Never commit private keys, `.pfx` certificates, live webhook tokens, or API secrets.

4. **Conventional Commits**:
   - Commit messages must follow the Conventional Commits specification:
     - `feat:` New features or capabilities
     - `fix:` Bug fixes
     - `docs:` Documentation improvements
     - `test:` Unit or integration test additions
     - `refactor:` Code restructuring without behavioral change

## Verification Gates

Before submitting a Pull Request, run the complete adversarial security review and test suite locally:

```powershell
# Execute the Koality Assured Adversarial Security Engine
python adversarial_review.py

# Execute PowerShell Pester test suite
Invoke-Pester -Path tests/PowershellScripts.Tests.ps1
```

All Pull Requests require a 100% pass rate across the five adversarial review stages.
