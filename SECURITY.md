# Security Policy

## Supported Versions

Koality Assured actively maintains and provides security updates for the current major version of this repository:

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

Koality Assured takes the security and integrity of its systems automation tooling seriously. If you discover a security vulnerability, potential privilege escalation flaw, or credential exposure vector within this repository, please report it privately:

- **Email**: `security@koalityassured.com`
- **PGP Key**: Available upon request or via company security page
- **Scope**: All scripts in `ActiveDirectory/`, `Security/`, `Utility/`, tests, and automation workflows.

### Disclosure Process & SLAs

1. **Initial Acknowledgment**: Within 24 hours of receiving the vulnerability report.
2. **Triaging & Verification**: Within 72 hours of submission.
3. **Remediation & Patching**: Within 14 business days depending on severity.
4. **Public Disclosure**: Coordinated following public release of the patch.

Please do **NOT** file public GitHub issues for security vulnerabilities or unintended credential disclosures.

## Automated Security Gates

This repository enforces strict, multi-stage automated adversarial security gates on all code contributions:
- **Zero-Leak Sanitization**: Enforced via SHA-256 integrity inventory and regular expression leak scanners (`adversarial_review.py`).
- **AST Lexical Parsing**: Syntax verification using the PowerShell AST parser across all scripts.
- **Credential & Key Prevention**: Continuous scanning blocking private keys (`.pfx`, `.p12`, `.key`), tokens, and hardcoded secrets.
