#!/usr/bin/env python3
"""Koality Assured PowerShell Scripts Test Suite.

Comprehensive automated testing covering:
1. Script discovery & directory layout.
2. PowerShell AST syntax verification.
3. Help documentation structure (.SYNOPSIS, .DESCRIPTION, .PARAMETER, .EXAMPLE, .NOTES).
4. CmdletBinding & parameter definition checks.
5. Strict anti-leak sanitization validation across all repository files.
6. Execution tests for utility and security tools.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

EXPECTED_SCRIPTS = [
    "ActiveDirectory/Manage-ADComputer.ps1",
    "ActiveDirectory/Test-DCSyncReplicationRights.ps1",
    "ActiveDirectory/Get-LocalAdminMembers.ps1",
    "ActiveDirectory/Get-StaleADAccounts.ps1",
    "Security/Get-ExpiringCertificates.ps1",
    "Security/Set-WindowsTlsHardening.ps1",
    "Security/Test-GraphQLIntrospection.ps1",
    "Utility/Convert-YamlToPSCustomObject.ps1",
    "Utility/Compare-WindowsHotfixes.ps1",
]

FORBIDDEN_LEAK_PATTERNS = [
    (r"\bblizzard\b", "Forbidden Corporate Name: Blizzard"),
    (r"\btake-two\b|\btaketwo\b|\b2kgames\b", "Forbidden Corporate Name: Take-Two / 2K Games"),
    (r"\b2k\.com\b|\bblizzard\.net\b|\bblizzard\.com\b|\bbattle\.net\b", "Forbidden Corporate Domain"),
    (r"\bABK-[A-Z0-9_-]+|\bCORE-[A-Z0-9_-]+|\bRLAB-[A-Z0-9_-]+", "Forbidden Internal Hostname Prefix"),
    (r"[E|e]:\\Code|[E|e]:/Code", "Forbidden Internal Absolute Drive Path"),
    (r"[C|c]:\\Users\\rober", "Forbidden User Home Path"),
    (r"[A-Za-z0-9._%+-]+@blizzard\.com", "Forbidden Corporate Email Address"),
]


class TestRepositoryStructure(unittest.TestCase):
    """Validates repository layout and presence of required modules."""

    def test_all_expected_scripts_exist(self):
        for script_rel in EXPECTED_SCRIPTS:
            script_path = REPO_ROOT / script_rel
            self.assertTrue(
                script_path.is_file(),
                f"Expected script is missing: {script_rel}",
            )

    def test_governance_files_exist(self):
        gov_files = [
            "README.md",
            "LICENSE",
            "SECURITY.md",
            "CONTRIBUTING.md",
            "AGENTS.md",
            ".gitignore",
            "adversarial_review.py",
        ]
        for f in gov_files:
            p = REPO_ROOT / f
            self.assertTrue(p.is_file(), f"Required governance file missing: {f}")


class TestPowerShellSyntaxAndAST(unittest.TestCase):
    """Executes PowerShell AST parser to ensure zero lexical/parsing errors."""

    def test_powershell_ast_clean(self):
        ps_files = list(REPO_ROOT.glob("**/*.ps1"))
        self.assertGreaterEqual(len(ps_files), 9)

        for ps in ps_files:
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                f"""
                $errors = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile('{str(ps)}', [ref]$null, [ref]$errors)
                if ($errors) {{
                    $errors | ForEach-Object {{ Write-Output $_.Message }}
                    exit 1
                }} else {{
                    exit 0
                }}
                """,
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(
                proc.returncode,
                0,
                f"PowerShell AST syntax error in {ps.relative_to(REPO_ROOT)}:\n{proc.stdout or proc.stderr}",
            )


class TestScriptMetadataAndStandards(unittest.TestCase):
    """Validates CmdletBinding, parameter validation, and documentation standards."""

    def test_all_scripts_have_cmdletbinding(self):
        for script_rel in EXPECTED_SCRIPTS:
            content = (REPO_ROOT / script_rel).read_text(encoding="utf-8")
            self.assertRegex(
                content,
                r"\[CmdletBinding\(.*?\)\]",
                f"Script {script_rel} missing [CmdletBinding()] attribute",
            )

    def test_all_scripts_have_help_documentation(self):
        required_tags = [r"\.SYNOPSIS", r"\.DESCRIPTION", r"\.EXAMPLE", r"\.NOTES"]
        for script_rel in EXPECTED_SCRIPTS:
            content = (REPO_ROOT / script_rel).read_text(encoding="utf-8")
            for tag in required_tags:
                self.assertRegex(
                    content,
                    tag,
                    f"Script {script_rel} missing comment-based help tag: {tag}",
                )

    def test_parameter_validation_attributes_present(self):
        for script_rel in EXPECTED_SCRIPTS:
            content = (REPO_ROOT / script_rel).read_text(encoding="utf-8")
            self.assertRegex(
                content,
                r"\[ValidateNotNullOrEmpty\(\)\]|\[ValidateSet\(.*?\)\]|\[ValidateRange\(.*?\)\]|\[ValidateLength\(.*?\)\]|\[Parameter\(.*?\)\]",
                f"Script {script_rel} missing standard parameter validation attributes",
            )


class TestSanitizationAuditing(unittest.TestCase):
    """Verifies complete eradication of proprietary names, internal paths, and corporate emails."""

    def test_zero_leak_patterns_in_repository(self):
        excluded_dirs = {".git", "__pycache__", ".pytest_cache"}
        excluded_files = {"adversarial_review.py", "test_powershell_scripts.py"}

        violations = []
        for root, dirs, files in os.walk(REPO_ROOT):
            dirs[:] = [d for d in dirs if d not in excluded_dirs]
            for f in files:
                if f in excluded_files or f.endswith(".pyc"):
                    continue
                file_path = Path(root) / f
                content = file_path.read_text(encoding="utf-8", errors="ignore")

                for pattern, desc in FORBIDDEN_LEAK_PATTERNS:
                    matches = re.findall(pattern, content, flags=re.IGNORECASE)
                    if matches:
                        violations.append(
                            f"{file_path.relative_to(REPO_ROOT)}: Found {desc} -> {matches[:3]}"
                        )

        self.assertEqual(
            len(violations),
            0,
            f"Sanitization violations detected:\n" + "\n".join(violations),
        )


class TestUtilityScriptExecution(unittest.TestCase):
    """Executes functional tests against utility and security scripts."""

    def test_convert_yaml_to_pscustomobject(self):
        ps_script = REPO_ROOT / "Utility" / "Convert-YamlToPSCustomObject.ps1"
        sample_yaml = (
            "environment: production\n"
            "services:\n"
            "  database:\n"
            "    host: db.contoso.local\n"
            "    port: 5432\n"
            "    ssl: true\n"
        )
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            f"""
            $yaml = @'
{sample_yaml}
'@
            $res = & '{str(ps_script)}' -YamlContent $yaml
            if ($res.environment -eq 'production' -and $res.services.database.host -eq 'db.contoso.local' -and $res.services.database.port -eq 5432 -and $res.services.database.ssl -eq $true) {{
                exit 0
            }} else {{
                exit 1
            }}
            """,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(
            proc.returncode,
            0,
            f"Convert-YamlToPSCustomObject failed execution test:\n{proc.stdout or proc.stderr}",
        )

    def test_compare_windows_hotfixes_local(self):
        ps_script = REPO_ROOT / "Utility" / "Compare-WindowsHotfixes.ps1"
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            f"""
            $res = & '{str(ps_script)}' -ComputerName 'localhost'
            if ($null -ne $res -and $res.Count -gt 0 -and $res[0].HotFixID) {{
                exit 0
            }} else {{
                exit 1
            }}
            """,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(
            proc.returncode,
            0,
            f"Compare-WindowsHotfixes failed execution test on localhost:\n{proc.stdout or proc.stderr}",
        )

    def test_set_windows_tls_hardening_audit_only(self):
        ps_script = REPO_ROOT / "Security" / "Set-WindowsTlsHardening.ps1"
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            f"""
            $report = & '{str(ps_script)}' -AuditOnly
            if ($null -ne $report -and $report.Count -ge 20) {{
                exit 0
            }} else {{
                exit 1
            }}
            """,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(
            proc.returncode,
            0,
            f"Set-WindowsTlsHardening in -AuditOnly mode failed:\n{proc.stdout or proc.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
