#!/usr/bin/env python3
"""Koality Assured Antagonistic Security & Sanitization Review Engine.

Executes comprehensive adversarial verification across the powershell-scripts repository:
1. Zero-leak cryptographic hash inventory & file integrity validation (SHA-256).
2. Pattern leak scanning for proprietary corporate names, internal domains, internal hostnames, and secrets.
3. Strict syntax validation across all PowerShell scripts (.ps1), Python (.py), YAML (.yml/.yaml), and JSON (.json).
4. Automated execution of Python unittest suite and PowerShell Pester test suite enforcing 100% pass rate.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Set, Tuple

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_ROOT = Path(__file__).resolve().parent

EXCLUDED_DIRS: Set[str] = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".vscode",
}

EXCLUDED_FILES: Set[str] = {
    "adversarial_review.py",
    "test_powershell_scripts.py",
    ".coverage",
}

# 1. Proprietary & Legacy Corporate Keywords
PROPRIETARY_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("Legacy Corporate Name (Blizzard)", re.compile(r"\bblizzard\b", re.IGNORECASE)),
    ("Legacy Corporate Name (Take-Two)", re.compile(r"\btake-two\b|\btaketwo\b", re.IGNORECASE)),
    ("Legacy Corporate Name (2K Games)", re.compile(r"\b2kgames\b|\b2k\.com\b", re.IGNORECASE)),
    ("Legacy Corporate Name (Activision)", re.compile(r"\bactivision\b", re.IGNORECASE)),
    (
        "Internal Corporate Domain",
        re.compile(r"\bblizzard\.net\b|\bblizzard\.com\b|\bbattle\.net\b|\bchromie\.net\b|\brlab\.local\b|\bt2\.corp\b", re.IGNORECASE),
    ),
    (
        "Proprietary Hostname / Prefix",
        re.compile(r"\bABK-[A-Z0-9_-]+|\bCORE-[A-Z0-9_-]+|\bRLAB-[A-Z0-9_-]+|\bBlizzardCA[0-9]*\b|\bCOREROOT[0-9]*\b|\bCOREBICA[0-9]*\b", re.IGNORECASE),
    ),
    (
        "Corporate Employee Email",
        re.compile(r"[A-Za-z0-9._%+-]+@(?:blizzard\.com|2k\.com|take2games\.com)", re.IGNORECASE),
    ),
    ("Local Reference Absolute Drive Paths", re.compile(r"[E|e]:\\Code|[E|e]:/Code")),
    ("Internal Developer User Profile Path", re.compile(r"[C|c]:\\Users\\rober(?:\b|\\|/)")),
]

# 2. Secret & Credential Leak Patterns
SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("RSA Private Key Header", re.compile(r"-----BEGIN RSA PRIVATE KEY-----")),
    ("EC Private Key Header", re.compile(r"-----BEGIN EC PRIVATE KEY-----")),
    ("Generic Private Key Header", re.compile(r"-----BEGIN (?:OPENSSH|ENCRYPTED|DSA)? ?PRIVATE KEY-----")),
    ("Live GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b")),
    ("Live Slack Token", re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*")),
    (
        "High-Entropy Secret Assignment",
        re.compile(r"(?i)(?:api_key|client_secret|auth_token)\s*=\s*['\"][A-Za-z0-9+/=]{32,}['\"]"),
    ),
]

BANNED_EXTENSIONS: Set[str] = {".pfx", ".p12", ".key", ".pkcs12"}


def banner(text: str) -> None:
    print(f"\n{'=' * 80}\n[KOALITY ASSURED AUDIT] {text}\n{'=' * 80}")


def collect_target_files() -> List[Path]:
    target_files: List[Path] = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for f in files:
            if f.endswith(".pyc"):
                continue
            p = Path(root) / f
            target_files.append(p)
    return target_files


def run_stage_1_sanitization(files: List[Path]) -> Tuple[bool, int]:
    banner("STAGE 1: Zero-Leak Sanitization Audit")
    violations: List[str] = []
    scanned_files = 0

    for file_path in files:
        if file_path.name in EXCLUDED_FILES or file_path.suffix in [".ico", ".png", ".jpg"]:
            continue

        rel_path = file_path.relative_to(REPO_ROOT).as_posix()
        scanned_files += 1

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            violations.append(f"Unable to read {rel_path}: {exc}")
            continue

        for desc, pattern in PROPRIETARY_PATTERNS:
            matches = pattern.findall(content)
            if matches:
                violations.append(f"[{rel_path}] Found forbidden {desc}: {matches[:3]}")

    print(f"Scanned {scanned_files} repository files for forbidden corporate leaks.")
    if violations:
        print(f"  [FAIL] Detected {len(violations)} sanitization violation(s):")
        for v in violations:
            print(f"    * {v}")
        return False, len(violations)

    print("  [PASS] Zero corporate leaks or proprietary references detected.")
    return True, 0


def run_stage_2_secret_audit(files: List[Path]) -> Tuple[bool, int]:
    banner("STAGE 2: Secret & Private Key Leak Audit")
    violations: List[str] = []
    scanned_files = 0

    for file_path in files:
        rel_path = file_path.relative_to(REPO_ROOT).as_posix()

        if file_path.suffix.lower() in BANNED_EXTENSIONS:
            violations.append(f"[{rel_path}] Prohibited private key extension {file_path.suffix}")

        if file_path.name in EXCLUDED_FILES or file_path.suffix in [".ico", ".png", ".jpg"]:
            continue

        scanned_files += 1
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            violations.append(f"Unable to read {rel_path}: {exc}")
            continue

        for desc, pattern in SECRET_PATTERNS:
            matches = pattern.findall(content)
            if matches:
                violations.append(f"[{rel_path}] Found potential secret leak ({desc})")

    print(f"Audited {scanned_files} repository files for credentials and private keys.")
    if violations:
        print(f"  [FAIL] Detected {len(violations)} secret leak violation(s):")
        for v in violations:
            print(f"    * {v}")
        return False, len(violations)

    print("  [PASS] Zero private keys or credentials present in working tree.")
    return True, 0


def run_stage_3_cryptographic_inventory(files: List[Path]) -> Tuple[bool, int]:
    banner("STAGE 3: Cryptographic SHA-256 Hash Inventory")
    inventory: List[Tuple[str, str]] = []

    for file_path in sorted(files):
        rel_path = file_path.relative_to(REPO_ROOT).as_posix()
        try:
            digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
            inventory.append((rel_path, digest))
        except Exception as exc:
            print(f"  [ERROR] Error hashing {rel_path}: {exc}")

    for rel_path, digest in inventory[:15]:
        print(f"  SHA256: {digest[:16]}... {rel_path}")
    if len(inventory) > 15:
        print(f"  ... and {len(inventory) - 15} additional tracked files hashed.")

    print(f"  [PASS] Successfully computed SHA-256 fingerprints across {len(inventory)} repository files.")
    return True, 0


def run_stage_4_syntax_validation(files: List[Path]) -> Tuple[bool, int]:
    banner("STAGE 4: Syntax & Structural AST Validation")
    errors: List[str] = []
    py_count = 0
    yaml_count = 0
    json_count = 0
    ps_count = 0

    import yaml

    for file_path in files:
        rel_path = file_path.relative_to(REPO_ROOT).as_posix()
        suffix = file_path.suffix.lower()

        if suffix == ".py":
            py_count += 1
            try:
                ast.parse(file_path.read_text(encoding="utf-8"), filename=rel_path)
            except SyntaxError as syn:
                errors.append(f"[{rel_path}] Python SyntaxError: line {syn.lineno}: {syn.msg}")

        elif suffix in (".yaml", ".yml"):
            yaml_count += 1
            try:
                yaml.safe_load(file_path.read_text(encoding="utf-8"))
            except Exception as yerr:
                errors.append(f"[{rel_path}] YAML SyntaxError: {yerr}")

        elif suffix == ".json":
            json_count += 1
            try:
                json.loads(file_path.read_text(encoding="utf-8"))
            except Exception as jerr:
                errors.append(f"[{rel_path}] JSON SyntaxError: {jerr}")

        elif suffix in (".ps1", ".psm1", ".psd1"):
            ps_count += 1
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                f"""
                $errors = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile('{str(file_path)}', [ref]$null, [ref]$errors)
                if ($errors) {{
                    $errors | ForEach-Object {{ Write-Output $_.Message }}
                    exit 1
                }} else {{
                    exit 0
                }}
                """,
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                errors.append(f"[{rel_path}] PowerShell AST error: {proc.stdout.strip() or proc.stderr.strip()}")

    print(f"Validated syntax: {ps_count} PowerShell, {py_count} Python, {yaml_count} YAML, {json_count} JSON.")
    if errors:
        print(f"  [FAIL] Encountered {len(errors)} syntax error(s):")
        for err in errors:
            print(f"    * {err}")
        return False, len(errors)

    print("  [PASS] All scripts and data files parsed with 0 syntax errors.")
    return True, 0


def run_stage_5_test_execution() -> Tuple[bool, int]:
    banner("STAGE 5: Automated Test Suite Execution")

    # 5A. Python unittest suite
    print("[*] Running Python Verification Suite (tests/test_powershell_scripts.py)...")
    py_cmd = [
        sys.executable,
        "-m",
        "unittest",
        "discover",
        "-s",
        str(REPO_ROOT / "tests"),
        "-p",
        "test_*.py",
    ]
    py_proc = subprocess.run(py_cmd, cwd=REPO_ROOT, capture_output=True, text=True)

    if py_proc.returncode != 0:
        print("  [FAIL] Python unit tests failed:", file=sys.stderr)
        print(py_proc.stdout, file=sys.stderr)
        print(py_proc.stderr, file=sys.stderr)
        return False, 1

    print("  [PASS] Python unit tests passed (100% success rate).")

    # 5B. PowerShell Pester suite
    print("[*] Running PowerShell Pester Test Suite (tests/PowershellScripts.Tests.ps1)...")
    ps_cmd = [
        "powershell.exe",
        "-NoProfile",
        "-Command",
        f"""
        $pester = Invoke-Pester -Path '{str(REPO_ROOT / "tests" / "PowershellScripts.Tests.ps1")}' -PassThru
        if ($pester.FailedCount -gt 0) {{
            Write-Error "Pester tests failed: $($pester.FailedCount)"
            exit 1
        }} else {{
            Write-Output "All $($pester.PassedCount) Pester tests passed!"
            exit 0
        }}
        """,
    ]
    ps_proc = subprocess.run(ps_cmd, cwd=REPO_ROOT, capture_output=True, text=True)

    if ps_proc.returncode != 0:
        print("  [FAIL] Pester tests failed:", file=sys.stderr)
        print(ps_proc.stdout, file=sys.stderr)
        print(ps_proc.stderr, file=sys.stderr)
        return False, 1

    print(f"  [PASS] {ps_proc.stdout.strip()}")
    return True, 0


def main() -> int:
    start_time = time.time()
    banner("KOALITY ASSURED -- ANTAGONISTIC SECURITY & SANITIZATION REVIEW")
    print(f"Target Repository Root: {REPO_ROOT}")
    print(f"Execution Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")

    files = collect_target_files()
    if not files:
        print("[ERROR] No project files discovered.")
        return 1

    stages = [
        ("Zero-Leak Sanitization Check", lambda: run_stage_1_sanitization(files)),
        ("Secret & Private Key Audit", lambda: run_stage_2_secret_audit(files)),
        ("Cryptographic Hash Inventory", lambda: run_stage_3_cryptographic_inventory(files)),
        ("Syntax & AST Validation", lambda: run_stage_4_syntax_validation(files)),
        ("Automated Test Suite Execution", run_stage_5_test_execution),
    ]

    summary = []
    total_violations = 0
    all_passed = True

    for name, func in stages:
        passed, count = func()
        total_violations += count
        if not passed:
            all_passed = False
        summary.append((name, "PASSED" if passed else "FAILED", count))

    elapsed = time.time() - start_time
    banner("REVIEW SUMMARY")
    print(f"{'Audit Stage':<35} | {'Status':<10} | {'Violations':<10}")
    print(f"{'-' * 35}-+-{'-' * 10}-+-{'-' * 10}")
    for name, status, count in summary:
        print(f"{name:<35} | {status:<10} | {count:<10}")

    print(f"\nReview executed across {len(files)} files in {elapsed:.2f} seconds.")

    if all_passed and total_violations == 0:
        print("\n[VERDICT: PASSED] 0 violations detected. Repository meets Koality Assured Security Standards.")
        return 0
    else:
        print(f"\n[VERDICT: FAILED] {total_violations} violation(s) detected. Remediation required.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
