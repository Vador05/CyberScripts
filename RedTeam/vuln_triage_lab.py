"""
Vulnerability Triage Lab - Static analysis tool for common vulnerability patterns.

Usage:
    python vuln_triage_lab.py /path/to/codebase
    python vuln_triage_lab.py /path/to/codebase --severity high
    python vuln_triage_lab.py /path/to/codebase --severity medium --explain
"""

import argparse
import os
import re
import sys
from pathlib import Path

RULES = [
    {
        "id": "SQLI-001",
        "name": "SQL Injection",
        "pattern": re.compile(
            r'(execute|cursor\.execute)\s*\(\s*["\'].*(%s|%d|%\w).*["\']|'
            r'execute\s*\(\s*f["\']|execute\s*\(\s*".*\+|execute\s*\(\s*\'.*\+',
            re.IGNORECASE,
        ),
        "severity": "high",
        "explanation": (
            "SQL injection allows attackers to manipulate database queries. "
            "Use parameterized queries (cursor.execute(sql, params)) instead of string formatting."
        ),
    },
    {
        "id": "CMDI-001",
        "name": "Command Injection",
        "pattern": re.compile(
            r'(os\.system|subprocess\.(call|run|Popen|check_output|getoutput|getstatusoutput))\s*\(\s*'
            r'(f["\']|["\'].*\+|\w+\s*\+)',
            re.IGNORECASE,
        ),
        "severity": "high",
        "explanation": (
            "Command injection lets attackers execute arbitrary OS commands. "
            "Use subprocess with a list of arguments and avoid shell=True."
        ),
    },
    {
        "id": "CMDI-002",
        "name": "Shell=True Usage",
        "pattern": re.compile(r'shell\s*=\s*True', re.IGNORECASE),
        "severity": "medium",
        "explanation": (
            "shell=True passes the command through the system shell, enabling injection. "
            "Pass arguments as a list and set shell=False."
        ),
    },
    {
        "id": "SECRET-001",
        "name": "Hardcoded Password",
        "pattern": re.compile(
            r'(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
            re.IGNORECASE,
        ),
        "severity": "high",
        "explanation": (
            "Hardcoded passwords are exposed in source control and binaries. "
            "Use environment variables or a secrets manager."
        ),
    },
    {
        "id": "SECRET-002",
        "name": "Hardcoded API Key / Token",
        "pattern": re.compile(
            r'(api_key|apikey|secret|token|auth)\s*=\s*["\'][A-Za-z0-9+/=_\-]{8,}["\']',
            re.IGNORECASE,
        ),
        "severity": "high",
        "explanation": (
            "Hardcoded secrets leak via repositories and logs. "
            "Load secrets from environment variables or a vault at runtime."
        ),
    },
    {
        "id": "PATH-001",
        "name": "Path Traversal",
        "pattern": re.compile(
            r'open\s*\(\s*(request\.|f["\']|["\'].*\+|\w+\s*\+)',
            re.IGNORECASE,
        ),
        "severity": "medium",
        "explanation": (
            "Unsanitized file paths allow traversal outside intended directories (e.g., ../../etc/passwd). "
            "Resolve and validate paths against an allowlist before opening."
        ),
    },
    {
        "id": "PATH-002",
        "name": "User-Controlled Path (os.path.join)",
        "pattern": re.compile(
            r'os\.path\.join\s*\([^)]*request\.|os\.path\.join\s*\([^)]*input\s*\(',
            re.IGNORECASE,
        ),
        "severity": "medium",
        "explanation": (
            "os.path.join with user input can be abused for traversal. "
            "Validate that the resolved path starts with the intended base directory."
        ),
    },
    {
        "id": "EVAL-001",
        "name": "Dangerous eval/exec",
        "pattern": re.compile(
            r'\b(eval|exec)\s*\(\s*(?![\"\'](?:[^\"\'\\]|\\.)*[\"\']\s*\))',
            re.IGNORECASE,
        ),
        "severity": "high",
        "explanation": (
            "eval/exec with dynamic input allows arbitrary code execution. "
            "Avoid these functions; use ast.literal_eval for safe literal parsing."
        ),
    },
]

SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}

_CONTROL_CHARS = re.compile(r'[\x00-\x1f\x7f-\x9f]')


def _sanitize(text):
    return _CONTROL_CHARS.sub('?', text)


def scan_file(path):
    findings = []
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"[WARN] Cannot read {path}: {exc}", file=sys.stderr)
        return findings
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            if rule["pattern"].search(line):
                findings.append(
                    {
                        "id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "file": str(path),
                        "line": lineno,
                        "snippet": _sanitize(line.strip()[:120]),
                        "explanation": rule["explanation"],
                    }
                )
    return findings


def triage_report(findings, min_severity="low", explain=False):
    min_rank = SEVERITY_RANK.get(min_severity, 1)
    filtered = [f for f in findings if SEVERITY_RANK[f["severity"]] >= min_rank]
    filtered.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["file"], f["line"]))

    if not filtered:
        print("No findings at or above severity:", min_severity)
        return

    print(f"\n{'='*70}")
    print(f"  VULNERABILITY TRIAGE REPORT  —  {len(filtered)} finding(s)")
    print(f"{'='*70}\n")

    for idx, f in enumerate(filtered, start=1):
        sev = f["severity"].upper()
        print(f"[{idx:03d}] [{sev:<6}] {f['id']} — {f['name']}")
        print(f"       File : {f['file']}:{f['line']}")
        print(f"       Code : {f['snippet']}")
        if explain:
            print(f"       Why  : {f['explanation']}")
        print()

    counts = {"high": 0, "medium": 0, "low": 0}
    for f in filtered:
        counts[f["severity"]] += 1
    print(f"Summary — HIGH: {counts['high']}  MEDIUM: {counts['medium']}  LOW: {counts['low']}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability Triage Lab: static-analysis scanner for common vulnerability patterns."
    )
    parser.add_argument("target_dir", help="Path to the Python codebase to scan.")
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum severity to display (default: low).",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Print educational context and remediation hints for each finding.",
    )
    args = parser.parse_args()

    target = Path(args.target_dir)
    if not target.is_dir():
        print(f"Error: '{target}' is not a directory.", file=sys.stderr)
        sys.exit(1)

    py_files = []
    for root, dirs, files in os.walk(target, followlinks=False):
        for fname in files:
            if fname.endswith(".py"):
                py_files.append(Path(root) / fname)
        unaccessible = []
        for d in dirs[:]:
            dir_path = os.path.join(root, d)
            try:
                with os.scandir(dir_path):
                    pass
            except (PermissionError, OSError) as exc:
                print(f"[WARN] Skipping unreadable directory {dir_path}: {exc}", file=sys.stderr)
                unaccessible.append(d)
        for d in unaccessible:
            dirs.remove(d)

    if not py_files:
        print("No Python files found in target directory.", file=sys.stderr)
        sys.exit(0)

    all_findings = []
    for py_file in py_files:
        all_findings.extend(scan_file(py_file))

    triage_report(all_findings, min_severity=args.severity, explain=args.explain)


if __name__ == "__main__":
    main()