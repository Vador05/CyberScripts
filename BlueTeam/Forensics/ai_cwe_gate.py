"""
ai_cwe_gate - Scan AI-generated source files for CWE-mapped vulnerability patterns.

Usage:
    python ai_cwe_gate.py src/
    python ai_cwe_gate.py main.py --severity high
    python ai_cwe_gate.py src/ --policy policy.json --severity medium
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


def load_rules(policy=None):
    rules = {
        "CWE-78": (
            "OS Command Injection",
            "high",
            re.compile(r"os\.system\s*\(|subprocess\.[^\(]+\([^)]*shell\s*=\s*True", re.IGNORECASE),
            "Use subprocess with a list of args and shell=False; never pass user input to shell=True.",
        ),
        "CWE-89": (
            "SQL Injection",
            "high",
            re.compile(r'(execute|query)\s*\(\s*["\']?\s*%(s|d)|f["\'].*(SELECT|INSERT|UPDATE|DELETE|WHERE)', re.IGNORECASE),
            "Use parameterized queries or an ORM; never interpolate user input into SQL strings.",
        ),
        "CWE-94": (
            "Eval/Exec Injection",
            "high",
            re.compile(r"\beval\s*\(|\bexec\s*\(", re.IGNORECASE),
            "Remove eval/exec; use ast.literal_eval for data, or refactor to avoid dynamic code execution.",
        ),
        "CWE-798": (
            "Hardcoded Credentials",
            "medium",
            re.compile(r'(password|secret|api_key|token|passwd)\s*=\s*["\'][^"\']{3,}["\']', re.IGNORECASE),
            "Load credentials from environment variables or a secrets manager; never hardcode them.",
        ),
        "CWE-326": (
            "Weak Cryptography",
            "medium",
            re.compile(r"hashlib\.(md5|sha1)\s*\(|MD5\s*\(|SHA1\s*\(", re.IGNORECASE),
            "Use SHA-256 or stronger for security-sensitive hashing; MD5/SHA1 are cryptographically broken.",
        ),
        "CWE-502": (
            "Unsafe Deserialization",
            "high",
            re.compile(r"pickle\.loads?\s*\(|yaml\.load\s*\([^)]*\)", re.IGNORECASE),
            "Use pickle only with trusted data; replace yaml.load with yaml.safe_load.",
        ),
        "CWE-22": (
            "Path Traversal",
            "medium",
            re.compile(r"open\s*\([^)]*\.\./|os\.path\.join\s*\([^)]*request|send_file\s*\([^)]*request", re.IGNORECASE),
            "Validate and canonicalize paths with os.path.realpath; reject inputs containing '..'.",
        ),
    }

    exclude_paths = []
    if policy:
        try:
            with open(policy, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[ERROR] Failed to load policy file: {exc}", file=sys.stderr)
            sys.exit(2)
        for cwe_id, entry in data.get("rules", {}).items():
            rules[cwe_id] = (
                entry["name"],
                entry["severity"],
                re.compile(entry["pattern"], re.IGNORECASE),
                entry["remediation"],
            )
        exclude_paths = data.get("exclude_paths", [])

    return rules, exclude_paths


COMMENT_RE = re.compile(r"^\s*(#|//|--|;)")


def scan_files(target, rules, exclude_paths):
    paths = []
    if os.path.isfile(target):
        paths = [target]
    else:
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d != ".git"]
            for fname in files:
                paths.append(os.path.join(root, fname))

    for fpath in paths:
        rel = os.path.relpath(fpath, target if os.path.isdir(target) else os.path.dirname(target))
        if any(rel.startswith(ex) for ex in exclude_paths):
            continue
        try:
            if os.path.getsize(fpath) > 256 * 1024:
                continue
        except OSError:
            continue
        try:
            with open(fpath, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        if b"\x00" in "".join(lines[:4]).encode("utf-8", errors="replace"):
            continue
        for lineno, raw_line in enumerate(lines, 1):
            if COMMENT_RE.match(raw_line):
                continue
            line = raw_line.rstrip("\n")
            for cwe_id, (name, severity, pattern, _) in rules.items():
                if pattern.search(line):
                    snippet = line.strip()[:120]
                    yield cwe_id, severity, fpath, lineno, snippet


def report_findings(findings_iter, rules, blocked_cwes, min_severity, scanned_count):
    counts = defaultdict(int)
    triggered_blocked = set()
    min_rank = SEVERITY_RANK[min_severity]

    for cwe_id, severity, fpath, lineno, snippet in findings_iter:
        counts[cwe_id] += 1
        if cwe_id in blocked_cwes:
            triggered_blocked.add(cwe_id)
        if SEVERITY_RANK.get(severity, 0) < min_rank:
            continue
        name, _, _, remediation = rules[cwe_id]
        print(f"[{severity.upper()}] {cwe_id} ({name}) {fpath}:{lineno}")
        print(f"  snippet : {snippet}")
        print(f"  fix     : {remediation}")

    print()
    print(f"{'CWE ID':<12} {'Name':<32} {'Hits':>6}")
    print("-" * 54)
    for cwe_id, count in sorted(counts.items()):
        name = rules[cwe_id][0]
        print(f"{cwe_id:<12} {name:<32} {count:>6}")
    print("-" * 54)
    print(f"Files scanned: {scanned_count}  Total findings: {sum(counts.values())}")

    if triggered_blocked:
        print()
        print("*** BLOCKED ***")
        print(f"Policy-violating CWEs detected: {', '.join(sorted(triggered_blocked))}")
        sys.exit(1)


def count_files(target):
    if os.path.isfile(target):
        return 1
    total = 0
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d != ".git"]
        total += len(files)
    return total


def main():
    parser = argparse.ArgumentParser(description="Scan AI-generated source files for CWE vulnerability patterns.")
    parser.add_argument("target", help="Source file or directory to scan")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low", help="Minimum severity to emit (default: low)")
    parser.add_argument("--policy", default=None, help="JSON policy file with 'block' CWE list and optional 'exclude_paths'")
    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"[ERROR] Target not found: {args.target}", file=sys.stderr)
        sys.exit(2)

    rules, exclude_paths = load_rules(args.policy)

    blocked_cwes = set()
    if args.policy:
        try:
            with open(args.policy, encoding="utf-8") as fh:
                pdata = json.load(fh)
            blocked_cwes = set(pdata.get("block", []))
        except (OSError, json.JSONDecodeError):
            pass
    if not blocked_cwes:
        blocked_cwes = {"CWE-78", "CWE-89", "CWE-94", "CWE-502"}

    scanned = count_files(args.target)
    findings = scan_files(args.target, rules, exclude_paths)
    report_findings(findings, rules, blocked_cwes, args.severity, scanned)


if __name__ == "__main__":
    main()