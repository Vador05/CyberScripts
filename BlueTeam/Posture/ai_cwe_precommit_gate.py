"""
AI Code CWE Pre-Commit Gate with Triage Dashboard

Scans git-staged source files for AI-generated vulnerability patterns mapped
to CWE classes, blocks commits on critical findings, and appends results to a
JSONL triage log. Dashboard mode renders per-CWE rankings and 7-day trends.

Usage:
    python ai_cwe_gate.py scan [--log .cwe_triage.jsonl] [--severity medium]
    python ai_cwe_gate.py dashboard [--log .cwe_triage.jsonl]

    # Install as a pre-commit hook:
    cp ai_cwe_gate.py .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
    echo '.cwe_triage.jsonl' >> .gitignore
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

CWE_RULES = [
    ("CWE-78",  "OS Command Injection",    "critical", r"subprocess\.(call|run|Popen).*?shell\s*=\s*True|os\.system\s*\("),
    ("CWE-89",  "SQL Injection",           "high",     r'(execute|cursor\.execute)\s*\(.*?(%[sd]|\.format\s*\(|f["\'])'),
    ("CWE-798", "Hard-coded Credentials",  "high",     r'(password|passwd|secret|api_key|token)\s*=\s*["\'][^"\']{4,}["\']'),
    ("CWE-327", "Broken Cryptography",     "medium",   r'hashlib\.(md5|sha1)\s*\(|MD5\s*\(|SHA1\s*\('),
    ("CWE-502", "Unsafe Deserialization",  "critical", r'pickle\.loads?\s*\(|yaml\.load\s*\((?!.*Loader)'),
    ("CWE-22",  "Path Traversal",          "high",     r'open\s*\(\s*(request\.|input\(|sys\.argv|os\.environ|[\w]+\s*\+)'),
]

REMEDIATIONS = {
    "CWE-78":  "Use subprocess with a list of args; never pass shell=True with user data.",
    "CWE-89":  "Use parameterized queries with bound parameters instead of string formatting.",
    "CWE-798": "Load secrets from environment variables or a dedicated secrets manager.",
    "CWE-327": "Replace MD5/SHA1 with SHA-256 or SHA-3 for any security-relevant hashing.",
    "CWE-502": "Replace pickle/yaml.load with json.loads or yaml.safe_load.",
    "CWE-22":  "Resolve and validate paths with os.path.abspath; reject inputs that escape root.",
}


def scan_staged():
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"[ERROR] git diff failed: {exc}", file=sys.stderr)
        return []

    ts = datetime.now(timezone.utc).isoformat()
    findings = []
    for path in (p.strip() for p in result.stdout.splitlines() if p.strip()):
        try:
            with open(path, errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, 1):
            for cwe_id, cwe_name, severity, pattern in CWE_RULES:
                if re.search(pattern, line):
                    findings.append({
                        "utc_timestamp": ts,
                        "cwe_id": cwe_id,
                        "cwe_name": cwe_name,
                        "severity": severity,
                        "file": path,
                        "line": lineno,
                        "snippet": line.strip()[:120],
                    })
    return findings


def append_triage_log(log_path, findings):
    if not findings:
        return
    try:
        if not os.path.exists(log_path):
            fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            os.close(fd)

        try:
            os.chmod(log_path, 0o600)
        except OSError:
            pass

        with open(log_path, "a") as fh:
            for f in findings:
                fh.write(json.dumps(f) + "\n")
    except OSError as exc:
        print(f"[ERROR] Cannot write triage log: {exc}", file=sys.stderr)


def render_dashboard(log_path):
    try:
        with open(log_path) as fh:
            records = [json.loads(ln) for ln in fh if ln.strip()]
    except FileNotFoundError:
        print("[INFO] No triage log found — run scan mode first.")
        return
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[ERROR] Reading log: {exc}", file=sys.stderr)
        return
    if not records:
        print("[INFO] Triage log is empty.")
        return

    cwe_stats = defaultdict(lambda: {"count": 0, "name": "", "last_seen": ""})
    file_counts = defaultdict(int)
    daily = defaultdict(int)
    for r in records:
        cid = r["cwe_id"]
        cwe_stats[cid]["count"] += 1
        cwe_stats[cid]["name"] = r.get("cwe_name", "")
        cwe_stats[cid]["last_seen"] = max(cwe_stats[cid]["last_seen"], r["utc_timestamp"][:10])
        file_counts[r["file"]] += 1
        daily[r["utc_timestamp"][:10]] += 1

    print("\n=== CWE Hit-Rate Rankings ===")
    print(f"{'CWE':<10} {'Name':<30} {'Hits':>6}  {'Last Seen'}")
    print("-" * 62)
    for cid, v in sorted(cwe_stats.items(), key=lambda x: -x[1]["count"]):
        print(f"{cid:<10} {v['name']:<30} {v['count']:>6}  {v['last_seen']}")

    print("\n=== Top-5 Repeat-Offender Files ===")
    print(f"{'File':<50} {'Findings':>8}")
    print("-" * 60)
    for path, cnt in sorted(file_counts.items(), key=lambda x: -x[1])[:5]:
        display = path if len(path) <= 50 else "..." + path[-47:]
        print(f"{display:<50} {cnt:>8}")

    today = datetime.now(timezone.utc).date()
    days = [(today - timedelta(days=i)).isoformat() for i in range(6, -1, -1)]
    counts = [daily.get(d, 0) for d in days]
    print("\n=== 7-Day Rolling Trend ===")
    print(f"{'Date':<12} {'Findings':>8}")
    print("-" * 22)
    for d, c in zip(days, counts):
        print(f"{d:<12} {c:>8}")
    first_avg = sum(counts[:3]) / 3
    last_avg = sum(counts[4:]) / 3
    trend = "rising" if last_avg > first_avg * 1.1 else "falling" if last_avg < first_avg * 0.9 else "stable"
    print(f"Trend (first-half vs last-half): {trend}\n")


def main():
    parser = argparse.ArgumentParser(description="AI Code CWE Pre-Commit Gate with Triage Dashboard")
    parser.add_argument("mode", choices=["scan", "dashboard"])
    parser.add_argument("--log", default=".cwe_triage.jsonl", help="Path to JSONL triage log")
    parser.add_argument("--severity", default="medium", choices=SEVERITY_ORDER,
                        help="Minimum severity to report and block on (default: medium)")
    args = parser.parse_args()

    if args.mode == "dashboard":
        render_dashboard(args.log)
        return

    findings = scan_staged()
    append_triage_log(args.log, findings)

    threshold = SEVERITY_ORDER[args.severity]
    blocked = False
    for f in findings:
        if SEVERITY_ORDER[f["severity"]] >= threshold:
            print(
                f"[{f['utc_timestamp']}] {f['cwe_id']} ({f['cwe_name']}) "
                f"[{f['severity'].upper()}] {f['file']}:{f['line']}\n"
                f"  snippet : {f['snippet']}\n"
                f"  fix     : {REMEDIATIONS.get(f['cwe_id'], 'Review and remediate.')}"
            )
            blocked = True

    verdict = "BLOCKED" if blocked else "PASSED"
    print(f"\n[SUMMARY] {len(findings)} finding(s) logged | verdict: {verdict}")
    if blocked:
        sys.exit(1)


if __name__ == "__main__":
    main()