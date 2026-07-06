"""
NPM Sleet Scanner - Detects Sapphire Sleet supply chain attack patterns in npm install logs.

Usage:
    python npm_sleet_scanner.py --log npm_install.log
    python npm_sleet_scanner.py --log npm_install.log --baseline trusted_packages.txt --severity alert
    python npm_sleet_scanner.py --log audit.log --severity info

Exit codes: 0 = no alert-severity findings, 1 = alert-severity findings detected
"""

import argparse
import re
import sys
from datetime import datetime, timezone


def load_rules():
    return [
        {
            "id": "SS-001",
            "severity": "alert",
            "pattern": re.compile(
                r"(?:mastra[-_]?a[il]|mastra[-_]?sdk|mastra[-_]?core[-_]?pro|mastra[-_]?client[-_]?sdk|"
                r"@mastra[-_]?ai\/(?!mastra\b)[a-z]|mastra[-_]?node[-_]?sdk|mastraai[-_]|"
                r"mestra[-_]?ai|mastro[-_]?ai|mastr4[-_]?ai|mastra[-_]?aii)",
                re.IGNORECASE,
            ),
            "rationale": "Typosquatted Mastra AI package name matching Sapphire Sleet campaign pattern",
        },
        {
            "id": "SS-002",
            "severity": "alert",
            "pattern": re.compile(
                r"postinstall.*(?:curl|wget|fetch|http|https).*(?:\d{1,3}\.){3}\d{1,3}|"
                r"postinstall.*(?:curl|wget).*-[sS].*http",
                re.IGNORECASE,
            ),
            "rationale": "Post-install script performing network callback (telemetry exfil TTP)",
        },
        {
            "id": "SS-003",
            "severity": "alert",
            "pattern": re.compile(
                r"(?:eval|exec|execSync|spawn|spawnSync|child_process)\s*\(.*(?:Buffer\.from|atob|base64)\s*\(",
                re.IGNORECASE,
            ),
            "rationale": "Base64-encoded payload execution via eval/exec (Contagious Interview extension)",
        },
        {
            "id": "SS-004",
            "severity": "alert",
            "pattern": re.compile(
                r"node\s+-e\s+['\"].*(?:Buffer\.from|require\('(?:http|https|net|child_process)'\))",
                re.IGNORECASE,
            ),
            "rationale": "Inline node -e execution with network or subprocess modules (DPRK loader TTP)",
        },
        {
            "id": "SS-005",
            "severity": "warn",
            "pattern": re.compile(
                r"scripts\.postinstall.*(?:sh|bash|cmd|powershell|pwsh)\s+-[cC]",
                re.IGNORECASE,
            ),
            "rationale": "Post-install shell invocation with command flag (potential dropper)",
        },
        {
            "id": "SS-006",
            "severity": "warn",
            "pattern": re.compile(
                r"(?:curl|wget)\s+.*-[oO]\s+(?:/tmp/|%TEMP%|\\Temp\\|\$env:TEMP)",
                re.IGNORECASE,
            ),
            "rationale": "Download to temp directory during install (staging area for payloads)",
        },
        {
            "id": "SS-007",
            "severity": "alert",
            "pattern": re.compile(
                r"(?:[A-Za-z0-9+/]{40,}={0,2})\b.*(?:eval|exec|Function\()",
                re.IGNORECASE,
            ),
            "rationale": "Long base64 string adjacent to execution primitive (encoded payload signature)",
        },
        {
            "id": "SS-008",
            "severity": "info",
            "pattern": re.compile(
                r"npm\s+(?:warn|error)\s+.*(?:deprecated|malicious|compromised|vulnerability)",
                re.IGNORECASE,
            ),
            "rationale": "npm registry warning about deprecated or flagged package",
        },
        {
            "id": "SS-009",
            "severity": "warn",
            "pattern": re.compile(
                r"(?:process\.env\.\w+|os\.environ)\s*\+.*(?:curl|wget|fetch)|"
                r"(?:HOME|USERPROFILE|APPDATA)\s*\+.*\.(?:ssh|aws|npmrc|gitconfig)",
                re.IGNORECASE,
            ),
            "rationale": "Credential path construction in install script (credential harvesting TTP)",
        },
        {
            "id": "SS-010",
            "severity": "alert",
            "pattern": re.compile(
                r"(?:mastra|@mastra).*(?:0\.0\.[0-9]|1\.0\.[0-9])\s+.*postinstall",
                re.IGNORECASE,
            ),
            "rationale": "Mastra-named package with low version and postinstall hook (supply chain seeding pattern)",
        },
    ]


def _levenshtein(a, b):
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def scan_log(log_path, baseline_packages, rules, min_severity):
    severity_rank = {"info": 0, "warn": 1, "alert": 2}
    min_rank = severity_rank.get(min_severity, 1)
    seen = set()
    alert_count = 0
    match_count = 0
    ts = lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        with open(log_path, "r", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.rstrip("\n")
                for rule in rules:
                    if severity_rank[rule["severity"]] < min_rank:
                        continue
                    m = rule["pattern"].search(line)
                    if not m:
                        continue
                    key = (rule["id"], m.group(0)[:80])
                    if key in seen:
                        continue
                    seen.add(key)
                    if baseline_packages:
                        token = m.group(0).lower().strip("@/")
                        if any(_levenshtein(token, bp) <= 2 for bp in baseline_packages):
                            if rule["id"] == "SS-001":
                                continue
                    print(
                        f"{ts()} MATCH rule={rule['id']} severity={rule['severity'].upper()} "
                        f"line={lineno} matched={m.group(0)!r} rationale={rule['rationale']!r}"
                    )
                    match_count += 1
                    if rule["severity"] == "alert":
                        alert_count += 1
    except OSError as exc:
        print(f"ERROR opening log file: {exc}", file=sys.stderr)
        sys.exit(2)

    return match_count, alert_count


def main():
    parser = argparse.ArgumentParser(
        description="Scan npm install logs for Sapphire Sleet supply chain attack indicators."
    )
    parser.add_argument("--log", required=True, help="Path to plain-text npm install or audit log")
    parser.add_argument("--baseline", help="Newline-separated trusted package names for typosquat diffing")
    parser.add_argument(
        "--severity",
        choices=["info", "warn", "alert"],
        default="warn",
        help="Minimum severity threshold to emit (default: warn)",
    )
    args = parser.parse_args()

    baseline_packages = []
    if args.baseline:
        try:
            with open(args.baseline, "r", errors="replace") as fh:
                baseline_packages = [l.strip().lower() for l in fh if l.strip()]
        except OSError as exc:
            print(f"ERROR opening baseline file: {exc}", file=sys.stderr)
            sys.exit(2)

    rules = load_rules()
    match_count, alert_count = scan_log(args.log, baseline_packages, rules, args.severity)

    print(f"\nSUMMARY total_matches={match_count} alert_severity={alert_count}")
    if alert_count > 0:
        print(f"RESULT FAIL — {alert_count} alert-severity indicator(s) detected", file=sys.stderr)
        sys.exit(1)
    print("RESULT PASS — no alert-severity indicators detected")


if __name__ == "__main__":
    main()