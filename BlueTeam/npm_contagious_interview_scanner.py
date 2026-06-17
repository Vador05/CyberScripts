"""
Contagious Interview NPM Payload Scanner

Detects behavioral signatures of Contagious Interview threat actor TTPs in npm
package audit logs and repository metadata.

Usage example:
    python npm_contagious_interview_scanner.py audit.log --severity high --output-format json
    python npm_contagious_interview_scanner.py package.json --severity medium
    cat npm-debug.log | python npm_contagious_interview_scanner.py /dev/stdin
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

SIGNATURES = [
    {
        "id": "CI-001",
        "name": "Malicious postinstall hook",
        "ttp": "T1195.002 - Supply Chain Compromise: Software Supply Chain",
        "severity": "critical",
        "pattern": re.compile(
            r'"postinstall"\s*:\s*"[^"]*(?:curl|wget|fetch|node\s+-e|eval|exec)[\s(]',
            re.IGNORECASE,
        ),
    },
    {
        "id": "CI-002",
        "name": "Base64 encoded payload in script",
        "ttp": "T1027 - Obfuscated Files or Information",
        "severity": "high",
        "pattern": re.compile(
            r'(?:Buffer\.from|atob|base64)\s*\(\s*["\'][A-Za-z0-9+/]{40,}={0,2}["\']',
            re.IGNORECASE,
        ),
    },
    {
        "id": "CI-003",
        "name": "BeaverTail staging pattern",
        "ttp": "T1059.007 - Command and Scripting Interpreter: JavaScript",
        "severity": "critical",
        "pattern": re.compile(
            r'(?:require\s*\(\s*["\']https?://|fetch\s*\(\s*["\']https?://).{0,120}(?:\.js["\'])',
            re.IGNORECASE,
        ),
    },
    {
        "id": "CI-004",
        "name": "InvisibleFerret C2 domain fragment",
        "ttp": "T1071.001 - Application Layer Protocol: Web Protocols",
        "severity": "critical",
        "pattern": re.compile(
            r"(?:npm(?:js)?-cdn|cdn-npm|npmcdn|pkgrepo|node-module-cdn|devtools-cdn)\.",
            re.IGNORECASE,
        ),
    },
    {
        "id": "CI-005",
        "name": "Typosquatted developer tool package",
        "ttp": "T1195.002 - Supply Chain Compromise: Software Supply Chain",
        "severity": "high",
        "pattern": re.compile(
            r'"name"\s*:\s*"(?:node-fetch-[a-z]{2,6}|axios-[a-z]{2,8}-module|react-devtools-[a-z]{2,8}|webpack-plugin-[a-z0-9]{4,10})"',
            re.IGNORECASE,
        ),
    },
    {
        "id": "CI-006",
        "name": "Staged payload delivery via install script",
        "ttp": "T1059 - Command and Scripting Interpreter",
        "severity": "high",
        "pattern": re.compile(
            r'"(?:preinstall|install|postinstall)"\s*:\s*"[^"]*node\s+(?:index|main|init|setup|loader)\.js',
            re.IGNORECASE,
        ),
    },
    {
        "id": "CI-007",
        "name": "Environment variable exfiltration attempt",
        "ttp": "T1552.007 - Unsecured Credentials: Container API",
        "severity": "high",
        "pattern": re.compile(
            r"process\.env\s*(?:\.\s*(?:npm_token|npm_auth|node_auth_token|aws_secret|github_token|ci_token)|\[['\"]\w{4,30}['\"])",
            re.IGNORECASE,
        ),
    },
    {
        "id": "CI-008",
        "name": "Dynamic require with network fetch",
        "ttp": "T1059.007 - Command and Scripting Interpreter: JavaScript",
        "severity": "medium",
        "pattern": re.compile(
            r"(?:eval|Function)\s*\(\s*(?:require|await\s+(?:fetch|axios|got))\s*\(",
            re.IGNORECASE,
        ),
    },
    {
        "id": "CI-009",
        "name": "Suspicious preinstall curl/wget",
        "ttp": "T1105 - Ingress Tool Transfer",
        "severity": "critical",
        "pattern": re.compile(
            r'"preinstall"\s*:\s*"[^"]*(?:curl\s+-[sS]|wget\s+-q)[^"]*\|',
            re.IGNORECASE,
        ),
    },
    {
        "id": "CI-010",
        "name": "Known Contagious Interview lure package pattern",
        "ttp": "T1566.002 - Phishing: Spearphishing Link",
        "severity": "critical",
        "pattern": re.compile(
            r'"name"\s*:\s*"(?:coinbase-vip|crypto-utils-pro|zoom-node-sdk|slack-node-sdk|browser-(?:sync|refresh)-module)"',
            re.IGNORECASE,
        ),
    },
]


def parse_log(log_file):
    try:
        with open(log_file, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                yield lineno, line.rstrip("\n")
    except OSError as exc:
        print(f"ERROR: Cannot read file '{log_file}': {exc}", file=sys.stderr)
        sys.exit(1)


def match_signatures(lineno, line, severity_threshold):
    threshold = SEVERITY_ORDER[severity_threshold]
    findings = []
    for sig in SIGNATURES:
        if SEVERITY_ORDER[sig["severity"]] < threshold:
            continue
        m = sig["pattern"].search(line)
        if m:
            findings.append({
                "lineno": lineno,
                "sig_id": sig["id"],
                "name": sig["name"],
                "ttp": sig["ttp"],
                "severity": sig["severity"],
                "evidence": line.strip()[:200],
                "match_start": m.start(),
                "match_end": m.end(),
            })
    return findings


def report_findings(findings, output_format):
    ts = datetime.now(timezone.utc).isoformat()
    category_counts = {}

    for f in findings:
        category_counts.setdefault(f["sig_id"], {"name": f["name"], "count": 0})
        category_counts[f["sig_id"]]["count"] += 1

        if output_format == "json":
            record = {
                "timestamp": ts,
                "severity": f["severity"].upper(),
                "sig_id": f["sig_id"],
                "ttp": f["ttp"],
                "lineno": f["lineno"],
                "finding": f["name"],
                "evidence": f["evidence"],
            }
            print(json.dumps(record))
        else:
            print(
                f"[{ts}] [{f['severity'].upper()}] [{f['sig_id']}] "
                f"Line {f['lineno']}: {f['name']} | TTP: {f['ttp']}"
            )
            print(f"  Evidence: {f['evidence']}")

    print(f"\n--- Summary: {len(findings)} finding(s) across {len(category_counts)} signature(s) ---",
          file=sys.stderr)
    for sig_id, info in sorted(category_counts.items()):
        print(f"  {sig_id} [{info['name']}]: {info['count']}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Contagious Interview NPM Payload Scanner — detects threat actor TTPs in npm logs",
        epilog="Example: python npm_contagious_interview_scanner.py audit.log --severity high --output-format json",
    )
    parser.add_argument("log_file", help="Path to npm audit log or package.json file")
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        default="medium",
        help="Minimum severity threshold for alerts (default: medium)",
    )
    parser.add_argument(
        "--output-format",
        choices=["plain", "json"],
        default="plain",
        help="Alert output format (default: plain)",
    )
    args = parser.parse_args()

    all_findings = []
    for lineno, line in parse_log(args.log_file):
        all_findings.extend(match_signatures(lineno, line, args.severity))

    if not all_findings:
        print(f"No findings at severity >= {args.severity}.", file=sys.stderr)
        sys.exit(0)

    report_findings(all_findings, args.output_format)
    sys.exit(1)


if __name__ == "__main__":
    main()