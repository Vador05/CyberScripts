"""
Ivanti Sentry Sigma Rule Matcher - Detects CVE-2023-38035 exploitation patterns in logs.

Usage:
    python ivanti_sentry_sigma_matcher.py /var/log/ivanti/sentry.log
    python ivanti_sentry_sigma_matcher.py /var/log/ivanti/sentry.log --severity high
    python ivanti_sentry_sigma_matcher.py /var/log/ivanti/sentry.log --rules extra_rules.json
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Strip ANSI escape sequences to prevent terminal injection from adversarial log content
_ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Cap line length fed to the regex engine to mitigate ReDoS on crafted log files
_MAX_LINE_MATCH_LEN = 2000

BUILTIN_RULES = [
    {
        "name": "ivanti_sentry_admin_portal_access",
        "severity": "high",
        "description": "Access to Ivanti Sentry administrative portal (port 8443)",
        "patterns": [r"8443.*/(admin|mics|mics-login|MICS)", r"/(admin|mics).*8443"],
        "runbook": [
            "Verify if source IP is an authorized administrator workstation",
            "Check if MobileIron Configuration Service (MICS) access was expected",
            "Review authentication logs for this source IP around the same time",
            "If unauthorized, block source IP at perimeter firewall immediately",
            "Escalate to IR team and preserve log artifacts for forensic review",
        ],
    },
    {
        "name": "ivanti_sentry_cve_2023_38035_exploit",
        "severity": "critical",
        "description": "CVE-2023-38035 exploitation attempt via MICS API authentication bypass",
        "patterns": [
            r"POST.*/(mics/v1\.5/|MICS/v1\.5/).*system",
            r"8443.*/mics/v1\.5/system/(certificates|sslcertificate)",
            r"authentication bypass.*sentry",
            r"mics.*api.*unauthenticated",
        ],
        "runbook": [
            "CRITICAL: Assume compromise if pattern matches — isolate appliance immediately",
            "Capture full memory and disk image of affected Ivanti Sentry appliance",
            "Identify all authenticated sessions active at time of match",
            "Check for new admin accounts or modified SSL certificates post-event",
            "Review outbound connections from appliance for C2 beaconing",
            "Apply Ivanti-released patches or mitigations per vendor advisory",
            "Notify CISO and begin formal incident response process",
        ],
    },
    {
        "name": "ivanti_sentry_recon_user_agent",
        "severity": "medium",
        "description": "Reconnaissance user-agent string associated with Sentry scanning",
        "patterns": [
            r"(python-requests|curl|wget|nuclei|masscan|zgrab).*8443",
            r"8443.*(python-requests|curl/[0-9]|Go-http-client|okhttp)",
        ],
        "runbook": [
            "Correlate source IP with threat intelligence feeds",
            "Check for follow-on exploitation attempts from same source",
            "If IP is external and unexpected, block at perimeter",
            "Review other log sources for lateral movement from same actor",
        ],
    },
    {
        "name": "ivanti_sentry_path_traversal_attempt",
        "severity": "high",
        "description": "Path traversal attempt against Ivanti Sentry web interface",
        "patterns": [
            r"(\.\./|%2e%2e%2f|%252e%252e%252f|\.\.%2f).*sentry",
            r"8443.*(\.\./|%2e%2e|%252e%252e)",
        ],
        "runbook": [
            "Block source IP immediately if traversal sequence detected",
            "Check WAF logs for additional traversal attempts",
            "Review file system for unauthorized file reads or modifications",
            "Determine if traversal reached sensitive configuration files",
            "Document IOCs and report to threat intelligence team",
        ],
    },
    {
        "name": "ivanti_sentry_command_injection",
        "severity": "critical",
        "description": "Command injection pattern in Ivanti Sentry request",
        "patterns": [
            r"8443.*[;&|`$]\s*(id|whoami|uname|cat\s+/etc|wget|curl)\b",
            r"(cmd|exec|system|shell_exec).*sentry.*8443",
        ],
        "runbook": [
            "CRITICAL: Treat as active exploitation — isolate appliance from network",
            "Preserve volatile memory before any remediation steps",
            "Check running processes for unexpected shells or reverse connections",
            "Review /tmp and world-writable directories for dropped payloads",
            "Engage IR team and vendor support immediately",
        ],
    },
    {
        "name": "ivanti_sentry_failed_auth_spike",
        "severity": "medium",
        "description": "Multiple authentication failures against Sentry admin interface",
        "patterns": [
            r"(401|403|authentication failed|invalid credentials).*8443",
            r"8443.*(401|403|login.*fail|auth.*fail)",
        ],
        "runbook": [
            "Count failure rate — more than 10/minute from single IP suggests brute force",
            "Temporarily block source IP if rate exceeds threshold",
            "Check for successful auth following failures (credential stuffing)",
            "Enable account lockout policy if not already configured",
            "Review threat intel for IP reputation",
        ],
    },
    {
        "name": "ivanti_sentry_cert_manipulation",
        "severity": "high",
        "description": "SSL certificate endpoint access pattern associated with CVE-2023-38035",
        "patterns": [
            r"(PUT|POST|DELETE).*/(ssl|certificate|cert).*8443",
            r"8443.*(PUT|POST).*(sslcertificate|ssl-cert|certificate)",
        ],
        "runbook": [
            "Verify if certificate change was authorized via change management",
            "Check current installed certificates against known-good baseline",
            "If unauthorized, revoke new certificate and restore from backup",
            "Treat as potential CVE-2023-38035 exploitation attempt",
            "Review MICS API logs for surrounding authentication bypass attempts",
        ],
    },
]

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _sanitize(text):
    return _ANSI_ESCAPE.sub("", text)


def _validate_rule(rule, source="rules file"):
    """Return True and emit warnings for recoverable issues; return False to skip rule."""
    if not isinstance(rule, dict):
        print(f"[WARN] Skipping non-object entry in {source}", file=sys.stderr)
        return False
    if not rule.get("name"):
        print(f"[WARN] Skipping rule with missing 'name' in {source}", file=sys.stderr)
        return False
    patterns = rule.get("patterns")
    if not isinstance(patterns, list) or not patterns:
        print(
            f"[WARN] Skipping rule '{rule.get('name')}' in {source} — 'patterns' must be a non-empty list",
            file=sys.stderr,
        )
        return False
    for p in patterns:
        if not isinstance(p, str):
            print(
                f"[WARN] Skipping rule '{rule.get('name')}' in {source} — all patterns must be strings",
                file=sys.stderr,
            )
            return False
    sev = rule.get("severity", "")
    if sev not in SEVERITY_ORDER:
        print(
            f"[WARN] Rule '{rule.get('name')}' in {source} has unrecognized severity '{sev}', defaulting to 'low'",
            file=sys.stderr,
        )
    return True


def load_rules(extra_path=None):
    rules = list(BUILTIN_RULES)
    if extra_path:
        path = Path(extra_path)
        if not path.exists():
            print(f"[ERROR] Rules file not found: {extra_path}", file=sys.stderr)
            sys.exit(1)
        if not path.is_file():
            print(f"[ERROR] Rules path is not a file: {extra_path}", file=sys.stderr)
            sys.exit(1)
        try:
            with open(path, "r", encoding="utf-8") as f:
                extra = json.load(f)
        except PermissionError:
            print(f"[ERROR] Permission denied reading rules file: {extra_path}", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"[ERROR] Invalid JSON in rules file: {e}", file=sys.stderr)
            sys.exit(1)
        if not isinstance(extra, list):
            print("[ERROR] Rules file must contain a JSON array", file=sys.stderr)
            sys.exit(1)
        for rule in extra:
            if _validate_rule(rule, source=str(extra_path)):
                rules.append(rule)
    return rules


def match_log(logfile, rules, min_severity):
    path = Path(logfile).resolve()
    if not path.exists():
        print(f"[ERROR] Log file not found: {logfile}", file=sys.stderr)
        sys.exit(1)
    if not path.is_file():
        print(f"[ERROR] Log path is not a file: {logfile}", file=sys.stderr)
        sys.exit(1)
    min_level = SEVERITY_ORDER.get(min_severity, 1)
    compiled = []
    for rule in rules:
        sev = rule.get("severity", "low")
        if SEVERITY_ORDER.get(sev, 0) < min_level:
            continue
        try:
            patterns = [re.compile(p, re.IGNORECASE) for p in rule.get("patterns", [])]
        except re.error as e:
            print(f"[WARN] Skipping rule '{rule.get('name')}' — bad regex: {e}", file=sys.stderr)
            continue
        compiled.append((rule, patterns))
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                line = line.rstrip("\n")
                match_target = line[:_MAX_LINE_MATCH_LEN]
                for rule, patterns in compiled:
                    for pat in patterns:
                        if pat.search(match_target):
                            yield {
                                "rule": rule,
                                "line": line,
                                "lineno": lineno,
                                "file": str(path),
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }
                            break
    except PermissionError:
        print(f"[ERROR] Permission denied reading: {logfile}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"[ERROR] Failed to read log file: {e}", file=sys.stderr)
        sys.exit(1)


def format_alert(match):
    rule = match["rule"]
    sep = "=" * 60
    lines = [
        sep,
        f"TIMESTAMP  : {match['timestamp']}",
        f"ALERT      : {_sanitize(str(rule.get('name', '')))}",
        f"SEVERITY   : {_sanitize(str(rule.get('severity', 'unknown'))).upper()}",
        f"DESCRIPTION: {_sanitize(str(rule.get('description', '')))}",
        f"FILE       : {match['file']}:{match['lineno']}",
        f"EVIDENCE   : {_sanitize(match['line'])}",
        "RUNBOOK    :",
    ]
    for i, step in enumerate(rule.get("runbook", []), 1):
        lines.append(f"  {i}. {_sanitize(str(step))}")
    lines.append(sep)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Scan Ivanti Sentry logs for CVE-2023-38035 exploitation patterns"
    )
    parser.add_argument("logfile", help="Path to plain-text log file to scan")
    parser.add_argument("--rules", metavar="PATH", help="JSON file with additional Sigma-style rules")
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        default="medium",
        help="Minimum severity to report (default: medium)",
    )
    args = parser.parse_args()
    rules = load_rules(args.rules)
    found = False
    for match in match_log(args.logfile, args.severity):
        print(format_alert(match))
        found = True
    if not found:
        print(f"[OK] No matches at severity>={args.severity} in {args.logfile}")


if __name__ == "__main__":
    main()