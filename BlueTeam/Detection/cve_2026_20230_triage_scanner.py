"""
CVE-2026-20230 Cisco UCM Triage Scanner

Scans plain-text Cisco UCM logs for indicators of active exploitation of CVE-2026-20230
(auth bypass / anomalous admin API calls / unexpected session tokens).

Usage:
    python cve_2026_20230_triage_scanner.py /var/log/ucm/audit.log
    python cve_2026_20230_triage_scanner.py /var/log/ucm/audit.log --hostname 10.0.0.5
    python cve_2026_20230_triage_scanner.py /var/log/ucm/audit.log --since 2026-06-20T00:00:00
"""

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

PATTERNS = {
    "auth_bypass": (
        r"(?i)(bypass|unauthenticated|no.?auth|auth.?skip|401.?override|"
        r"unauthorized.*admin|forged.?token|token.?forgery)",
        "CRITICAL",
    ),
    "anomalous_admin_api": (
        r"(?i)(POST|GET|PUT|DELETE)\s+/(?:ccmadmin|axl|cucm)/(?:api|ws|service)"
        r".*(?:unexpected|invalid.?session|replay|duplicate.?nonce|malformed)",
        "CRITICAL",
    ),
    "privilege_escalation": (
        r"(?i)(privilege.?escal|role.?elevated|sudo.*ccm|escalated.*admin"
        r"|gained.*superuser|unauthorized.*role.?change)",
        "CRITICAL",
    ),
    "unexpected_session_token": (
        r"(?i)(session.?token.*invalid|token.*expired.*reused|"
        r"jwt.*tamper|cookie.*forged|jsessionid.*mismatch)",
        "HIGH",
    ),
    "suspicious_admin_login": (
        r"(?i)(admin.*login.*fail.*\d{3,}|brute.?force|"
        r"repeated.*auth.*failure|lockout.?bypass)",
        "HIGH",
    ),
    "cve_reference": (
        r"(?i)(CVE-2026-20230|20230-cisco|ucm.?rce|ucm.?bypass)",
        "HIGH",
    ),
    "recon_probe": (
        r"(?i)(version.?disclosure|/version|/status|/api/v\d+/health"
        r"|fingerprint.*ucm|banner.?grab)",
        "INFO",
    ),
}

TIMESTAMP_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
)

SEVERITY_ORDER = {"CRITICAL": 3, "HIGH": 2, "INFO": 1}


def parse_line_timestamp(line: str):
    m = TIMESTAMP_RE.search(line)
    if not m:
        return None
    raw = m.group(1).replace(" ", "T")
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def scan_log(log_path: Path, hostname: str | None, since: datetime | None) -> list[dict]:
    findings = []
    compiled = {name: (re.compile(pat), sev) for name, (pat, sev) in PATTERNS.items()}
    with log_path.open("r", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            if hostname and hostname not in line:
                continue
            ts = parse_line_timestamp(line)
            if since and ts and ts < since:
                continue
            for ioc_name, (regex, severity) in compiled.items():
                if regex.search(line):
                    findings.append({
                        "lineno": lineno,
                        "ioc": ioc_name,
                        "severity": severity,
                        "timestamp": ts.isoformat() if ts else "unknown",
                        "excerpt": line.rstrip()[:200],
                    })
    return findings


def assess_severity(findings: list[dict]) -> tuple[str, str]:
    if not findings:
        return "INFO", "low"
    ioc_types = {f["ioc"] for f in findings}
    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    has_escalation = "privilege_escalation" in ioc_types
    has_bypass = "auth_bypass" in ioc_types
    if critical_count >= 3 or (has_escalation and has_bypass):
        return "CRITICAL", "high"
    if critical_count >= 1 or has_bypass or has_escalation:
        return "HIGH", "medium"
    return "INFO", "low"


def render_report(findings: list[dict], overall_sev: str, confidence: str, log_path: Path):
    sep = "=" * 70
    print(sep)
    print("CVE-2026-20230 Cisco UCM TRIAGE REPORT")
    print(f"Log file : {log_path}")
    print(f"Generated: {datetime.utcnow().isoformat()}Z")
    print(sep)
    print(f"OVERALL SEVERITY : {overall_sev}")
    print(f"CONFIDENCE       : {confidence}")
    print(f"TOTAL MATCHES    : {len(findings)}")
    print()

    if findings:
        print("--- MATCHED IOCs ---")
        for f in findings:
            print(f"[{f['severity']:8s}] Line {f['lineno']:>6} | {f['timestamp']} | {f['ioc']}")
            print(f"          {f['excerpt']}")
        print()
    else:
        print("No exploitation indicators detected in the provided log.\n")

    print("--- PATCH VERIFICATION RUNBOOK ---")
    print("1. Check installed UCM version (SSH to publisher node):")
    print("     show version active")
    print("   Expected patched versions: 14.0(1)SU4 or later, 15.0(1)SU1 or later.")
    print()
    print("2. Verify advisory remediation applied:")
    print("   Cisco Security Advisory: cisco-sa-ucm-authbypass-CVE-2026-20230")
    print("   URL: https://sec.cloudapps.cisco.com/security/center/content/")
    print("        CiscoSecurityAdvisory/cisco-sa-ucm-authbypass-CVE-2026-20230")
    print()
    print("3. Review active admin sessions:")
    print("     show ccm admin sessions")
    print()
    print("4. Rollback note: Downgrade path is NOT supported for this fix.")
    print("   Snapshot/backup the cluster BEFORE applying the patch.")
    print()
    print("5. Escalation: If CRITICAL indicators confirmed, isolate the UCM")
    print("   publisher from external networks and engage Cisco TAC immediately.")
    print()
    print("--- DISCLAIMER ---")
    print("This report is advisory only. All findings must be reviewed by a")
    print("qualified analyst before remediation actions are taken.")
    print(sep)


def main():
    parser = argparse.ArgumentParser(
        description="Triage scanner for CVE-2026-20230 in Cisco UCM log files."
    )
    parser.add_argument("log_file", help="Path to plain-text Cisco UCM log file")
    parser.add_argument("--hostname", help="Filter lines containing this hostname or IP")
    parser.add_argument(
        "--since",
        help="ISO datetime string; skip entries before this time (e.g. 2026-06-20T00:00:00)",
    )
    args = parser.parse_args()

    log_path = Path(args.log_file)
    if not log_path.exists():
        print(f"ERROR: Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)
    if not log_path.is_file():
        print(f"ERROR: Path is not a regular file: {log_path}", file=sys.stderr)
        sys.exit(1)

    since_dt = None
    if args.since:
        try:
            since_dt = datetime.fromisoformat(args.since)
        except ValueError:
            print(f"ERROR: Invalid --since datetime format: {args.since}", file=sys.stderr)
            sys.exit(1)

    try:
        findings = scan_log(log_path, args.hostname, since_dt)
    except PermissionError:
        print(f"ERROR: Permission denied reading: {log_path}", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"ERROR: Could not read log file: {exc}", file=sys.stderr)
        sys.exit(1)

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 0), reverse=True)
    overall_sev, confidence = assess_severity(findings)
    render_report(findings, overall_sev, confidence, log_path)


if __name__ == "__main__":
    main()