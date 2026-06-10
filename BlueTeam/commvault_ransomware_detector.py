"""
Commvault Ransomware Pre-Staging Detector

Analyzes plain-text Commvault log exports for ransomware pre-staging indicators:
  - Anomalous API calls (e.g., bulk credential lookups, export endpoints)
  - Credential enumeration patterns (repeated identity/token requests)
  - Job-schedule tampering (disable/delete/modify backup schedules or policies)

Usage:
    python commvault_ransomware_detector.py --log-file /path/to/commvault.log
    python commvault_ransomware_detector.py --log-file /path/to/commvault.log --threshold 5
    python commvault_ransomware_detector.py --log-file /path/to/commvault.log --since 2024-01-15T08:00:00

Output is TLP:AMBER -- may contain sensitive infrastructure details.
Run on an isolated analyst workstation, not shared systems.
"""

import argparse
import re
import sys
from datetime import datetime, timezone


DETECTION_RULES = [
    # --- Anomalous API calls ---
    {
        "name": "Bulk Credential Export API",
        "pattern": re.compile(
            r"(GET|POST)\s+.*/(?:identity|credentials?|secrets?|token)s?\b.*(export|dump|list|getAll|bulk)",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
        "category": "anomalous-api",
    },
    {
        "name": "Commvault REST API Login Burst",
        "pattern": re.compile(
            r"(POST|api call).*?/(?:v[12]/)?(?:Login|CreateSession|GetAuthToken)",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
        "category": "anomalous-api",
    },
    {
        "name": "Client/Agent Enumeration API",
        "pattern": re.compile(
            r"(GET|api call).*?/(?:v[12]/)?(?:Client|Agent|Subclient|BackupSet)\b.*(getAll|list|getAllClients|getAllAgents)",
            re.IGNORECASE,
        ),
        "severity": "MEDIUM",
        "category": "anomalous-api",
    },
    {
        "name": "Disaster Recovery / Export Config Call",
        "pattern": re.compile(
            r"(GET|POST|api call).*?/(?:v[12]/)?(?:DRBackup|ExportSettings|CommCellMigration|ExportEntities)",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
        "category": "anomalous-api",
    },
    {
        "name": "Storage Policy or Library Enumeration",
        "pattern": re.compile(
            r"(GET|api call).*?/(?:v[12]/)?(?:StoragePolicy|Library|MediaAgent)\b.*(getAll|list)",
            re.IGNORECASE,
        ),
        "severity": "LOW",
        "category": "anomalous-api",
    },
    # --- Credential enumeration ---
    {
        "name": "QSDK/QLogin Credential Probing",
        "pattern": re.compile(
            r"(qlogin|qsdk|CommCell_Login|CvGUI.*login|qoperation\s+execscript.*login)",
            re.IGNORECASE,
        ),
        "severity": "MEDIUM",
        "category": "credential-enumeration",
    },
    {
        "name": "Repeated Auth Failure",
        "pattern": re.compile(
            r"(authentication\s+fail|login\s+fail|invalid\s+(password|credentials?)|access\s+denied|unauthorized)",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
        "category": "credential-enumeration",
    },
    {
        "name": "New User / Role Creation",
        "pattern": re.compile(
            r"(createUser|addUser|createRole|assignRole|POST.*?/(?:v[12]/)?(?:User|Role)\b)",
            re.IGNORECASE,
        ),
        "severity": "MEDIUM",
        "category": "credential-enumeration",
    },
    {
        "name": "Password Reset or Token Refresh",
        "pattern": re.compile(
            r"(resetPassword|changePassword|updatePassword|renewToken|refreshToken|POST.*?/(?:v[12]/)?(?:Password|Token)\b)",
            re.IGNORECASE,
        ),
        "severity": "MEDIUM",
        "category": "credential-enumeration",
    },
    # --- Job / schedule tampering ---
    {
        "name": "Backup Schedule Disabled or Deleted",
        "pattern": re.compile(
            r"(disableSchedule|deleteSchedule|schedule.*disabled|schedule.*deleted|PUT.*?/(?:v[12]/)?Schedule\b.*disabl)",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
        "category": "schedule-tamper",
    },
    {
        "name": "Backup Job Killed or Suspended",
        "pattern": re.compile(
            r"(killJob|suspendJob|job.*killed|job.*suspended|POST.*?/(?:v[12]/)?Job\b.*(kill|suspend))",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
        "category": "schedule-tamper",
    },
    {
        "name": "Storage Policy Modified or Deleted",
        "pattern": re.compile(
            r"(deleteStoragePolicy|modifyStoragePolicy|storage\s+policy.*deleted|storage\s+policy.*modified|DELETE.*?/(?:v[12]/)?StoragePolicy\b)",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
        "category": "schedule-tamper",
    },
    {
        "name": "Subclient or Backup Set Deleted",
        "pattern": re.compile(
            r"(deleteSubclient|deleteBackupSet|subclient.*deleted|backupset.*deleted|DELETE.*?/(?:v[12]/)?(?:Subclient|BackupSet)\b)",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
        "category": "schedule-tamper",
    },
    {
        "name": "Retention Policy Shortened",
        "pattern": re.compile(
            r"(modifyRetention|updateRetention|retention.*modified|retentionDays\s*=\s*[0-3]\b)",
            re.IGNORECASE,
        ),
        "severity": "MEDIUM",
        "category": "schedule-tamper",
    },
    {
        "name": "Commvault Service or Process Stopped",
        "pattern": re.compile(
            r"(stop.*commvault|cvd\s+stop|GxCVD.*stop|services?\s+stop.*commvault|net\s+stop.*GxCVD)",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
        "category": "schedule-tamper",
    },
]

SEVERITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
MAX_SAMPLES = 5


def _parse_line_timestamp(line):
    """Return aware UTC datetime extracted from a log line, or None."""
    candidates = [
        (r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]),
        (r"(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})", ["%m/%d/%Y %H:%M:%S"]),
    ]
    for pat, fmts in candidates:
        m = re.search(pat, line)
        if m:
            raw = m.group(1)
            for fmt in fmts:
                try:
                    return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
    return None


def load_log_lines(path, since):
    """Read log file; filter to lines at or after `since` when provided."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.readlines()
    except FileNotFoundError:
        sys.exit("[ERROR] Log file not found: " + path)
    except PermissionError:
        sys.exit("[ERROR] Permission denied reading: " + path)
    except OSError as exc:
        sys.exit("[ERROR] Could not read log file: " + str(exc))

    stripped = [l.rstrip("\n") for l in raw]
    if since is None:
        return stripped

    result = []
    for line in stripped:
        ts = _parse_line_timestamp(line)
        # Keep lines with no parseable timestamp -- cannot exclude what we cannot date
        if ts is None or ts >= since:
            result.append(line)
    return result


def run_detection_rules(lines, threshold):
    """Apply all rules to `lines`; return findings that meet `threshold`."""
    hits = {rule["name"]: [] for rule in DETECTION_RULES}
    for line in lines:
        for rule in DETECTION_RULES:
            if rule["pattern"].search(line):
                hits[rule["name"]].append(line)

    findings = []
    for rule in DETECTION_RULES:
        matched = hits[rule["name"]]
        if len(matched) >= threshold:
            findings.append({
                "name": rule["name"],
                "severity": rule["severity"],
                "category": rule["category"],
                "count": len(matched),
                "samples": matched[:MAX_SAMPLES],
            })

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["count"]), reverse=True)
    return findings


def print_report(findings):
    """Print structured findings and a summary verdict to stdout."""
    sep = "=" * 72
    print(sep)
    print("  COMMVAULT RANSOMWARE PRE-STAGING DETECTOR -- FINDINGS REPORT")
    print(sep)

    if not findings:
        print("\n[+] No patterns exceeded the threshold. Result: CLEAN\n")
        return

    for idx, f in enumerate(findings, 1):
        print("\n[%d] %s" % (idx, f["name"]))
        print("    Severity : " + f["severity"])
        print("    Category : " + f["category"])
        print("    Matches  : %d" % f["count"])
        print("    Samples  :")
        for sample in f["samples"]:
            display = sample if len(sample) <= 200 else sample[:197] + "..."
            print("      > " + display)

    print()
    print(sep)
    highest = findings[0]["severity"]
    total = len(findings)
    print("  VERDICT: SUSPICIOUS  |  findings=%d  |  highest_severity=%s" % (total, highest))
    print(sep)
    print()


def _parse_since_arg(value):
    """Parse ISO datetime string into an aware UTC datetime."""
    fmts = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d",
    ]
    for fmt in fmts:
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    sys.exit("[ERROR] Cannot parse --since '%s'. Use ISO format, e.g. 2024-01-15T08:00:00" % value)


def main():
    parser = argparse.ArgumentParser(
        prog="commvault_ransomware_detector",
        description="Detect ransomware pre-staging indicators in Commvault log exports.",
    )
    parser.add_argument(
        "--log-file",
        required=True,
        metavar="PATH",
        help="Path to plain-text Commvault log export file",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        metavar="N",
        help="Minimum rule hits to flag a pattern (default: 3)",
    )
    parser.add_argument(
        "--since",
        metavar="DATETIME",
        default=None,
        help="Only analyze lines after this ISO datetime (e.g. 2024-01-15T08:00:00)",
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be >= 1")

    since_dt = _parse_since_arg(args.since) if args.since else None

    lines = load_log_lines(args.log_file, since_dt)

    if not lines:
        print("[INFO] No log lines matched the time window. Nothing to analyze.")
        sys.exit(0)

    print("[INFO] Loaded %d log line(s) from %s" % (len(lines), args.log_file))
    if since_dt:
        print("[INFO] Time filter: lines after " + since_dt.isoformat())
    print("[INFO] Detection threshold: %d hit(s) per pattern\n" % args.threshold)

    findings = run_detection_rules(lines, args.threshold)
    print_report(findings)

    # Exit 1 when findings exist -- useful for SIEM/pipeline integration
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
