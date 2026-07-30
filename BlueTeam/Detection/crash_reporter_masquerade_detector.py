"""
CrashStealer macOS Crash Reporter Masquerade Detector

Scans macOS unified log exports for post-Gatekeeper execution anomalies matching
the CrashStealer notarized-dropper pattern.

Usage:
    python crash_reporter_masquerade_detector.py /path/to/unified.log
    python crash_reporter_masquerade_detector.py /path/to/unified.log --severity high
    python crash_reporter_masquerade_detector.py /path/to/unified.log --iocs extra_iocs.json
    python crash_reporter_masquerade_detector.py /path/to/unified.log --severity medium --iocs iocs.json

Log format expected (syslog-style from 'log show --style syslog'):
    2024-01-15 10:23:45.123456-0800  hostname process[1234]: message body
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

CRASH_REPORTER_NAMES = {"crashreporter", "reportcrash", "crashpad_handler", "com.apple.crashreporter"}
SYSTEM_PATHS = ("/System/Library/", "/usr/lib/", "/Library/Apple/")
STAGING_PATHS = ("/tmp/", "/private/tmp/")
STAGING_PATH_PATTERNS = (
    r"Library/Application Support/",
    r"Downloads/",
    r"/tmp/",
    r"/private/tmp/",
)
CREDENTIAL_KEYWORDS = (
    "keychain", "seckeychain", "seckeychainfind", "cookies", "login data",
    "key4.db", "logins.json", "chrome", "safari", "firefox", "credential",
)
BUNDLE_PATTERN = re.compile(r"/Contents/MacOS/", re.IGNORECASE)
LOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+(?:[+-]\d{4})?)"
    r"\s+(?P<host>\S+)\s+(?P<proc>[^\[]+)\[(?P<pid>\d+)\]:\s*(?P<msg>.*)$"
)
TS_FORMATS = ("%Y-%m-%d %H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S.%f")


def parse_ts(ts_str):
    ts_str = ts_str.strip()
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def parse_log_entries(log_file):
    with open(log_file, "r", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = LOG_RE.match(line)
            if not m:
                continue
            proc_field = m.group("proc").strip()
            path_match = re.match(r"^(.+?)\s*\((.+)\)$", proc_field)
            if path_match:
                proc_name = path_match.group(1).strip()
                exec_path = path_match.group(2).strip()
            else:
                proc_name = proc_field
                exec_path = ""
            yield {
                "ts_str": m.group("ts").strip(),
                "ts": parse_ts(m.group("ts")),
                "host": m.group("host"),
                "proc": proc_name,
                "pid": m.group("pid"),
                "exec_path": exec_path,
                "msg": m.group("msg"),
                "raw": line,
            }


def is_crash_reporter_name(name):
    return name.lower() in CRASH_REPORTER_NAMES or any(
        cr in name.lower() for cr in CRASH_REPORTER_NAMES
    )


def is_system_path(path):
    return any(path.startswith(sp) for sp in SYSTEM_PATHS)


def match_rules(entry, extra_iocs):
    alerts = []
    proc = entry["proc"]
    exec_path = entry["exec_path"]
    msg = entry["msg"].lower()
    pid = entry["pid"]

    extra_names = set(n.lower() for n in extra_iocs.get("process_names", []))
    extra_parent_paths = extra_iocs.get("non_system_parent_paths", [])
    extra_staging = extra_iocs.get("staging_directories", [])

    all_staging_patterns = list(STAGING_PATH_PATTERNS) + extra_staging

    is_cr_name = is_crash_reporter_name(proc) or any(n in proc.lower() for n in extra_names)
    outside_system = exec_path and not is_system_path(exec_path)
    non_system_parent = any(exec_path.startswith(p) for p in extra_parent_paths) if extra_parent_paths else False

    if is_cr_name and (outside_system or non_system_parent or (is_cr_name and not exec_path)):
        if outside_system or non_system_parent:
            alerts.append({
                "stage": "Masquerade",
                "technique": "T1036.005",
                "rule": "CrashReporterNameMasquerade",
                "severity": "high",
                "proc": proc,
                "pid": pid,
                "raw": entry["raw"],
                "ts": entry["ts"],
            })

    if is_cr_name and outside_system:
        if any(kw in msg for kw in CREDENTIAL_KEYWORDS):
            alerts.append({
                "stage": "CredentialAccess",
                "technique": "T1555.001/T1555.003",
                "rule": "CredentialStoreAccessFromSpoofedProcess",
                "severity": "high",
                "proc": proc,
                "pid": pid,
                "raw": entry["raw"],
                "ts": entry["ts"],
            })

    staging_hit = any(re.search(pat, entry["msg"], re.IGNORECASE) for pat in all_staging_patterns)
    no_bundle = exec_path and not BUNDLE_PATTERN.search(exec_path)
    if staging_hit and (is_cr_name or no_bundle):
        write_exec = re.search(r"\b(write|exec|spawn|launch|open|install|copy|mv|cp)\b", msg)
        if write_exec:
            alerts.append({
                "stage": "PayloadStaging",
                "technique": "T1105/T1036.005",
                "rule": "NotarizedDropperPayloadStaging",
                "severity": "medium",
                "proc": proc,
                "pid": pid,
                "raw": entry["raw"],
                "ts": entry["ts"],
            })

    return alerts


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def report_findings(log_file, extra_iocs, min_severity):
    stage_counts = defaultdict(int)
    technique_set = set()
    peak_severity = "low"
    dedup = {}
    has_high = False

    try:
        entries = parse_log_entries(log_file)
    except OSError as e:
        print(f"ERROR: Cannot open log file: {e}", file=sys.stderr)
        sys.exit(2)

    for entry in entries:
        try:
            alerts = match_rules(entry, extra_iocs)
        except Exception:
            continue

        for alert in alerts:
            if SEVERITY_ORDER.get(alert["severity"], 0) < SEVERITY_ORDER.get(min_severity, 0):
                continue

            dedup_key = (alert["rule"], alert["pid"])
            ts = alert["ts"]
            if dedup_key in dedup and ts and dedup[dedup_key]:
                if ts - dedup[dedup_key] < timedelta(seconds=60):
                    continue
            dedup[dedup_key] = ts

            raw_preview = alert["raw"][:200]
            print(
                f"[{alert.get('ts_str', entry['ts_str'])}] "
                f"ALERT stage={alert['stage']} "
                f"technique={alert['technique']} "
                f"severity={alert['severity'].upper()} "
                f"rule={alert['rule']} "
                f"proc={alert['proc']}[{alert['pid']}] | {raw_preview}"
            )

            stage_counts[alert["stage"]] += 1
            technique_set.add(alert["technique"])

            if SEVERITY_ORDER.get(alert["severity"], 0) > SEVERITY_ORDER.get(peak_severity, 0):
                peak_severity = alert["severity"]
            if alert["severity"] == "high":
                has_high = True

    print("\n--- Summary ---")
    for stage, count in sorted(stage_counts.items()):
        print(f"  {stage}: {count} hit(s)")
    print(f"  ATT&CK techniques observed: {', '.join(sorted(technique_set)) or 'none'}")
    print(f"  Peak severity: {peak_severity.upper()}")

    if has_high:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="CrashStealer macOS Crash Reporter Masquerade Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("log_file", help="Path to macOS unified log export (syslog-style)")
    parser.add_argument("--iocs", help="Path to supplemental JSON IOC file", default=None)
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum alert severity to emit (default: low)",
    )
    args = parser.parse_args()

    extra_iocs = {}
    if args.iocs:
        try:
            with open(args.iocs, "r") as f:
                extra_iocs = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: Cannot load IOC file: {e}", file=sys.stderr)
            sys.exit(2)

    report_findings(args.log_file, extra_iocs, args.severity)


if __name__ == "__main__":
    main()