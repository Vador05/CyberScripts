"""
GRC Evidence Gap Scanner

Parses plain-text audit logs against a JSON control catalog and surfaces
controls whose evidence is missing or outside the required collection window.

Usage example:
    python grc_evidence_gap_scanner.py --log audit.log --controls controls.json --window 30

controls.json format:
    [
        {
            "id": "AC-2",
            "description": "Account Management",
            "criticality": "high",
            "max_evidence_age_days": 7,
            "pattern": "account.*(created|modified|deleted)",
            "remediation": "Run account audit report and attach to AC-2 evidence folder"
        }
    ]

audit.log format (one entry per line):
    2026-06-20T14:32:01 account modified user=jdoe by=admin
"""

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone


TIMESTAMP_PATTERNS = [
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})",
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
    r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})",
    r"(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})",
]

TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%b %d %H:%M:%S",
]

VALID_CRITICALITIES = {"critical", "high", "medium", "low"}


def parse_timestamp(line):
    for pattern, fmt in zip(TIMESTAMP_PATTERNS, TIMESTAMP_FORMATS):
        m = re.search(pattern, line)
        if m:
            raw = m.group(1)
            try:
                if "%Y" not in fmt:
                    raw = f"{datetime.now(timezone.utc).year} {raw}"
                    fmt = f"%Y {fmt}"
                return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def parse_log(log_path, controls, window_start):
    evidence = {ctrl["id"]: None for ctrl in controls}

    compiled = {}
    for ctrl in controls:
        try:
            compiled[ctrl["id"]] = re.compile(ctrl["pattern"], re.IGNORECASE)
        except re.error as exc:
            print(
                f"ERROR: Invalid regex pattern for control '{ctrl['id']}': {exc}",
                file=sys.stderr,
            )
            sys.exit(2)

    try:
        with open(log_path, "r", errors="replace") as fh:
            for line in fh:
                line = line.rstrip()
                ts = parse_timestamp(line)
                if ts is None or ts < window_start:
                    continue
                for ctrl in controls:
                    cid = ctrl["id"]
                    if compiled[cid].search(line):
                        if evidence[cid] is None or ts > evidence[cid]:
                            evidence[cid] = ts
    except OSError as exc:
        print(f"ERROR: Cannot read log file: {exc}", file=sys.stderr)
        sys.exit(2)

    return evidence


def load_controls(controls_path):
    try:
        with open(controls_path, "r") as fh:
            data = json.load(fh)
    except OSError as exc:
        print(f"ERROR: Cannot read controls file: {exc}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in controls file: {exc}", file=sys.stderr)
        sys.exit(2)

    if not isinstance(data, list):
        print("ERROR: Controls file must contain a JSON array.", file=sys.stderr)
        sys.exit(2)

    required_fields = {"id", "criticality", "max_evidence_age_days", "pattern", "remediation"}
    for i, ctrl in enumerate(data):
        if not isinstance(ctrl, dict):
            print(f"ERROR: Control at index {i} is not an object.", file=sys.stderr)
            sys.exit(2)

        missing = required_fields - ctrl.keys()
        if missing:
            print(f"ERROR: Control at index {i} missing fields: {missing}", file=sys.stderr)
            sys.exit(2)

        max_age = ctrl["max_evidence_age_days"]
        if not isinstance(max_age, (int, float)) or isinstance(max_age, bool) or max_age <= 0:
            print(
                f"ERROR: Control at index {i} 'max_evidence_age_days' must be a positive number.",
                file=sys.stderr,
            )
            sys.exit(2)

        crit = ctrl["criticality"].lower() if isinstance(ctrl["criticality"], str) else ""
        if crit not in VALID_CRITICALITIES:
            print(
                f"ERROR: Control at index {i} has unknown criticality '{ctrl['criticality']}'. "
                f"Must be one of: {', '.join(sorted(VALID_CRITICALITIES))}.",
                file=sys.stderr,
            )
            sys.exit(2)

    return data


def evaluate_controls(controls, evidence, now):
    gaps = []
    for ctrl in controls:
        cid = ctrl["id"]
        last_seen = evidence.get(cid)
        max_age = ctrl["max_evidence_age_days"]

        if last_seen is None:
            gap_days = float("inf")
            last_seen_str = "NEVER"
        else:
            gap_days = (now - last_seen).days
            last_seen_str = last_seen.strftime("%Y-%m-%d")

        if gap_days > max_age:
            gaps.append({
                "id": cid,
                "description": ctrl.get("description", ""),
                "last_seen": last_seen_str,
                "gap_days": gap_days,
                "max_age": max_age,
                "criticality": ctrl["criticality"].lower(),
                "remediation": ctrl["remediation"],
            })

    criticality_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    gaps.sort(key=lambda g: (
        criticality_rank.get(g["criticality"], 9),
        -(g["gap_days"] if g["gap_days"] != float("inf") else 99999),
    ))
    return gaps


def report_gaps(gaps):
    if not gaps:
        print("No evidence gaps detected.")
        return False

    col_w = [12, 18, 10, 12, 55]
    header = (
        f"{'Control ID':<{col_w[0]}} "
        f"{'Last Evidence':<{col_w[1]}} "
        f"{'Gap Days':<{col_w[2]}} "
        f"{'Criticality':<{col_w[3]}} "
        f"{'Suggested Remediation':<{col_w[4]}}"
    )
    sep = "-" * sum(col_w) + "-" * (len(col_w) - 1)

    print(header)
    print(sep)

    has_critical = False
    for g in gaps:
        crit = g["criticality"]
        if crit == "critical":
            has_critical = True
        gap_str = "INF" if g["gap_days"] == float("inf") else str(g["gap_days"])
        print(
            f"{g['id']:<{col_w[0]}} "
            f"{g['last_seen']:<{col_w[1]}} "
            f"{gap_str:<{col_w[2]}} "
            f"{crit:<{col_w[3]}} "
            f"{g['remediation']:<{col_w[4]}}"
        )

    print(sep)
    print(f"Total gaps: {len(gaps)}")
    return has_critical


def main():
    parser = argparse.ArgumentParser(
        description="GRC Evidence Gap Scanner: detect compliance control evidence gaps in audit logs."
    )
    parser.add_argument("--log", required=True, metavar="PATH", help="Plain-text audit log file")
    parser.add_argument("--controls", required=True, metavar="PATH", help="JSON control catalog file")
    parser.add_argument("--window", type=int, default=30, metavar="INT", help="Lookback period in days (default 30)")
    args = parser.parse_args()

    if args.window <= 0:
        print("ERROR: --window must be a positive integer.", file=sys.stderr)
        sys.exit(2)

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=args.window)

    controls = load_controls(args.controls)
    evidence = parse_log(args.log, controls, window_start)
    gaps = evaluate_controls(controls, evidence, now)
    has_critical = report_gaps(gaps)

    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()