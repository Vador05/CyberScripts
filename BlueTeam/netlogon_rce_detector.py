"""
Netlogon RCE Detector - Detects CVE-2026-41089 exploitation attempts.

Parses plain-text Windows Security event log exports and reports
indicators of Netlogon RCE exploitation via Event ID 4742/5805
patterns and anomalous Netlogon RPC signatures.

Usage:
    python netlogon_rce_detector.py --log-file security.log
    python netlogon_rce_detector.py --log-file security.log --threshold 5
    python netlogon_rce_detector.py --log-file security.log --since 2026-06-01T00:00:00
"""

import argparse
import re
import sys
from datetime import datetime

RPC_ANOMALY_KEYWORDS = [
    "netlogon", "nrpc", "msrpc", "zerologon", "netlogonssp",
    "secure channel", "anonymouspipe", "null session",
    "credential reset", "machine account", "computer account password",
]

RULE_4742_MACHINE_RESET = "4742_machine_account_password_reset"
RULE_5805_SECURE_CHANNEL = "5805_failed_secure_channel"
RULE_RPC_ANOMALY = "netlogon_rpc_anomaly"
RULE_ANONYMOUS_ACCESS = "anonymous_netlogon_access"
RULE_RAPID_RESET = "rapid_credential_reset"

_TS_RE = re.compile(r"(?:Date:|Time:|Date/Time:)\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")
_EID_RE = re.compile(r"(?:Event\s*ID|EventID):\s*(\d+)")
# Separate patterns so Computer: can override Source: (Source is the log provider name, not the host)
_SRC_RE = re.compile(r"Source:\s*(\S+)")
_COMPUTER_RE = re.compile(r"Computer:\s*(\S+)")
_DESC_RE = re.compile(r"(?:Description|Message):\s*(.+)")
# Match machine-account names (word chars followed by $) rather than any bare $
_MACHINE_ACCOUNT_RE = re.compile(r"\b\w+\$")


def parse_events(log_file, since):
    events = []
    current = {}

    try:
        fh = open(log_file, "r", encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"[ERROR] Cannot open log file: {exc}", file=sys.stderr)
        sys.exit(1)

    with fh:
        for raw_line in fh:
            line = raw_line.strip()

            if not line:
                if current.get("event_id") is not None:
                    ts = current.get("timestamp")
                    if since is None or ts is None or ts >= since:
                        events.append(current)
                current = {}
                continue

            # Only parse structured fields before description accumulation begins.
            # Windows event descriptions contain sub-fields (e.g. "Computer: hostname",
            # "Event ID: 4742") that would corrupt already-parsed metadata if re-matched
            # after strip() removes their leading whitespace.
            if "description" not in current:
                m = _TS_RE.search(line)
                if m:
                    try:
                        current["timestamp"] = datetime.fromisoformat(m.group(1).replace(" ", "T"))
                    except ValueError:
                        pass

                m = _EID_RE.search(line)
                if m:
                    current["event_id"] = int(m.group(1))

                m = _SRC_RE.search(line)
                if m and "source" not in current:
                    current["source"] = m.group(1)

                # Computer: takes priority over Source: (Source is the provider/channel name)
                m = _COMPUTER_RE.search(line)
                if m:
                    current["source"] = m.group(1)

            m = _DESC_RE.search(line)
            if m:
                current["description"] = current.get("description", "") + " " + m.group(1)
            elif "description" in current:
                current["description"] += " " + line

        if current.get("event_id") is not None:
            ts = current.get("timestamp")
            if since is None or ts is None or ts >= since:
                events.append(current)

    return events


def score_event(event):
    score = 0
    tags = []
    eid = event.get("event_id", 0)
    desc = (event.get("description") or "").lower()

    if eid == 4742:
        if any(kw in desc for kw in ("password last set", "password reset")) or _MACHINE_ACCOUNT_RE.search(desc):
            score += 3
            tags.append(RULE_4742_MACHINE_RESET)
        if "anonymous" in desc or "null" in desc:
            score += 2
            tags.append(RULE_ANONYMOUS_ACCESS)

    if eid == 5805:
        score += 3
        tags.append(RULE_5805_SECURE_CHANNEL)
        if "access denied" in desc or "failed" in desc:
            score += 1

    rpc_hits = sum(1 for kw in RPC_ANOMALY_KEYWORDS if kw in desc)
    if rpc_hits >= 2:
        score += rpc_hits
        tags.append(RULE_RPC_ANOMALY)

    if desc.count("password") > 2 or ("reset" in desc and desc.count("reset") > 1):
        score += 2
        tags.append(RULE_RAPID_RESET)

    return score, tags


def main():
    parser = argparse.ArgumentParser(
        description="Detect CVE-2026-41089 Netlogon RCE exploitation in plain-text Windows Security event logs."
    )
    parser.add_argument("--log-file", required=True, metavar="PATH",
                        help="Path to plain-text exported Windows Security event log")
    parser.add_argument("--threshold", type=int, default=3, metavar="N",
                        help="Minimum anomaly score to trigger an alert (default: 3)")
    parser.add_argument("--since", metavar="DATETIME",
                        help="ISO datetime to filter events from, e.g. 2026-06-01T00:00:00")
    args = parser.parse_args()

    if args.threshold < 1:
        print("[ERROR] --threshold must be at least 1", file=sys.stderr)
        sys.exit(1)

    since = None
    if args.since:
        try:
            since = datetime.fromisoformat(args.since)
        except ValueError:
            print(f"[ERROR] Invalid --since value {args.since!r}. Use ISO format: 2026-06-01T00:00:00",
                  file=sys.stderr)
            sys.exit(1)

    events = parse_events(args.log_file, since)
    alert_count = 0

    for event in events:
        score, tags = score_event(event)
        if score >= args.threshold:
            alert_count += 1
            ts = event.get("timestamp", "UNKNOWN")
            src = event.get("source", "UNKNOWN")
            eid = event.get("event_id", "?")
            print(f"[ALERT] ts={ts} event_id={eid} source={src} score={score} rules=[{','.join(tags)}]")

    print(f"[SUMMARY] scanned={len(events)} alerts={alert_count} threshold={args.threshold}")


if __name__ == "__main__":
    main()
