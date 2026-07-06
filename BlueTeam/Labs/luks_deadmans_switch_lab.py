#!/usr/bin/env python3
"""
LUKS Dead Man's Switch Lab - Replays syslog events to audit dead man's switch trigger coverage.

Usage:
    python luks_deadmans_switch_lab.py /var/log/syslog --window 300 --severity low
    python luks_deadmans_switch_lab.py auth.log --window 60 --severity high
"""

import argparse
import re
import sys
from datetime import datetime, timezone

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

TS_PATTERNS = [
    (r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", "%Y-%m-%dT%H:%M:%S"),
    (r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", "%Y-%m-%d %H:%M:%S"),
    (r"([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})", "%b %d %H:%M:%S"),
]

EVENT_PATTERNS = [
    ("usb_connect",    re.compile(r"(usb.*new.*device|udevd.*add.*usb|usb.*connect(?:ed)?)", re.I)),
    ("usb_disconnect", re.compile(r"(usb.*disconnect|udevd.*remove.*usb|usb.*removed)", re.I)),
    ("luks_unlock",    re.compile(r"(cryptsetup.*open|device.mapper.*create|luks.*unlock)", re.I)),
    ("luks_lock",      re.compile(r"(cryptsetup.*close|device.mapper.*remove|luks.*lock)", re.I)),
    ("timer_heartbeat",re.compile(r"(systemd.*timer.*trigger|dead.man.*switch|heartbeat.*usb)", re.I)),
]

MITIGATIONS = {
    "USBAbsence":   "Add udev rule: ACTION==\"remove\", SUBSYSTEM==\"usb\", RUN+=\"/usr/bin/cryptsetup close <vol>\"",
    "TimerExpiry":  "Set systemd OnUnitActiveSec= below --window value and bind unit to cryptsetup close",
    "LUKSUnlocked": "Enforce auto-lock on USB remove; audit /etc/udev/rules.d/ for missing lock triggers",
    "MissedLockout":"Mandate re-authentication after USB absence; consider kernel keyring eviction on unplug",
}


def parse_timestamp(line):
    now = datetime.now(timezone.utc)
    current_year = now.year

    for pattern, fmt in TS_PATTERNS:
        m = re.search(pattern, line)
        if not m:
            continue
        try:
            ts_str = m.group(1)

            if "%Y" in fmt:
                dt = datetime.strptime(ts_str, fmt)
            else:
                year = current_year
                dt = datetime.strptime(f"{year} {ts_str}", f"%Y {fmt}")
                dt_utc = dt.replace(tzinfo=timezone.utc)
                while dt_utc > now and year > current_year - 10:
                    year -= 1
                    dt = datetime.strptime(f"{year} {ts_str}", f"%Y {fmt}")
                    dt_utc = dt.replace(tzinfo=timezone.utc)

            return dt.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def parse_events(log_file):
    events = []
    try:
        with open(log_file, "r", errors="replace") as fh:
            for line in fh:
                line = line.rstrip()
                ts = parse_timestamp(line)
                if ts is None:
                    continue
                for etype, pattern in EVENT_PATTERNS:
                    if pattern.search(line):
                        events.append({"ts": ts, "type": etype, "raw": line[:120]})
                        break
    except OSError as exc:
        print(f"ERROR: Cannot read log file: {exc}", file=sys.stderr)
        sys.exit(2)
    return sorted(events, key=lambda e: e["ts"])


def fmt_duration(secs):
    secs = int(secs)
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m{secs % 60}s"
    return f"{secs // 3600}h{(secs % 3600) // 60}m"


def fmt_ts(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def evaluate_triggers(events, window):
    findings = []
    usb_present, usb_removed_at, luks_unlocked, last_heartbeat = True, None, False, None

    for ev in events:
        t, etype, raw = ev["ts"], ev["type"], ev["raw"]

        if etype == "usb_connect":
            if usb_removed_at is not None and luks_unlocked:
                gap = t - usb_removed_at
                if gap > window:
                    findings.append({"sev": "high" if gap > window * 2 else "medium",
                                     "ts": usb_removed_at, "cls": "MissedLockout", "raw": raw, "dur": gap})
            usb_present, usb_removed_at = True, None

        elif etype == "usb_disconnect":
            usb_present, usb_removed_at = False, t
            if luks_unlocked:
                findings.append({"sev": "medium", "ts": t, "cls": "USBAbsence", "raw": raw, "dur": 0})

        elif etype == "luks_unlock":
            luks_unlocked = True
            if not usb_present and usb_removed_at is not None:
                gap = t - usb_removed_at
                findings.append({"sev": "high" if gap > window else "medium",
                                 "ts": t, "cls": "LUKSUnlocked", "raw": raw, "dur": gap})

        elif etype == "luks_lock":
            luks_unlocked = False

        elif etype == "timer_heartbeat":
            if last_heartbeat is not None:
                gap = t - last_heartbeat
                if gap > window:
                    findings.append({"sev": "high" if gap > window * 3 else "low",
                                     "ts": last_heartbeat, "cls": "TimerExpiry", "raw": raw, "dur": gap})
            last_heartbeat = t

    if usb_removed_at is not None and luks_unlocked and events:
        gap = events[-1]["ts"] - usb_removed_at
        if gap > window:
            findings.append({"sev": "high", "ts": usb_removed_at, "cls": "MissedLockout",
                              "raw": events[-1]["raw"], "dur": gap})
    return findings


def report_findings(findings, min_sev):
    min_rank = SEVERITY_ORDER[min_sev]
    counts, longest, peak_rank = {}, 0, -1

    for f in findings:
        if SEVERITY_ORDER[f["sev"]] < min_rank:
            continue
        counts[f["cls"]] = counts.get(f["cls"], 0) + 1
        longest = max(longest, f["dur"])
        peak_rank = max(peak_rank, SEVERITY_ORDER[f["sev"]])
        print(f"[{f['sev'].upper():6}] {fmt_ts(f['ts'])} | {f['cls']} | {f['raw'][:80]}")
        print(f"         MITIGATE: {MITIGATIONS.get(f['cls'], 'Review LUKS and udev configuration')}")

    print("\n--- Summary ---")
    if not counts:
        print("No findings above specified severity threshold.")
    else:
        for cls, cnt in sorted(counts.items()):
            print(f"  {cls}: {cnt} finding(s)")
        print(f"  Longest unprotected window: {fmt_duration(longest)}")
        peak_name = next(k for k, v in SEVERITY_ORDER.items() if v == peak_rank)
        print(f"  Peak severity: {peak_name.upper()}")

    if peak_rank >= SEVERITY_ORDER["high"]:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="LUKS Dead Man's Switch Lab: replay syslog events to audit auto-lock coverage.",
        epilog="Example: python luks_deadmans_switch_lab.py /var/log/syslog --window 300 --severity low",
    )
    parser.add_argument("log_file", help="Path to plain-text syslog or journald export")
    parser.add_argument("--window", type=int, default=300, help="USB absence tolerance in seconds (default: 300)")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum alert level to emit (default: low)")
    args = parser.parse_args()

    if args.window <= 0:
        print("ERROR: --window must be a positive integer", file=sys.stderr)
        sys.exit(2)

    events = parse_events(args.log_file)
    if not events:
        print("No matching events found in log file. Verify log format or regex patterns.", file=sys.stderr)
        sys.exit(0)

    findings = evaluate_triggers(events, args.window)
    report_findings(findings, args.severity)


if __name__ == "__main__":
    main()