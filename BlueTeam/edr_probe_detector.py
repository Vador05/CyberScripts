#!/usr/bin/env python3
"""
EDR Probe Detector - Analyzes security logs for automated EDR evasion probing patterns.

Usage:
    python edr_probe_detector.py /var/log/edr.log
    python edr_probe_detector.py /var/log/edr.log --threshold 5 --format yara
    python edr_probe_detector.py /var/log/edr.log --format sigma

Output: Sigma or YARA rule printed to stdout with matched pattern summary.
"""

import argparse
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime


TIMESTAMP_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r".*?(?P<proc>[A-Za-z0-9_\-\.]+\.(?:exe|dll|sys|ps1|sh|py))"
    r".*?(?P<action>[A-Z][A-Z_]{2,}(?:Query|Enum|Open|Read|Write|Create|Delete|List|Scan|Hook|Inject|Load))"
)

EVASION_KEYWORDS = {
    "NtQuerySystemInformation", "EnumProcesses", "CreateRemoteThread",
    "VirtualAllocEx", "WriteProcessMemory", "SetWindowsHookEx", "LoadLibrary",
    "OpenProcess", "ReadProcessMemory", "NtOpenProcess", "DeviceIoControl",
    "RegOpenKey", "RegQueryValue", "RegEnumKey",
}

BURST_WINDOW_SECONDS = 5
MIN_BURST_COUNT = 3


def parse_log_events(path):
    events = []
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                m = TIMESTAMP_RE.search(line)
                if not m:
                    continue
                try:
                    ts_str = m.group("ts").replace("T", " ")
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    continue
                events.append({
                    "ts": ts,
                    "proc": m.group("proc").lower(),
                    "action": m.group("action"),
                })
    except OSError as exc:
        print(f"[ERROR] Cannot read log file: {exc}", file=sys.stderr)
        sys.exit(1)
    return events


def detect_probe_patterns(events, threshold):
    action_counts = Counter(e["action"] for e in events)
    proc_counts = Counter(e["proc"] for e in events)

    evasion_hits = {a: c for a, c in action_counts.items() if a in EVASION_KEYWORDS and c >= threshold}

    burst_procs = set()
    proc_times = defaultdict(list)
    for e in events:
        proc_times[e["proc"]].append(e["ts"])
    for proc, times in proc_times.items():
        times.sort()
        for i in range(len(times) - MIN_BURST_COUNT + 1):
            delta = (times[i + MIN_BURST_COUNT - 1] - times[i]).total_seconds()
            if delta <= BURST_WINDOW_SECONDS:
                burst_procs.add(proc)
                break

    enum_chains = defaultdict(set)
    for e in events:
        if "Enum" in e["action"] or "Query" in e["action"] or "List" in e["action"]:
            enum_chains[e["proc"]].add(e["action"])
    deep_enumerators = {p: acts for p, acts in enum_chains.items() if len(acts) >= 3}

    flagged_procs = {
        p for p in proc_counts if proc_counts[p] >= threshold
    } | burst_procs | set(deep_enumerators)

    return {
        "evasion_hits": evasion_hits,
        "burst_procs": burst_procs,
        "deep_enumerators": deep_enumerators,
        "flagged_procs": flagged_procs,
        "total_events": len(events),
        "action_counts": action_counts,
    }


def emit_sigma(findings, threshold):
    actions = list(findings["evasion_hits"].keys()) or [a for a, _ in findings["action_counts"].most_common(5)]
    procs = sorted(findings["flagged_procs"])[:8]
    action_conditions = "\n            - ".join(f"'{a}'" for a in actions)

    if procs:
        proc_conditions = "\n            - ".join(f"'*{p}*'" for p in procs)
        process_block = f"""    flagged_processes:
        EventData.Image|contains:
            - {proc_conditions}
"""
        condition = "evasion_actions and flagged_processes"
    else:
        process_block = ""
        condition = "evasion_actions"

    return f"""title: Automated EDR Evasion Probe Detected
id: edr-probe-auto-generated
status: experimental
description: >
    Detects automated EDR evasion reconnaissance patterns: burst API enumeration,
    systematic process inspection, and evasion API repetition above threshold {threshold}.
    Review before deploying to production SIEM. Output may contain sensitive hostnames.
author: edr_probe_detector (heuristic)
date: {datetime.now().strftime('%Y/%m/%d')}
logsource:
    product: windows
    category: process_creation
detection:
    evasion_actions:
        EventData.Action|contains:
            - {action_conditions}
{process_block}    condition: {condition}
falsepositives:
    - Legitimate security software and AV engines
    - System management tools performing scheduled inventory
level: high
tags:
    - attack.discovery
    - attack.defense_evasion
"""


def emit_yara(findings, threshold):
    actions = list(findings["evasion_hits"].keys()) or [a for a, _ in findings["action_counts"].most_common(5)]
    procs = sorted(findings["flagged_procs"])[:8]
    str_defs = "\n        ".join(f'$a{i} = "{a}" nocase' for i, a in enumerate(actions))
    a_cond = " or ".join(f"$a{i}" for i in range(len(actions)))

    if procs:
        proc_defs = "\n        ".join(f'$p{i} = "{p}" nocase' for i, p in enumerate(procs))
        p_cond = " or ".join(f"$p{i}" for i in range(len(procs)))
        strings_section = f"        {str_defs}\n        {proc_defs}"
        condition = f"({a_cond}) and ({p_cond})"
    else:
        strings_section = f"        {str_defs}"
        condition = f"({a_cond})"

    return f"""rule EDR_Probe_Detector_AutoGen {{
    meta:
        description = "Automated EDR evasion probe pattern (threshold={threshold})"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        author = "edr_probe_detector (heuristic)"
        severity = "high"
        review_required = "true"
    strings:
{strings_section}
    condition:
        {condition}
}}
"""


def main():
    parser = argparse.ArgumentParser(
        description="Detect automated EDR evasion probing patterns in plain text logs."
    )
    parser.add_argument("logfile", help="Path to plain text log file")
    parser.add_argument("--threshold", type=int, default=10,
                        help="Minimum event frequency to flag as automated (default: 10)")
    parser.add_argument("--format", choices=["sigma", "yara"], default="sigma",
                        help="Output rule format (default: sigma)")
    args = parser.parse_args()

    if args.threshold < 1:
        print("[ERROR] --threshold must be >= 1", file=sys.stderr)
        sys.exit(1)

    events = parse_log_events(args.logfile)
    if not events:
        print("[WARN] No parseable events found in log file.", file=sys.stderr)
        sys.exit(0)

    findings = detect_probe_patterns(events, args.threshold)

    print(f"# Matched {findings['total_events']} events | "
          f"Evasion APIs: {len(findings['evasion_hits'])} | "
          f"Burst procs: {len(findings['burst_procs'])} | "
          f"Deep enumerators: {len(findings['deep_enumerators'])}\n")

    if not findings["flagged_procs"] and not findings["evasion_hits"]:
        print(f"# No patterns exceeded threshold={args.threshold}. No rule emitted.")
        sys.exit(0)

    rule = emit_sigma(findings, args.threshold) if args.format == "sigma" else emit_yara(findings, args.threshold)
    print(rule)


if __name__ == "__main__":
    main()
