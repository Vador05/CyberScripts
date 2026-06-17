"""
WinRE XML BitLocker Bypass Detector — simulates GreatXML-style bypass sequences
and scans plain-text Windows logs for anomalous ReAgent.xml / BCD access patterns.

Usage:
    python winre_xml_detector.py simulate
    python winre_xml_detector.py detect --log C:\\logs\\system.log --rule sigma
    python winre_xml_detector.py detect --log /tmp/winevt.txt --rule elastic
"""

import argparse
import re
import sys
from datetime import datetime, timedelta, timezone

PATTERNS = {
    "ReAgent.xml access": re.compile(
        r"ReAgent\.xml", re.IGNORECASE
    ),
    "Unexpected WinRE BCD mount": re.compile(
        r"(\\BCD|bcdedit|winre\.wim|reagent\.xml).*"
        r"(mount|attach|write|modify|set|open)",
        re.IGNORECASE,
    ),
    "reagentc.exe invocation": re.compile(
        r"reagentc(\.exe)?\s", re.IGNORECASE
    ),
    "WinRE partition access": re.compile(
        r"(Recovery|WinRE|WindowsRE)\\.*\.(xml|wim|bcd)",
        re.IGNORECASE,
    ),
}

SIMULATE_SEQUENCE = [
    ("INFO", "Process started", "reagentc.exe /disable"),
    ("INFO", "File accessed", r"C:\Windows\System32\Recovery\ReAgent.xml"),
    ("WARN", "File modified", r"C:\Windows\System32\Recovery\ReAgent.xml"),
    ("INFO", "BCD store opened", r"\\?\GLOBALROOT\Device\HarddiskVolume1\EFI\Microsoft\Boot\BCD"),
    ("INFO", "WinRE partition mounted", r"\\?\GLOBALROOT\Device\HarddiskVolume4\Recovery\WindowsRE\winre.wim"),
    ("WARN", "reagentc.exe invoked", "reagentc.exe /setreimage /path R:\\Recovery\\WindowsRE"),
    ("CRIT", "ReAgent.xml overwritten", r"C:\Windows\System32\Recovery\ReAgent.xml"),
    ("INFO", "BCD entry modified", "bcdedit /set {bootmgr} path \\EFI\\Microsoft\\Boot\\bootmgfw.efi"),
    ("WARN", "reagentc.exe invoked", "reagentc.exe /enable"),
    ("CRIT", "Bypass complete", "WinRE recovery environment redirected; BitLocker key exposure risk"),
]


def simulate_attack():
    ts_base = datetime.now(timezone.utc)
    print("=== GreatXML WinRE BitLocker Bypass Simulation ===")
    for i, (level, action, detail) in enumerate(SIMULATE_SEQUENCE):
        ts = (ts_base + timedelta(seconds=i * 3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"[{ts}] [{level:4}] {action}: {detail}")
    print("=== End of simulation sequence ===")


def detect_anomalies(log_path):
    findings = []
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        print(f"[ERROR] Cannot read log file: {exc}", file=sys.stderr)
        sys.exit(1)

    for lineno, line in enumerate(lines, start=1):
        for label, pattern in PATTERNS.items():
            if pattern.search(line):
                findings.append((lineno, label, line.rstrip()))
                break

    return findings


def emit_sigma_rule():
    ts = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    print(f"""title: Anomalous WinRE ReAgent.xml Access (GreatXML BitLocker Bypass)
id: d4f7a1c2-88b3-4e6f-9c0d-1a2b3c4d5e6f
status: experimental
description: Detects suspicious access to ReAgent.xml and WinRE BCD components
  indicative of the GreatXML BitLocker recovery partition bypass technique.
references:
  - https://attack.mitre.org/techniques/T1542/001/
author: winre_xml_detector
date: {ts}
tags:
  - attack.defense_evasion
  - attack.t1542.001
logsource:
  product: windows
  category: file_event
detection:
  selection_reagent:
    TargetFilename|contains:
      - 'ReAgent.xml'
      - '\\Recovery\\WindowsRE\\'
  selection_bcd:
    TargetFilename|contains:
      - '\\EFI\\Microsoft\\Boot\\BCD'
      - 'winre.wim'
  selection_process:
    Image|endswith: '\\reagentc.exe'
    CommandLine|contains:
      - '/disable'
      - '/setreimage'
      - '/enable'
  condition: selection_reagent or selection_bcd or selection_process
falsepositives:
  - Legitimate Windows Update or WinRE maintenance operations
  - Scheduled recovery environment reconfiguration
level: high""")


def emit_elastic_rule():
    print("""// Elastic EQL — WinRE XML BitLocker Bypass (GreatXML / T1542.001)
sequence by host.id with maxspan=5m
  [file where
    file.path like~ "*ReAgent.xml*" or
    file.path like~ "*\\\\Recovery\\\\WindowsRE\\\\*" or
    file.path like~ "*\\\\EFI\\\\Microsoft\\\\Boot\\\\BCD*"
  ]
  [process where
    process.name like~ "reagentc.exe" and
    (process.command_line like~ "*/disable*" or
     process.command_line like~ "*/setreimage*")
  ]
  [file where
    file.path like~ "*ReAgent.xml*" and
    event.action in ("modification", "overwrite", "creation")
  ]
// False positives: scheduled WinRE maintenance, Windows Update servicing stacks
// MITRE: T1542.001 | severity: high""")


_LOG_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")


def main():
    parser = argparse.ArgumentParser(
        description="WinRE XML BitLocker Bypass Detector",
        epilog="Example: %(prog)s detect --log system.log --rule sigma",
    )
    parser.add_argument("mode", choices=["simulate", "detect"])
    parser.add_argument("--log", help="Path to plain-text Windows log file (detect mode)")
    parser.add_argument("--rule", choices=["sigma", "elastic"], default="sigma")
    args = parser.parse_args()

    if args.mode == "simulate":
        simulate_attack()
        return

    if not args.log:
        parser.error("--log is required in detect mode")

    findings = detect_anomalies(args.log)
    if findings:
        print(f"[*] {len(findings)} suspicious line(s) found in {args.log}\n")
        for lineno, label, line in findings:
            m = _LOG_TS_RE.search(line)
            ts_field = f" ts={m.group()}" if m else ""
            print(f"[ALERT] line={lineno}{ts_field} pattern=\"{label}\"")
            print(f"        {line}\n")
    else:
        print("[*] No anomalous WinRE access patterns detected.")

    print("\n" + "=" * 60)
    print(f"Detection rule ({args.rule}):\n")
    if args.rule == "sigma":
        emit_sigma_rule()
    else:
        emit_elastic_rule()


if __name__ == "__main__":
    main()