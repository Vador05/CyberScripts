"""
Woodgnat/Mistic Kill Chain Detector

Scans plain-text endpoint log exports for Woodgnat/Mistic campaign indicators.

Usage:
    python woodgnat_mistic_detector.py /var/log/endpoint_export.txt
    python woodgnat_mistic_detector.py /var/log/endpoint_export.txt --iocs feeds/daily.json --severity high
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Optional

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

BUNDLED_IOCS = {
    "domains": [
        r"update-cdn\.photos",
        r"img-delivery\.services",
        r"photo-share\.online",
        r"mistic-relay\.net",
        r"cdn-hotel\.pics",
    ],
    "ips": [
        r"185\.220\.101\.\d+",
        r"45\.142\.212\.\d+",
        r"194\.165\.16\.\d+",
        r"91\.92\.240\.\d+",
    ],
}

ANOMALOUS_NODE_PARENTS = [
    "explorer.exe", "winrar.exe", "7zfm.exe", "outlook.exe",
    "thunderbird.exe", "winzip32.exe", "chrome.exe", "firefox.exe",
    "msedge.exe", "iexplore.exe",
]

PHOTO_ARCHIVE_PATTERN = re.compile(
    r"(?i)(photo|image|img|pic|snapshot|gallery|receipt_img|room_photo)[\w\-]*\.(zip|rar|7z)",
)

LOG_ENTRY_RE = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[\w:.+-]*)"
    r".*?(?:process|proc|image|exe)[\s=:\"]*(?P<process>[\w.\-]+\.exe)"
    r"(?:.*?(?:parent|ppid|parentimage|parentproc)[\s=:\"]*(?P<parent>[\w.\-]+\.exe))?"
    r"(?:.*?(?:dst|dest|domain|host|url|connection|network)[\s=:\"]*(?P<network>[\w.\-:/]+))?",
    re.IGNORECASE,
)

TIMESTAMP_FALLBACK = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")


@dataclass
class Finding:
    timestamp: str
    stage: str
    severity: str
    pattern: str
    raw_line: str


@dataclass
class DetectorState:
    ioc_domains: list = field(default_factory=list)
    ioc_ips: list = field(default_factory=list)
    findings: list = field(default_factory=list)


def load_supplemental_iocs(path: str, state: DetectorState) -> None:
    with open(path) as f:
        data = json.load(f)
    state.ioc_domains.extend(data.get("domains", []))
    state.ioc_ips.extend(data.get("ips", []))


def parse_log_entries(log_path: str):
    with open(log_path, errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = LOG_ENTRY_RE.search(line)
            ts_m = TIMESTAMP_FALLBACK.search(line)
            timestamp = (m.group("timestamp") if m and m.group("timestamp")
                         else (ts_m.group(0) if ts_m else "UNKNOWN"))
            process = m.group("process").lower() if m and m.group("process") else ""
            parent = m.group("parent").lower() if m and m.group("parent") else ""
            network = m.group("network") if m and m.group("network") else ""
            yield {"timestamp": timestamp, "process": process, "parent": parent,
                   "network": network, "raw": line}


def match_patterns(entry: dict, state: DetectorState) -> list[Finding]:
    hits = []
    ts, raw = entry["timestamp"], entry["raw"]

    if PHOTO_ARCHIVE_PATTERN.search(raw):
        hits.append(Finding(ts, "Delivery", "medium",
                            f"Photo-themed archive filename: {PHOTO_ARCHIVE_PATTERN.search(raw).group(0)}", raw))

    if entry["process"] == "node.exe" and entry["parent"]:
        for bad_parent in ANOMALOUS_NODE_PARENTS:
            if bad_parent in entry["parent"]:
                hits.append(Finding(ts, "Execution", "high",
                                    f"node.exe spawned from anomalous parent: {entry['parent']}", raw))
                break

    net_val = entry["network"]
    if net_val:
        for pattern in state.ioc_domains:
            if re.search(pattern, net_val, re.IGNORECASE):
                hits.append(Finding(ts, "C2", "high",
                                    f"Mistic C2 domain match: {pattern}", raw))
                break
        for pattern in state.ioc_ips:
            if re.search(pattern, net_val):
                hits.append(Finding(ts, "C2", "high",
                                    f"Mistic C2 IP match: {pattern}", raw))
                break

    return hits


def report_findings(findings: list[Finding], min_severity: str) -> int:
    min_rank = SEVERITY_RANK[min_severity]
    emitted = [f for f in findings if SEVERITY_RANK[f.severity] >= min_rank]
    tally = {"Delivery": 0, "Execution": 0, "C2": 0}
    highest = "low"

    for f in emitted:
        print(f"[{f.timestamp}] [{f.stage.upper()}] [{f.severity.upper()}] {f.pattern}")
        print(f"  >> {f.raw_line[:200]}")
        tally[f.stage] = tally.get(f.stage, 0) + 1
        if SEVERITY_RANK[f.severity] > SEVERITY_RANK[highest]:
            highest = f.severity

    print("\n--- SUMMARY ---")
    for stage, count in tally.items():
        print(f"  {stage}: {count} alert(s)")
    print(f"  Highest severity observed: {highest.upper()}")
    print(f"  Total alerts emitted: {len(emitted)}")
    return len(emitted)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect Woodgnat/Mistic kill-chain stages in endpoint log exports.",
        epilog="Example: woodgnat_mistic_detector.py hotel_logs.txt --iocs daily_feed.json --severity medium",
    )
    parser.add_argument("log_file", help="Path to plain-text endpoint/SIEM log export")
    parser.add_argument("--iocs", metavar="JSON_FILE",
                        help="Supplemental JSON file with domains/ips lists to merge with bundled signatures")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum alert severity to emit (default: low)")
    args = parser.parse_args()

    state = DetectorState(
        ioc_domains=list(BUNDLED_IOCS["domains"]),
        ioc_ips=list(BUNDLED_IOCS["ips"]),
    )

    if args.iocs:
        try:
            load_supplemental_iocs(args.iocs, state)
        except (OSError, json.JSONDecodeError, KeyError) as e:
            print(f"[ERROR] Failed to load supplemental IOCs: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        findings: list[Finding] = []
        for entry in parse_log_entries(args.log_file):
            findings.extend(match_patterns(entry, state))
    except OSError as e:
        print(f"[ERROR] Cannot read log file: {e}", file=sys.stderr)
        sys.exit(1)

    count = report_findings(findings, args.severity)
    sys.exit(0 if count == 0 else 1)


if __name__ == "__main__":
    main()