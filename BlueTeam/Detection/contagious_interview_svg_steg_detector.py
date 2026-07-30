"""
contagious_interview_svg_steg_detector.py - Scans endpoint logs or SVG files for Contagious Interview kill-chain TTPs.

Usage:
    python contagious_interview_svg_steg_detector.py artifact.svg
    python contagious_interview_svg_steg_detector.py endpoint.log --iocs extra.json --severity high
    python contagious_interview_svg_steg_detector.py process.csv --severity medium

Exit code 1 on any high-severity match.
"""

import argparse
import json
import re
import sys
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone

RULES = {
    "Staging": [
        {"name": "svg_script_element", "severity": "high", "technique": "T1027.012",
         "pattern": r"(?i)<script[\s>]", "fields": ["line"]},
        {"name": "base64_blob_attribute", "severity": "high", "technique": "T1027.012",
         "pattern": r'(?i)(?:href|src|data|xlink:href)\s*=\s*["\']?[A-Za-z0-9+/=]{256,}', "fields": ["line"]},
        {"name": "foreignobject_embed", "severity": "medium", "technique": "T1027.012",
         "pattern": r"(?i)<(?:foreignObject|image|use)\b[^>]*(?:href|xlink:href)\s*=", "fields": ["line"]},
        {"name": "npm_typosquat_fetch", "severity": "high", "technique": "T1195.002",
         "pattern": r"(?i)(?:npm install|registry\.npmjs\.org)[/ ](?:beavertail|nodestealer|node-fetch-helper|browser-credential|cross-env-extra|nodemailer-core)", "fields": ["line"]},
    ],
    "Execution": [
        {"name": "js_atob_eval_chain", "severity": "high", "technique": "T1059.007",
         "pattern": r"(?i)(?:eval|new\s+Function)\s*\(\s*(?:atob|Buffer\.from)\s*\(", "fields": ["line"]},
        {"name": "node_spawns_shell", "severity": "high", "technique": "T1059.007",
         "pattern": r"(?i)(?:node|npm)(?:\.exe)?\s.+?(?:cmd|powershell|wscript|sh|bash)(?:\.exe)?", "fields": ["line", "cmdline"]},
        {"name": "appdata_temp_node_exec", "severity": "high", "technique": "T1059.007",
         "pattern": r"(?i)(?:AppData|/tmp|\\Temp)[/\\].+?(?:node|npm)(?:\.exe)?", "fields": ["line", "cmdline"]},
    ],
    "Collection": [
        {"name": "browser_profile_traversal", "severity": "high", "technique": "T1555.003",
         "pattern": r"(?i)(?:Chrome|Firefox|Brave|Edge)[/\\](?:User Data|Profiles?)[/\\].+?(?:Login Data|Cookies|Web Data)", "fields": ["line", "cmdline"]},
        {"name": "keychain_dpapi_access", "severity": "high", "technique": "T1555.003",
         "pattern": r"(?i)(?:CryptUnprotectData|dpapi|login\.keychain(?:-db)?|security\s+find-.+-password)", "fields": ["line", "cmdline"]},
        {"name": "clipboard_read_node", "severity": "high", "technique": "T1056.001",
         "pattern": r"(?i)(?:clipboardy|node-clipboard|readText\(\)|xclip\s+-o|pbpaste)", "fields": ["line", "cmdline"]},
    ],
    "C2": [
        {"name": "invisibleferret_dyndns_c2", "severity": "high", "technique": "T1071.001",
         "pattern": r"(?i)python(?:3|\.exe)?\s.+?(?:ddns\.net|no-ip\.(?:com|org)|hopto\.org|duckdns\.org|pastebin\.com|rentry\.co)", "fields": ["line", "cmdline"]},
        {"name": "python_b64_arg", "severity": "medium", "technique": "T1071.001",
         "pattern": r"(?i)python(?:3|\.exe)?\s+-c\s+['\"]?[A-Za-z0-9+/]{32,}={0,2}", "fields": ["line", "cmdline"]},
        {"name": "scheduled_task_python", "severity": "high", "technique": "T1053.005",
         "pattern": r"(?i)(?:schtasks|launchctl|crontab)\b.+?(?:python|\.py)\b", "fields": ["line", "cmdline"]},
        {"name": "plist_python_relaunch", "severity": "medium", "technique": "T1053.005",
         "pattern": r"(?i)<string>(?:/usr/bin/)?python3?\b[^<]+\.py</string>", "fields": ["line"]},
    ],
}

SEV_ORDER = {"low": 0, "medium": 1, "high": 2}


def load_iocs(path):
    with open(path) as f:
        extra = json.load(f)
    for stage, additions in extra.items():
        validated = []
        for rule in additions:
            missing = [f for f in ("pattern", "technique", "name", "severity") if f not in rule]
            if missing:
                raise ValueError(
                    f"Rule missing required fields {missing}: {rule}"
                )
            try:
                re.compile(rule["pattern"])
            except re.error as e:
                raise ValueError(
                    f"Invalid regex pattern in rule '{rule['name']}': {e}"
                )
            validated.append(rule)
        RULES.setdefault(stage, []).extend(validated)


def parse_line(raw):
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    entry = {"line": line}
    m = re.match(r'^([^,]+),([^,]*),([^,]*),([^,]*)(?:,(.*))?$', line)
    if m:
        for k, v in zip(["timestamp", "parent_image", "image", "cmdline", "workdir"], m.groups()):
            if v:
                entry[k] = urllib.parse.unquote(v)
    return entry


def match_rules(entry, min_sev):
    hits = []
    for stage, rules in RULES.items():
        for rule in rules:
            if SEV_ORDER.get(rule.get("severity", "low"), 0) < SEV_ORDER[min_sev]:
                continue
            for field in rule.get("fields", ["line"]):
                text = entry.get(field, "")
                if text and re.search(rule["pattern"], text):
                    hits.append((stage, rule["technique"], rule["severity"], rule["name"], entry["line"]))
                    break
    return hits


def main():
    ap = argparse.ArgumentParser(description="Detect Contagious Interview SVG steganography kill-chain indicators.")
    ap.add_argument("log_file", help="Endpoint log export or SVG artifact to analyze")
    ap.add_argument("--iocs", help="JSON file with supplemental Contagious Interview signatures")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum alert level to emit (default: low)")
    args = ap.parse_args()

    if args.iocs:
        try:
            load_iocs(args.iocs)
        except (OSError, json.JSONDecodeError, ValueError) as e:
            print(f"[ERROR] --iocs: {e}", file=sys.stderr)
            sys.exit(2)

    try:
        fh = open(args.log_file, encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(2)

    stage_counts = defaultdict(int)
    technique_hits = set()
    process_ids = set()
    peak_sev = 0
    dedup = {}

    with fh:
        for raw in fh:
            entry = parse_line(raw)
            if not entry:
                continue
            if entry.get("image"):
                process_ids.add(entry["image"])
            for stage, technique, severity, name, source in match_rules(entry, args.severity):
                key = (name, entry.get("image", ""), entry.get("cmdline", "")[:64])
                ts = datetime.now(timezone.utc)
                if key in dedup and (ts - dedup[key]).total_seconds() < 60:
                    continue
                dedup[key] = ts
                stage_counts[stage] += 1
                technique_hits.add(technique)
                peak_sev = max(peak_sev, SEV_ORDER[severity])
                print(f"[{ts.strftime('%Y-%m-%dT%H:%M:%SZ')}] [{stage}] [{technique}] [{severity.upper()}] {name} | {source[:200]}")

    peak_label = ["low", "medium", "high"][peak_sev] if any(stage_counts.values()) else "none"
    print("\n--- Summary ---")
    for stage, count in stage_counts.items():
        print(f"  {stage}: {count} hit(s)")
    print(f"  ATT&CK techniques: {', '.join(sorted(technique_hits)) or 'none'}")
    print(f"  Unique processes/artifacts: {len(process_ids)}")
    print(f"  Peak severity: {peak_label}")
    sys.exit(1 if peak_sev == 2 else 0)


if __name__ == "__main__":
    main()