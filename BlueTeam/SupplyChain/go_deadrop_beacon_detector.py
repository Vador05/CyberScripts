"""
go_deadrop_beacon_detector.py - Scans Go module manifests and source exports for GitHub dead drop beaconing patterns.

Usage:
    python go_deadrop_beacon_detector.py go.mod
    python go_deadrop_beacon_detector.py go.sum --iocs extra_iocs.json --severity high
    python go_deadrop_beacon_detector.py main.go --severity medium

Exit code 1 if any high-severity finding is detected.
"""

import argparse
import json
import re
import sys
import urllib.parse
from collections import defaultdict

RULES = {
    "ModuleImport": [
        {"name": "pseudo_version_pin", "severity": "high", "technique": "T1195.001",
         "pattern": r"v0\.0\.0-\d{14}-[0-9a-f]{12}"},
        {"name": "replace_to_github_fork", "severity": "medium", "technique": "T1195.001",
         "pattern": r"^\s*replace\s+\S+\s+=>\s+github\.com/"},
        {"name": "randomized_repo_name", "severity": "medium", "technique": "T1195.001",
         "pattern": r"github\.com/[a-z0-9]{8,}/[a-z0-9]{8,}(\s|$|/)"},
        {"name": "typosquat_go_pkg", "severity": "high", "technique": "T1195.001",
         "pattern": r"github\.com/[^/\s]+/(?:g0lang|go1ang|golang-[a-z]{3,8}|go[_-]utils[_-][a-z]{4,})"},
    ],
    "DeadDropFetch": [
        {"name": "raw_github_payload_ext", "severity": "high", "technique": "T1102.001",
         "pattern": r"raw\.githubusercontent\.com/[^/\s]+/[^/\s]+/[^\s]+\.(ps1|bat|cmd|bin)"},
        {"name": "gist_dead_drop", "severity": "high", "technique": "T1102.001",
         "pattern": r"gist\.github\.com/[a-zA-Z0-9_-]+/[a-f0-9]{20,}"},
        {"name": "api_github_gist", "severity": "high", "technique": "T1102.001",
         "pattern": r"api\.github\.com/gists/[a-f0-9]{20,}"},
        {"name": "raw_github_config_fetch", "severity": "medium", "technique": "T1102.001",
         "pattern": r"raw\.githubusercontent\.com/[^/\s]+/[^/\s]+/[^\s]+\.(json|txt|conf|cfg)"},
    ],
    "PSPayloadExec": [
        {"name": "iex_downloadstring", "severity": "high", "technique": "T1059.001",
         "pattern": r"(IEX|Invoke-Expression).*DownloadString"},
        {"name": "encoded_command_payload", "severity": "high", "technique": "T1059.001",
         "pattern": r"(-EncodedCommand|-enc\s+)[A-Za-z0-9+/=]{20,}"},
        {"name": "exec_command_powershell", "severity": "high", "technique": "T1059.001",
         "pattern": r'exec\.Command\s*\(\s*["\']powershell'},
        {"name": "downloadstring_http", "severity": "high", "technique": "T1059.001",
         "pattern": r'\.DownloadString\s*\(["\']https?://'},
    ],
}

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


def load_iocs(path):
    with open(path) as f:
        data = json.load(f)
    for phase, entries in data.get("rules", {}).items():
        if phase in RULES:
            RULES[phase].extend(entries)


def parse_module_entries(path):
    entries = []
    with open(path, errors="replace") as f:
        for lineno, raw in enumerate(f, 1):
            line = urllib.parse.unquote(raw.rstrip())
            entries.append({"line": line, "lineno": lineno})
    return entries


def match_rules(entries, min_severity):
    findings, seen = [], set()
    for entry in entries:
        text = entry["line"]
        for phase, rules in RULES.items():
            for rule in rules:
                if SEVERITY_RANK.get(rule["severity"], 0) < SEVERITY_RANK[min_severity]:
                    continue
                m = re.search(rule["pattern"], text, re.IGNORECASE)
                if not m:
                    continue
                matched = m.group(0)
                key = (phase, rule["name"], matched[:60])
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "phase": phase,
                    "technique": rule["technique"],
                    "severity": rule["severity"],
                    "name": rule["name"],
                    "matched": matched,
                    "lineno": entry["lineno"],
                })
    return findings


def report_findings(findings, min_severity):
    phase_counts, techniques, peak = defaultdict(int), set(), "low"
    for f in findings:
        if SEVERITY_RANK[f["severity"]] < SEVERITY_RANK[min_severity]:
            continue
        print(
            f"[{f['phase']}] [{f['technique']}] [{f['severity'].upper()}] "
            f"{f['name']} | {f['matched']!r} | line {f['lineno']}"
        )
        phase_counts[f["phase"]] += 1
        techniques.add(f["technique"])
        if SEVERITY_RANK[f["severity"]] > SEVERITY_RANK[peak]:
            peak = f["severity"]
    print("\n--- Summary ---")
    for phase, count in sorted(phase_counts.items()):
        print(f"  {phase}: {count} hit(s)")
    print(f"  ATT&CK techniques: {', '.join(sorted(techniques)) or 'none'}")
    print(f"  Peak severity: {peak.upper()}")
    return peak == "high"


def main():
    ap = argparse.ArgumentParser(
        description="Detect Go dead drop beacon and PowerShell payload patterns in Go module manifests and source exports."
    )
    ap.add_argument("module_file", help="Path to go.mod, go.sum, or exported Go source file")
    ap.add_argument("--iocs", help="Supplemental IOC JSON file with additional rules")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum severity to report (default: low)")
    args = ap.parse_args()

    if args.iocs:
        try:
            load_iocs(args.iocs)
        except (OSError, json.JSONDecodeError, KeyError) as e:
            print(f"Error loading IOCs: {e}", file=sys.stderr)
            sys.exit(2)

    try:
        entries = parse_module_entries(args.module_file)
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(2)

    findings = match_rules(entries, args.severity)
    has_high = report_findings(findings, args.severity)
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()