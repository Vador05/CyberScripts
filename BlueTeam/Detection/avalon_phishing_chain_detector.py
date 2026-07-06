"""
Avalon Multi-Stage Phishing Chain & Lateral Movement Detector

Scans proxy, SMTP gateway, or endpoint log exports for Avalon intrusion TTPs
across three kill-chain stages with MITRE ATT&CK technique labeling.

Usage:
    python avalon_phishing_chain_detector.py access.log
    python avalon_phishing_chain_detector.py smtp.log --iocs extra_iocs.json --severity high
    python avalon_phishing_chain_detector.py proxy.log --severity medium

Exit codes:
    0 - no high-severity findings
    1 - one or more high-severity findings detected
"""

import argparse
import json
import re
import sys
import time
import urllib.parse
from collections import defaultdict


BUILTIN_IOCS = {
    "phishing_domains": [
        r"secure-docs?\.(ru|cn|tk|ml|ga|cf)",
        r"office365-verify\.",
        r"sharepoint-secure\.",
        r"docusign-verify\.",
        r"avalon-drop\d*\.",
        r"mail-secure-\w+\.",
    ],
    "c2_ips": [
        r"185\.220\.\d+\.\d+",
        r"194\.165\.\d+\.\d+",
        r"45\.142\.\d+\.\d+",
    ],
    "staging_uri_patterns": [
        r"/templates?/[a-z0-9]{8,}/.*\.(doc[xm]?|xls[xm]?|ppt[xm]?)$",
        r"/attach/[a-f0-9]{32}/",
        r"/(invoice|payment|order|report)-\d{4,}\.(doc[xm]?|pdf\.exe)$",
        r"/tmpl/inject/",
    ],
    "c2_uri_patterns": [
        r"/(update|sync|check|ping|poll)/[a-z]{4,8}/[a-f0-9]{8,16}",
        r"/(gate|panel|index)\.php\?[a-z]{1,4}=[a-f0-9]+",
        r"/[a-z]{6}/\d{1,3}/[a-f0-9]{16}",
    ],
    "phishing_senders": [
        r"no-?reply@.*\.(ru|cn|tk|ml|ga|cf)$",
        r"admin@(?!yourdomain).*\d{4,}\.",
        r"support@secure-docs?\.",
    ],
}

RULES = [
    {
        "stage": "PhishingDelivery",
        "technique": "T1566/T1204",
        "name": "PhishingDocumentStaging",
        "severity": "high",
        "field": "uri",
        "patterns": BUILTIN_IOCS["staging_uri_patterns"],
    },
    {
        "stage": "PhishingDelivery",
        "technique": "T1566",
        "name": "PhishingSenderDomain",
        "severity": "high",
        "field": "sender",
        "patterns": BUILTIN_IOCS["phishing_domains"],
    },
    {
        "stage": "PhishingDelivery",
        "technique": "T1566/T1204",
        "name": "HTMLSmugglingContentType",
        "severity": "medium",
        "field": "raw",
        "patterns": [r"content-type.*application/octet-stream.*\.html?", r"x-content-type.*smuggl"],
    },
    {
        "stage": "PayloadExecution",
        "technique": "T1059/T1071",
        "name": "ScriptingEngineUserAgent",
        "severity": "high",
        "field": "useragent",
        "patterns": [
            r"powershell",
            r"wscript|cscript",
            r"mshta",
            r"certutil",
            r"bitsadmin",
        ],
    },
    {
        "stage": "PayloadExecution",
        "technique": "T1071",
        "name": "C2BeaconURIPattern",
        "severity": "high",
        "field": "uri",
        "patterns": BUILTIN_IOCS["c2_uri_patterns"],
    },
    {
        "stage": "PayloadExecution",
        "technique": "T1071",
        "name": "C2InfrastructureIP",
        "severity": "high",
        "field": "host",
        "patterns": BUILTIN_IOCS["c2_ips"],
    },
    {
        "stage": "LateralMovement",
        "technique": "T1021/T1078",
        "name": "SMBRelayProbePattern",
        "severity": "high",
        "field": "raw",
        "patterns": [
            r"smb.*relay|ntlm.*relay",
            r"STATUS_MORE_PROCESSING_REQUIRED.*NTLMSSP",
        ],
    },
    {
        "stage": "LateralMovement",
        "technique": "T1078",
        "name": "NTLMAuthAnomaly",
        "severity": "medium",
        "field": "raw",
        "patterns": [r"ntlmssp_auth.*failure", r"kerberos.*preauth.*fail", r"4625.*logon.*type.*3"],
    },
    {
        "stage": "LateralMovement",
        "technique": "T1021",
        "name": "PassTheHashRDPVPN",
        "severity": "high",
        "field": "raw",
        "patterns": [
            r"rdp.*logon.*pass.?the.?hash",
            r"4648.*rdp|vpn.*credential.*replay",
            r"sekurlsa|mimikatz",
        ],
    },
]

LOG_PATTERNS = [
    re.compile(
        r"(?P<ts>\d+\.\d+)\s+\d+\s+(?P<src>\S+)\s+\w+/(?P<code>\d+)\s+\d+\s+(?P<method>\w+)\s+(?P<uri>\S+)\s+\S+\s+\S+/\S+\s+(?P<ct>\S+)"
    ),
    re.compile(
        r'(?P<src>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<uri>\S+)[^"]*"\s+(?P<code>\d+).*?"(?P<useragent>[^"]*)"'
    ),
    re.compile(
        r"(?P<ts>\w{3}\s+\d+\s+\S+)\s+\S+\s+\S+\[.*?\]:\s+(?P<raw>.*(from|to|subject|sender).*)",
        re.IGNORECASE,
    ),
    re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+(?P<raw>.+)"),
]


def parse_log_entries(path):
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"ERROR: cannot open log file: {e}", file=sys.stderr)
        sys.exit(2)
    with fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            entry = {"raw": line.lower(), "ts": "", "src": "", "uri": "", "host": "",
                     "method": "", "code": "", "useragent": "", "sender": ""}
            for pat in LOG_PATTERNS:
                m = pat.search(line)
                if m:
                    gd = m.groupdict()
                    entry.update({k: v for k, v in gd.items() if v})
                    break
            if "uri" in entry and entry["uri"]:
                try:
                    entry["uri"] = urllib.parse.unquote(entry["uri"]).lower()
                except Exception:
                    pass
            host_m = re.search(r"https?://([^/]+)", entry.get("uri", ""))
            if host_m and not entry["host"]:
                entry["host"] = host_m.group(1)
            sender_m = re.search(r"from[=:\s]+<?([^\s>]+@[^\s>]+)>?", line, re.IGNORECASE)
            if sender_m:
                entry["sender"] = sender_m.group(1).lower()
            yield entry


def load_iocs(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot load IOC file: {e}", file=sys.stderr)
        sys.exit(2)


def merge_iocs(extra):
    for rule in RULES:
        field = rule.get("field", "")
        key_map = {
            "uri": ["staging_uri_patterns", "c2_uri_patterns"],
            "host": ["c2_ips", "phishing_domains"],
            "sender": ["phishing_senders", "phishing_domains"],
        }
        for k in key_map.get(field, []):
            if k in extra:
                rule["patterns"] = list(set(rule["patterns"] + extra[k]))


def match_rules(entry, rules, severity_floor):
    severity_order = {"low": 0, "medium": 1, "high": 2}
    floor = severity_order.get(severity_floor, 0)
    hits = []
    for rule in rules:
        if severity_order.get(rule["severity"], 0) < floor:
            continue
        field_val = entry.get(rule["field"], "") or entry.get("raw", "")
        for pat in rule["patterns"]:
            if re.search(pat, field_val, re.IGNORECASE):
                hits.append(rule)
                break
    return hits


def report_findings(path, rules, severity_floor, extra_iocs):
    dedup = defaultdict(dict)
    stage_counts = defaultdict(int)
    techniques = set()
    attackers = set()
    peak = "low"
    severity_order = {"low": 0, "medium": 1, "high": 2}
    high_found = False

    for entry in parse_log_entries(path):
        hits = match_rules(entry, rules, severity_floor)
        src = entry.get("src") or entry.get("sender") or "unknown"
        ts_now = time.time()
        for rule in hits:
            key = (src, rule["name"])
            last_seen = dedup[key].get("ts", 0)
            if ts_now - last_seen < 60:
                continue
            dedup[key]["ts"] = ts_now
            stage_counts[rule["stage"]] += 1
            techniques.add(rule["technique"])
            if src not in ("unknown", ""):
                attackers.add(src)
            sev = rule["severity"]
            if severity_order.get(sev, 0) > severity_order.get(peak, 0):
                peak = sev
            if sev == "high":
                high_found = True
            ts_label = entry.get("ts") or "no-ts"
            raw_snippet = entry["raw"][:120]
            print(
                f"[{ts_label}] STAGE={rule['stage']} TECHNIQUE={rule['technique']} "
                f"SEV={sev.upper()} RULE={rule['name']} SRC={src} | {raw_snippet}"
            )

    print("\n=== SUMMARY ===")
    for stage, count in sorted(stage_counts.items()):
        print(f"  {stage}: {count} hit(s)")
    print(f"  ATT&CK techniques: {', '.join(sorted(techniques)) or 'none'}")
    print(f"  Unique attackers: {len(attackers)}")
    print(f"  Peak severity: {peak.upper()}")
    return high_found


def main():
    parser = argparse.ArgumentParser(
        description="Avalon Multi-Stage Phishing Chain & Lateral Movement Detector"
    )
    parser.add_argument("log_file", help="Path to proxy, SMTP gateway, or endpoint log export")
    parser.add_argument("--iocs", metavar="FILE", help="JSON file with supplemental IOCs")
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum alert severity to emit (default: low)",
    )
    args = parser.parse_args()

    rules = [r.copy() for r in RULES]
    for r in rules:
        r["patterns"] = list(r["patterns"])

    if args.iocs:
        extra = load_iocs(args.iocs)
        merge_iocs(extra)

    high_found = report_findings(args.log_file, rules, args.severity, args.iocs)
    sys.exit(1 if high_found else 0)


if __name__ == "__main__":
    main()