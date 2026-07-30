"""
wireless_adb_c2_detector.py - Scans network connection logs for unauthorized Wireless ADB (TCP/5555) sessions.

Usage:
    python wireless_adb_c2_detector.py connections.log
    python wireless_adb_c2_detector.py firewall.log --iocs iocs.json --severity medium
    python wireless_adb_c2_detector.py netstat.log --severity high

Exit code 1 if any high-severity finding is detected.
"""

import argparse
import ipaddress
import json
import re
import sys
from collections import defaultdict

RULES = {
    "Exposure": [
        {"name": "adb_daemon_listen", "severity": "high", "technique": "T1219",
         "pattern": r"(?:LISTEN|listen)", "port": 5555,
         "mitigation": "Disable ADB over WiFi on device; enforce USB-only debugging via MDM policy."},
        {"name": "adb_daemon_established_inbound", "severity": "high", "technique": "T1219",
         "pattern": r"(?:ESTABLISHED|established)", "port": 5555, "require_inbound": True,
         "mitigation": "Terminate session, revoke ADB authorization, rotate device credentials."},
    ],
    "LateralMovement": [
        {"name": "adb_wifi_no_pairing", "severity": "high", "technique": "T1021.002",
         "port": 5555, "require_internal_dst": True, "require_no_pairing": True,
         "mitigation": "Block TCP/5555 on internal segments; require USB pairing before WiFi ADB."},
    ],
    "C2Callback": [
        {"name": "adb_external_c2", "severity": "high", "technique": "T1572",
         "port": 5555, "require_external_dst": True,
         "mitigation": "Block egress TCP/5555 at perimeter; inspect for reverse ADB tunnel artifacts."},
    ],
}

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

ENTRY_RE = re.compile(
    r"(?P<ts>\S+\s+\S+|\S+)?\s*"
    r"(?:tcp\S*\s+\S+\s+\S+\s+)?"
    r"(?P<src>[\d.]+):(?P<sport>\d+)\s+"
    r"(?P<dst>[\d.]+):(?P<dport>\d+)\s+"
    r"(?P<state>\S+)",
    re.IGNORECASE,
)

ENTRY_RE2 = re.compile(
    r"(?P<src>[\d.]+)\s+(?P<dst>[\d.]+)\s+.*?(?P<dport>5555|5037)\b.*?(?P<state>ESTABLISHED|LISTEN|SYN_SENT|CLOSE_WAIT)",
    re.IGNORECASE,
)


def is_internal(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


def load_iocs(path):
    if not path:
        return {}, [], []
    try:
        with open(path) as f:
            data = json.load(f)
        return (
            data.get("bad_ips", {}),
            data.get("allowlist", []),
            data.get("paired_hosts", []),
        )
    except (OSError, json.JSONDecodeError) as e:
        print(f"[ERROR] Failed to load IOCs: {e}", file=sys.stderr)
        sys.exit(2)


def parse_entries(log_path):
    entries = []
    try:
        with open(log_path) as f:
            lines = f.readlines()
    except OSError as e:
        print(f"[ERROR] Cannot read log file: {e}", file=sys.stderr)
        sys.exit(2)

    for lineno, raw in enumerate(lines, 1):
        line = raw.strip()
        m = ENTRY_RE.search(line)
        if not m:
            m = ENTRY_RE2.search(line)
            if not m:
                continue
        try:
            src, dst = m.group("src"), m.group("dst")
            dport = int(m.group("dport"))
            state = m.group("state").upper()
            sport = int(m.group("sport")) if "sport" in m.groupdict() else 0
        except (ValueError, IndexError):
            continue
        entries.append({
            "src": src, "dst": dst, "dport": dport, "sport": sport,
            "state": state, "lineno": lineno, "raw": line,
        })
    return entries


def build_pairing_set(entries):
    paired = set()
    for e in entries:
        if e["dport"] == 5037 and e["state"] in ("ESTABLISHED", "CLOSE_WAIT", "TIME_WAIT"):
            paired.add(e["src"])
    return paired


def match_rules(entries, bad_ips, allowlist, paired_hosts, min_severity):
    paired_set = build_pairing_set(entries)
    paired_set.update(paired_hosts)
    allowset = set(allowlist)
    findings = []
    seen = set()

    for e in entries:
        if e["src"] in allowset or e["dst"] in allowset:
            continue
        src, dst, dport, state = e["src"], e["dst"], e["dport"], e["state"]

        for stage, rules in RULES.items():
            for rule in rules:
                if SEVERITY_RANK.get(rule["severity"], 0) < SEVERITY_RANK.get(min_severity, 0):
                    continue
                if rule.get("port") and dport != rule["port"]:
                    continue
                if "pattern" in rule and not re.search(rule["pattern"], state, re.IGNORECASE):
                    continue
                if rule.get("require_inbound") and not is_internal(dst):
                    continue
                if rule.get("require_internal_dst") and not is_internal(dst):
                    continue
                if rule.get("require_external_dst") and is_internal(dst):
                    continue
                if rule.get("require_no_pairing") and src in paired_set:
                    continue

                extra_sev = bad_ips.get(src, bad_ips.get(dst))
                severity = extra_sev if extra_sev and SEVERITY_RANK.get(extra_sev, 0) > SEVERITY_RANK.get(rule["severity"], 0) else rule["severity"]

                key = (rule["name"], src, dst)
                if key in seen:
                    continue
                seen.add(key)

                findings.append({
                    "severity": severity,
                    "stage": stage,
                    "technique": rule["technique"],
                    "rule": rule["name"],
                    "src": f"{src}:{e['sport']}",
                    "dst": f"{dst}:{dport}",
                    "lineno": e["lineno"],
                    "mitigation": rule["mitigation"],
                })
    return findings


def report(findings):
    peak = "low"
    stage_counts = defaultdict(int)
    techniques = set()

    for f in findings:
        sev_label = f["severity"].upper()
        print(f"[{sev_label}] stage={f['stage']} technique={f['technique']} "
              f"src={f['src']} dst={f['dst']} line={f['lineno']} | {f['mitigation']}")
        stage_counts[f["stage"]] += 1
        techniques.add(f["technique"])
        if SEVERITY_RANK.get(f["severity"], 0) > SEVERITY_RANK.get(peak, 0):
            peak = f["severity"]

    print("\n--- Summary ---")
    for stage, count in sorted(stage_counts.items()):
        print(f"  {stage}: {count} finding(s)")
    print(f"  ATT&CK techniques: {', '.join(sorted(techniques)) or 'none'}")
    print(f"  Peak severity: {peak.upper()}")
    return peak


def main():
    parser = argparse.ArgumentParser(description="Wireless ADB C2 & Lateral Movement Detector")
    parser.add_argument("log_file", help="Path to network connection log")
    parser.add_argument("--iocs", help="JSON file with bad_ips, allowlist, paired_hosts")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum severity to emit (default: low)")
    args = parser.parse_args()

    bad_ips, allowlist, paired_hosts = load_iocs(args.iocs)
    entries = parse_entries(args.log_file)
    findings = match_rules(entries, bad_ips, allowlist, paired_hosts, args.severity)

    if not findings:
        print("No findings.")
        sys.exit(0)

    peak = report(findings)
    sys.exit(1 if peak == "high" else 0)


if __name__ == "__main__":
    main()