"""
FortiBleed Triage Scanner - Scans FortiGate logs for CVE-2024-21762, CVE-2023-27997, CVE-2024-23113 exploitation indicators.

Usage:
    python fortibleed_triage_scanner.py /var/log/fortigate.log
    python fortibleed_triage_scanner.py /var/log/fortigate.log --cve CVE-2024-21762
    python fortibleed_triage_scanner.py /var/log/fortigate.log --verbose
"""

import argparse
import re
import sys
from collections import defaultdict

CVE_RULES = {
    "CVE-2024-21762": {
        "description": "FortiOS SSL-VPN out-of-bounds write RCE",
        "severity": "CRITICAL",
        "patterns": [
            (re.compile(r"url=.*\/remote\/(?:logincheck|hostcheck|info).*['\"]?\s*\.\./", re.I), "path-traversal in SSL-VPN URL"),
            (re.compile(r"url=.*\/remote\/[^\s]*%2e%2e", re.I), "URL-encoded traversal in SSL-VPN"),
            (re.compile(r"action=ssl-login-fail.*url=.*\/remote\/", re.I), "repeated SSL-VPN login failures"),
            (re.compile(r"msg=.*heap.*overflow|msg=.*memory.*corrupt", re.I), "heap/memory corruption indicator"),
        ],
        "remediation": [
            "Upgrade FortiOS to 7.4.3+, 7.2.7+, 7.0.14+, or 6.4.15+",
            "Disable SSL-VPN if not required (set ssl-vpn-max-proto-ver disable)",
            "Review /var/log/sslvpn_stat.log for anomalous session counts",
            "Rotate all VPN credentials and certificates immediately",
            "Check for new admin accounts or unauthorized SSH keys",
        ],
    },
    "CVE-2023-27997": {
        "description": "FortiOS SSL-VPN heap-based buffer overflow pre-auth RCE",
        "severity": "CRITICAL",
        "patterns": [
            (re.compile(r"url=.*\/remote\/hostcheck_validate", re.I), "hostcheck_validate endpoint probe"),
            (re.compile(r"policyid=0.*url=.*\/remote\/", re.I), "unauthenticated SSL-VPN request (policyid=0)"),
            (re.compile(r"url=.*\/remote\/logincheck.*method=post.*srcip=", re.I), "POST to logincheck pre-auth"),
            (re.compile(r"bytesrcv=(?:[5-9]\d{4}|[1-9]\d{5,}).*url=.*\/remote\/", re.I), "large payload to SSL-VPN endpoint"),
        ],
        "remediation": [
            "Upgrade FortiOS to 7.2.5+, 7.0.12+, 6.4.13+, or 6.2.15+",
            "Apply workaround: disable SSL-VPN web mode (config vpn ssl settings; unset ssl-vpn-web-mode)",
            "Block external access to port 443/10443 at perimeter if SSL-VPN unused",
            "Audit SSL-VPN user session logs for sessions without corresponding auth events",
            "Check for implants in /data/lib/ and unexpected SUID binaries",
        ],
    },
    "CVE-2024-23113": {
        "description": "FortiOS fgfmd format string unauthenticated RCE",
        "severity": "CRITICAL",
        "patterns": [
            (re.compile(r"url=.*\/fgfm|port=541\b", re.I), "fgfmd protocol access on port 541"),
            (re.compile(r"msg=.*fgfm.*error|action=fgfm", re.I), "fgfmd error or action event"),
            (re.compile(r"dstport=541\b.*proto=6", re.I), "TCP connection to fgfmd port"),
            (re.compile(r"msg=.*format.*string|msg=.*printf.*inject", re.I), "format string injection indicator"),
            (re.compile(r"logdesc=.*unauthorized.*fgfm|logdesc=.*fgfm.*auth.*fail", re.I), "unauthorized fgfmd access"),
        ],
        "remediation": [
            "Upgrade FortiOS to 7.4.3+, 7.2.7+, 7.0.14+, or 6.4.15+",
            "Disable fgfmd access from untrusted interfaces: config system fgfm; set interface-select-method specify",
            "Restrict port 541 to trusted FortiManager IPs only via local-in policy",
            "Review FortiManager connection logs for unauthorized management activity",
            "Check for unexpected configuration changes in recent audit logs",
        ],
    },
}

BEACON_PATTERNS = [
    re.compile(r"url=.*\/remote\/info.*interval=\d+", re.I),
    re.compile(r"action=tunnel-stat.*duration=(?:[3-9]\d{3}|\d{5,})", re.I),
    re.compile(r"msg=.*beacon|msg=.*c2|msg=.*command.and.control", re.I),
    re.compile(r"url=.*\.(onion|bit|bazar)\b", re.I),
]


def parse_logs(path):
    records = []
    with open(path, "r", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line:
                continue
            fields = {}
            for token in re.finditer(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)', line):
                key, val = token.group(1), token.group(2).strip('"')
                fields[key] = val
            if fields:
                records.append({"lineno": lineno, "raw": line, "fields": fields})
    return records


def detect_iocs(records, cve_filter=None):
    hits = []
    cvelist = {cve_filter: CVE_RULES[cve_filter]} if cve_filter else CVE_RULES
    for rec in records:
        line = rec["raw"]
        fields = rec["fields"]
        srcip = fields.get("srcip", fields.get("src", "unknown"))
        date = fields.get("date", "")
        time_val = fields.get("time", "")
        timestamp = f"{date} {time_val}".strip() or f"line:{rec['lineno']}"
        for cve, meta in cvelist.items():
            for pattern, label in meta["patterns"]:
                if pattern.search(line):
                    hits.append({
                        "timestamp": timestamp,
                        "srcip": srcip,
                        "cve": cve,
                        "severity": meta["severity"],
                        "label": label,
                        "raw": line,
                    })
                    break
        for bp in BEACON_PATTERNS:
            if bp.search(line):
                hits.append({
                    "timestamp": timestamp,
                    "srcip": srcip,
                    "cve": "POST-EXPLOIT",
                    "severity": "HIGH",
                    "label": "post-exploitation beaconing",
                    "raw": line,
                })
                break
    return hits


def report_findings(hits, verbose=False):
    if not hits:
        print("[*] No FortiBleed exploitation indicators found.")
        return
    col = "{:<22} {:<16} {:<16} {:<9} {}"
    print("\n=== FortiBleed Triage Scanner — Hit Table ===")
    print(col.format("TIMESTAMP", "SOURCE IP", "CVE", "SEVERITY", "MATCHED PATTERN"))
    print("-" * 95)
    for h in hits:
        print(col.format(h["timestamp"][:22], h["srcip"][:16], h["cve"], h["severity"], h["label"]))
        if verbose:
            print(f"    RAW: {h['raw'][:200]}")
    ip_counts = defaultdict(int)
    cve_counts = defaultdict(int)
    matched_cves = set()
    for h in hits:
        ip_counts[h["srcip"]] += 1
        cve_counts[h["cve"]] += 1
        if h["cve"] != "POST-EXPLOIT":
            matched_cves.add(h["cve"])
    print(f"\n=== IOC Summary ({len(hits)} total hits) ===")
    print("Top offending source IPs:")
    for ip, cnt in sorted(ip_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"  {ip:<20} {cnt} hit(s)")
    print("\nHits by CVE:")
    for cve, cnt in sorted(cve_counts.items(), key=lambda x: -x[1]):
        print(f"  {cve:<20} {cnt} hit(s)")
    if matched_cves:
        print("\n=== Remediation Checklist ===")
        for cve in sorted(matched_cves):
            meta = CVE_RULES[cve]
            print(f"\n[{cve}] {meta['description']} — Severity: {meta['severity']}")
            for i, step in enumerate(meta["remediation"], 1):
                print(f"  {i}. {step}")


def main():
    parser = argparse.ArgumentParser(
        description="Scan FortiGate logs for FortiBleed exploitation indicators.",
        epilog="Example: python fortibleed_triage_scanner.py fortigate.log --cve CVE-2024-21762 --verbose",
    )
    parser.add_argument("log_file", help="Path to plain-text FortiGate log file")
    parser.add_argument("--cve", choices=list(CVE_RULES.keys()), default=None, help="Filter to a specific CVE ID")
    parser.add_argument("--verbose", action="store_true", help="Print full matched log line alongside each hit")
    args = parser.parse_args()

    try:
        records = parse_logs(args.log_file)
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {args.log_file}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied reading: {args.log_file}", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"[ERROR] Could not read log file: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsed {len(records)} log records from {args.log_file}")
    hits = detect_iocs(records, cve_filter=args.cve)
    report_findings(hits, verbose=args.verbose)


if __name__ == "__main__":
    main()