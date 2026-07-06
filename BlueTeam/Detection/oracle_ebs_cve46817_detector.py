"""
Oracle EBS CVE-2026-46817 Exploitation Detector

Scans Oracle HTTP Server or Apache combined-format access log exports for
active exploitation of CVE-2026-46817 against Oracle E-Business Suite.

Usage:
    python oracle_ebs_cve46817_detector.py /var/log/oracle/access.log
    python oracle_ebs_cve46817_detector.py access.log --severity high
    python oracle_ebs_cve46817_detector.py access.log --iocs extra_iocs.json --severity medium

IOC JSON format:
    {"attacker_ips": ["1.2.3.4"], "domains": ["evil.com"], "uri_fragments": ["/shell.jsp"]}
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

BUNDLED_RULES = [
    {"stage": "Recon", "severity": "low", "name": "EBS_OA_HTML_Probe",
     "field": "uri", "pattern": r"/OA_HTML/(?:AppsLogin|jsp/|cabo/)", "case_insensitive": True},
    {"stage": "Recon", "severity": "low", "name": "EBS_Servlet_Probe",
     "field": "uri", "pattern": r"/oa_servlets/", "case_insensitive": True},
    {"stage": "Recon", "severity": "low", "name": "EBS_FNDWRR_Probe",
     "field": "uri", "pattern": r"/OA_HTML/.*FNDWRR", "case_insensitive": True},
    {"stage": "Recon", "severity": "low", "name": "EBS_IceServ_Probe",
     "field": "uri", "pattern": r"/OA_HTML/.*IceServlet", "case_insensitive": True},
    {"stage": "Exploit", "severity": "high", "name": "CVE46817_AuthBypass_ICX",
     "field": "uri", "pattern": r"/OA_HTML/.*ICX_SESSION_TICKET.*=", "case_insensitive": True},
    {"stage": "Exploit", "severity": "high", "name": "CVE46817_AuthBypass_Cookie_Manip",
     "field": "uri", "pattern": r"/OA_HTML/.*(?:icx_session|oracle_ecid|gwyuid)=['\"]?\w{40,}", "case_insensitive": True},
    {"stage": "Exploit", "severity": "high", "name": "CVE46817_SSO_Bypass",
     "field": "uri", "pattern": r"/OA_HTML/.*(?:dbc=|fndnam=|gwyuid=).*(?:apps|system)", "case_insensitive": True},
    {"stage": "Exploit", "severity": "high", "name": "CVE46817_Servlet_Injection",
     "field": "uri", "pattern": r"/oa_servlets/.*(?:exec|cmd|command|eval|system)\s*[=(]", "case_insensitive": True},
    {"stage": "PostExploit", "severity": "high", "name": "Webshell_Access",
     "field": "uri", "pattern": r"\.(?:jsp|jspx|war|class)\?.*(?:cmd|exec|shell|run)=", "case_insensitive": True},
    {"stage": "PostExploit", "severity": "high", "name": "EBS_Data_Exfil_Pattern",
     "field": "uri", "pattern": r"/OA_HTML/.*(?:FND_FILE|wf_notification|ap_invoices|gl_je_lines).*SELECT", "case_insensitive": True},
    {"stage": "PostExploit", "severity": "medium", "name": "Suspicious_UAgent_Recon",
     "field": "user_agent", "pattern": r"(?:python-requests|curl/|wget/|nikto|sqlmap|nmap)", "case_insensitive": True},
]

KNOWN_ATTACKER_IPS = {"185.220.101.45", "45.142.212.100", "194.165.16.77", "91.92.251.103", "193.27.228.112"}
KNOWN_EXFIL_DOMAINS = {"update-srv.net", "cdn-oracle.tk", "ebs-patch.xyz", "finance-upd.com"}

LOG_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)\s+\S+"\s+(?P<status>\d+)\s+\S+(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def load_supplemental_iocs(path):
    try:
        with open(path) as f:
            data = json.load(f)
        ips = set(data.get("attacker_ips", []))
        domains = set(data.get("domains", []))
        uri_frags = data.get("uri_fragments", [])
        return ips, domains, uri_frags
    except (OSError, json.JSONDecodeError) as e:
        print(f"[WARN] Could not load supplemental IOCs from {path}: {e}", file=sys.stderr)
        return set(), set(), []


def build_rules(extra_ips, extra_domains, extra_uri_frags):
    rules = list(BUNDLED_RULES)
    all_ips = KNOWN_ATTACKER_IPS | extra_ips
    all_domains = KNOWN_EXFIL_DOMAINS | extra_domains
    if all_ips:
        ip_pattern = "|".join(re.escape(ip) for ip in all_ips)
        rules.append({"stage": "PostExploit", "severity": "high", "name": "Known_Attacker_IP",
                       "field": "ip", "pattern": f"^(?:{ip_pattern})$", "case_insensitive": False})
    if all_domains:
        dom_pattern = "|".join(re.escape(d) for d in all_domains)
        rules.append({"stage": "PostExploit", "severity": "high", "name": "Known_Exfil_Domain",
                       "field": "uri", "pattern": f"(?:{dom_pattern})", "case_insensitive": True})
    for i, frag in enumerate(extra_uri_frags):
        rules.append({"stage": "PostExploit", "severity": "medium", "name": f"Custom_IOC_URI_{i}",
                       "field": "uri", "pattern": re.escape(frag), "case_insensitive": True})
    for rule in rules:
        flags = re.IGNORECASE if rule.get("case_insensitive") else 0
        rule["compiled"] = re.compile(rule["pattern"], flags)
    return rules


def parse_log_entries(path):
    try:
        with open(path, errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                line = line.rstrip("\n")
                m = LOG_RE.match(line)
                if not m:
                    continue
                yield {
                    "ip": m.group("ip"),
                    "time": m.group("time"),
                    "method": m.group("method"),
                    "uri": m.group("uri"),
                    "status": m.group("status"),
                    "user_agent": m.group("ua") or "",
                    "raw": line,
                    "lineno": lineno,
                }
    except OSError as e:
        print(f"[ERROR] Cannot read log file: {e}", file=sys.stderr)
        sys.exit(2)


def match_rules(entry, rules, min_severity):
    hits = []
    min_rank = SEVERITY_ORDER[min_severity]
    for rule in rules:
        if SEVERITY_ORDER[rule["severity"]] < min_rank:
            continue
        field_val = entry.get(rule["field"], "")
        if rule["compiled"].search(field_val):
            hits.append(rule)
    return hits


def report_findings(log_path, rules, min_severity):
    stage_counts = defaultdict(int)
    attacker_ips = set()
    peak_severity = "low"
    dedup_window = {}
    window_seconds = 60
    found_high = False

    for entry in parse_log_entries(log_path):
        hits = match_rules(entry, rules, min_severity)
        for rule in hits:
            dedup_key = (entry["ip"], rule["name"])
            now_str = entry["time"]
            last_seen = dedup_window.get(dedup_key)
            if last_seen:
                try:
                    t_now = datetime.strptime(now_str.split()[0], "%d/%b/%Y:%H:%M:%S")
                    t_last = datetime.strptime(last_seen.split()[0], "%d/%b/%Y:%H:%M:%S")
                    if abs((t_now - t_last).total_seconds()) < window_seconds:
                        continue
                except ValueError:
                    pass
            dedup_window[dedup_key] = now_str
            stage_counts[rule["stage"]] += 1
            attacker_ips.add(entry["ip"])
            if SEVERITY_ORDER[rule["severity"]] > SEVERITY_ORDER[peak_severity]:
                peak_severity = rule["severity"]
            if rule["severity"] == "high":
                found_high = True
            print(f"[{entry['time']}] STAGE={rule['stage']} SEV={rule['severity'].upper()} "
                  f"RULE={rule['name']} SRC={entry['ip']} | {entry['raw']}")

    print("\n--- Summary ---")
    for stage in ("Recon", "Exploit", "PostExploit"):
        print(f"  {stage}: {stage_counts.get(stage, 0)} hit(s)")
    print(f"  Unique attacker IPs: {len(attacker_ips)}")
    print(f"  Peak severity: {peak_severity.upper()}")
    return found_high


def main():
    parser = argparse.ArgumentParser(
        description="Detect CVE-2026-46817 exploitation in Oracle EBS HTTP access logs."
    )
    parser.add_argument("log_file", help="Path to plain-text Oracle HTTP Server or Apache combined-format access log")
    parser.add_argument("--iocs", metavar="JSON_FILE", help="Supplemental IOC file with attacker IPs, domains, URI fragments")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum alert severity to emit (default: low)")
    args = parser.parse_args()

    extra_ips, extra_domains, extra_frags = set(), set(), []
    if args.iocs:
        extra_ips, extra_domains, extra_frags = load_supplemental_iocs(args.iocs)

    rules = build_rules(extra_ips, extra_domains, extra_frags)
    found_high = report_findings(args.log_file, rules, args.severity)
    sys.exit(1 if found_high else 0)


if __name__ == "__main__":
    main()