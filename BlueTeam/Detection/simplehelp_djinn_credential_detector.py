"""
SimpleHelp CVE-2026-48558 & Djinn Cloud/AI Credential Exfil Detector

Scans HTTP access logs or SIEM exports for CVE-2026-48558 SimpleHelp exploitation
chained with Djinn stealer cloud/AI credential exfiltration across three kill-chain stages.

Usage:
    python simplehelp_djinn_credential_detector.py access.log
    python simplehelp_djinn_credential_detector.py access.log --severity high
    python simplehelp_djinn_credential_detector.py access.log --iocs extra_iocs.json --severity medium

    extra_iocs.json format:
    {
        "c2_domains": ["evil.example.com"],
        "c2_ips": ["1.2.3.4"],
        "exploit_uris": ["/api/evil-path"]
    }
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime

RULES = {
    "Exploitation": [
        {"name": "CVE-2026-48558-PathTraversal", "severity": "high",
         "pattern": re.compile(r"(?:GET|POST)\s+.*(?:/api/[^\"'\s]*(?:\.\./|%2e%2e/|%252e)|/clientsoftware/[^\"'\s]*(?:\.\./|%2e%2e))", re.I)},
        {"name": "CVE-2026-48558-AuthBypass", "severity": "high",
         "pattern": re.compile(r"(?:GET|POST)\s+.*(?:/api/(?:authenticate|session|admin)[^\"'\s]*(?:\?|&)(?:bypass|token=&|auth=1)|/clientsoftware/\.\.)", re.I)},
        {"name": "SimpleHelp-API-SuspiciousProbe", "severity": "medium",
         "pattern": re.compile(r"(?:GET|POST)\s+.*(?:/api/(?:getserverdetails|getinstallationdetails|getsupportkey)[^\"'\s]*)", re.I)},
        {"name": "SimpleHelp-AdminInterface-Access", "severity": "medium",
         "pattern": re.compile(r"(?:GET|POST)\s+.*/interface/[^\"'\s]*admin", re.I)},
    ],
    "CredentialAccess": [
        {"name": "Djinn-AWS-Credentials", "severity": "high",
         "pattern": re.compile(r"(?:\.aws/credentials|\.aws/config|AWS_ACCESS_KEY|aws_secret_access_key)", re.I)},
        {"name": "Djinn-GCP-ADC", "severity": "high",
         "pattern": re.compile(r"(?:application_default_credentials\.json|gcloud/credentials\.db|GOOGLE_APPLICATION_CREDENTIALS|gcp_service_account)", re.I)},
        {"name": "Djinn-OpenAI-Key", "severity": "high",
         "pattern": re.compile(r"(?:openai_key|OPENAI_API_KEY|\.openai|openai_credentials|sk-[A-Za-z0-9]{20,})", re.I)},
        {"name": "Djinn-AI-Env-Files", "severity": "medium",
         "pattern": re.compile(r"(?:\.env(?:\.local|\.production|\.dev)?|anthropic_api_key|ANTHROPIC_API_KEY|huggingface_token|HF_TOKEN)", re.I)},
        {"name": "Djinn-Azure-Credentials", "severity": "high",
         "pattern": re.compile(r"(?:\.azure/accessTokens\.json|AZURE_CLIENT_SECRET|azure_credentials|MSI_SECRET)", re.I)},
        {"name": "Djinn-SSH-Keys", "severity": "medium",
         "pattern": re.compile(r"(?:id_rsa|id_ed25519|id_ecdsa|\.ssh/[^\"'\s]+)", re.I)},
    ],
    "Exfiltration": [
        {"name": "Djinn-C2-Domain", "severity": "high",
         "pattern": re.compile(r"(?:djinn-c2\.xyz|exfil-hub\.net|cloudstealer\.ru|djinn-relay\.onion|data-drop\.cc)", re.I)},
        {"name": "Djinn-C2-IP", "severity": "high",
         "pattern": re.compile(r"(?:185\.220\.101\.\d+|194\.165\.16\.\d+|45\.142\.212\.\d+|91\.108\.4\.\d+)")},
        {"name": "Djinn-Exfil-URI-Pattern", "severity": "high",
         "pattern": re.compile(r"(?:POST|PUT)\s+.*(?:/upload/creds|/exfil/|/collect/keys|/drop/data|/harvest/)", re.I)},
        {"name": "Djinn-Beacon-Pattern", "severity": "medium",
         "pattern": re.compile(r"(?:GET|POST)\s+.*(?:/ping\?id=|/beacon\?|/check-in\?uuid=|/c2/|/gate\.php)", re.I)},
        {"name": "Large-POST-Suspicious", "severity": "low",
         "pattern": re.compile(r'POST\s+\S+\s+HTTP/\d\.\d"\s+(?:200|201)\s+(?:[5-9]\d{5}|\d{7,})', re.I)},
    ],
}

LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<request>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
KV_PATTERN = re.compile(r'(?P<key>\w+)=(?:"(?P<qval>[^"]+)"|(?P<val>\S+))')
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def parse_log_entry(line):
    m = LOG_PATTERN.match(line)
    if m:
        return {"ip": m.group("ip"), "ts": m.group("ts"),
                "request": m.group("request"), "status": m.group("status"),
                "ua": m.group("ua") or ""}
    kv = {m.group("key"): (m.group("qval") or m.group("val")) for m in KV_PATTERN.finditer(line)}
    if kv.get("src_ip") or kv.get("srcip") or kv.get("client_ip"):
        return {"ip": kv.get("src_ip") or kv.get("srcip") or kv.get("client_ip", "-"),
                "ts": kv.get("timestamp") or kv.get("time", "-"),
                "request": kv.get("request") or kv.get("uri", line),
                "status": kv.get("status") or kv.get("response_code", "-"),
                "ua": kv.get("useragent") or kv.get("user_agent", "")}
    return {"ip": "-", "ts": "-", "request": line, "status": "-", "ua": ""}


def load_supplemental_iocs(path):
    with open(path) as f:
        data = json.load(f)
    for domain in data.get("c2_domains", []):
        RULES["Exfiltration"].append({"name": f"Custom-C2-Domain-{domain}", "severity": "high",
                                       "pattern": re.compile(re.escape(domain), re.I)})
    for ip in data.get("c2_ips", []):
        RULES["Exfiltration"].append({"name": f"Custom-C2-IP-{ip}", "severity": "high",
                                       "pattern": re.compile(re.escape(ip))})
    for uri in data.get("exploit_uris", []):
        RULES["Exploitation"].append({"name": f"Custom-ExploitURI-{uri}", "severity": "high",
                                       "pattern": re.compile(re.escape(uri), re.I)})


def format_alert(stage, rule, entry, line):
    ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    return f"[{ts}] STAGE={stage} SEVERITY={rule['severity'].upper()} RULE={rule['name']} SRC={entry['ip']} | {line.rstrip()}"


def run(args):
    if args.iocs:
        try:
            load_supplemental_iocs(args.iocs)
        except (OSError, json.JSONDecodeError, KeyError) as e:
            print(f"ERROR: Failed to load supplemental IOCs: {e}", file=sys.stderr)
            sys.exit(2)

    min_sev = SEVERITY_ORDER[args.severity]
    stage_counts = defaultdict(int)
    attacker_ips = set()
    peak_sev = -1
    dedup = defaultdict(set)
    found_high = False

    try:
        fh = open(args.log_file)
    except OSError as e:
        print(f"ERROR: Cannot open log file: {e}", file=sys.stderr)
        sys.exit(2)

    with fh:
        for line in fh:
            if not line.strip():
                continue
            entry = parse_log_entry(line)
            haystack = line
            for stage, rules in RULES.items():
                for rule in rules:
                    if SEVERITY_ORDER[rule["severity"]] < min_sev:
                        continue
                    if not rule["pattern"].search(haystack):
                        continue
                    dedup_key = (entry["ip"], rule["name"])
                    if dedup_key in dedup[stage]:
                        continue
                    dedup[stage].add(dedup_key)
                    print(format_alert(stage, rule, entry, line))
                    stage_counts[stage] += 1
                    if entry["ip"] != "-":
                        attacker_ips.add(entry["ip"])
                    sev_val = SEVERITY_ORDER[rule["severity"]]
                    if sev_val > peak_sev:
                        peak_sev = sev_val
                    if rule["severity"] == "high":
                        found_high = True

    peak_label = ["low", "medium", "high"][peak_sev] if peak_sev >= 0 else "none"
    print("\n--- SUMMARY ---")
    total = sum(stage_counts.values())
    print(f"Total matches: {total} | Unique attacker IPs: {len(attacker_ips)} | Peak severity: {peak_label.upper()}")
    for stage in ("Exploitation", "CredentialAccess", "Exfiltration"):
        print(f"  {stage}: {stage_counts.get(stage, 0)} hit(s)")
    if attacker_ips:
        print(f"  Attacker IPs: {', '.join(sorted(attacker_ips))}")

    sys.exit(1 if found_high else 0)


def main():
    parser = argparse.ArgumentParser(
        description="Detect CVE-2026-48558 SimpleHelp exploitation + Djinn credential exfiltration in logs."
    )
    parser.add_argument("log_file", help="Path to HTTP access log or SIEM log export")
    parser.add_argument("--iocs", help="Path to supplemental JSON IOC file")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum severity level to report (default: low)")
    run(parser.parse_args())


if __name__ == "__main__":
    main()