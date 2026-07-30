"""
UTA0533 SonicWall Pre-Patch Exploitation & Custom Malware TTP Detector

Scans plain-text SonicWall SMA appliance access log exports for UTA0533
intrusion-set activity across three kill-chain stages.

Usage:
    python uta0533_sonicwall_preauth_ttp_detector.py access.log
    python uta0533_sonicwall_preauth_ttp_detector.py access.log --severity high
    python uta0533_sonicwall_preauth_ttp_detector.py access.log --iocs iocs.json

Example IOC JSON: {"ips": ["1.2.3.4"], "uri_fragments": ["/evil/path"], "domains": ["c2.evil.com"]}
"""
import argparse, json, re, sys
from collections import defaultdict
from urllib.parse import unquote

COMBINED_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+\S+(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)
KV_RE = re.compile(
    r'(?:client_ip|c-ip|src)[:=](?P<ip>\S+?)[\s,].*?(?:uri|cs-uri-stem|path)[:=]"?(?P<uri>\S+?)"?'
    r'.*?(?:method|cs-method)[:=](?P<method>\w+).*?(?:status|sc-status)[:=](?P<status>\d+)',
    re.IGNORECASE | re.DOTALL,
)

TRAVERSAL_RE = re.compile(r'(?:%2[Ee]|\.\.)[/%]|%00|%2[Ff]\.\.|\.\.[/\\]|;path=', re.IGNORECASE)
NULL_BYTE_RE = re.compile(r'%00|\x00', re.IGNORECASE)
SHELL_META_RE = re.compile(r'[|;&`$<>]|\$\(|\$\{|`[^`]+`', re.IGNORECASE)
LOW_ENTROPY_PATH_RE = re.compile(r'/[a-f0-9]{8,32}(?:/[a-f0-9]{8,32})+', re.IGNORECASE)
BINARY_EXT_RE = re.compile(r'\.(sh|elf|bin|so|cgi|pl|py|php|jsp|war)(\?|$)', re.IGNORECASE)
CONTENT_MISMATCH_RE = re.compile(r'content-type[^\n]*(?:octet-stream|x-executable|application/x-sh)', re.IGNORECASE)

PREAUTH_PATHS = re.compile(
    r'/(?:cgi-bin/management|auth/welcome|appliance/login|dana-na/|cgi-bin/sslvpnclient'
    r'|cgi-bin/authforms|vpn/index\.cgi|remote/logincheck)',
    re.IGNORECASE,
)
IMPLANT_PATHS = re.compile(
    r'/(?:cgi-bin/[a-zA-Z0-9_-]+\.(?:sh|pl|py|elf|bin|cgi)|'
    r'appliance/(?:update|upgrade|install)|cgi-bin/upload)',
    re.IGNORECASE,
)
CRED_HARVEST_PATHS = re.compile(
    r'/(?:etc/passwd|etc/shadow|cgi-bin/userdb|vpn/credential|'
    r'cgi-bin/auth|appliance/config\.cgi|cgi-bin/session)',
    re.IGNORECASE,
)

RULES = [
    {"name": "PreAuth-ManagementProbe", "stage": "PreAuthProbe", "technique": "T1190",
     "severity": "high", "path_re": PREAUTH_PATHS, "payload_re": TRAVERSAL_RE, "statuses": {"200", "302"}},
    {"name": "PreAuth-NullByteInjection", "stage": "PreAuthProbe", "technique": "T1190",
     "severity": "high", "path_re": PREAUTH_PATHS, "payload_re": NULL_BYTE_RE, "statuses": None},
    {"name": "ImplantStaging-CGIDelivery", "stage": "ImplantStaging", "technique": "T1505.003",
     "severity": "high", "path_re": IMPLANT_PATHS, "payload_re": BINARY_EXT_RE, "statuses": {"200", "201"}},
    {"name": "ImplantStaging-LowEntropyBeacon", "stage": "ImplantStaging", "technique": "T1505.003",
     "severity": "medium", "path_re": LOW_ENTROPY_PATH_RE, "payload_re": None, "statuses": {"200"}},
    {"name": "CredHarvest-PasswdProbe", "stage": "CredentialHarvest", "technique": "T1552",
     "severity": "high", "path_re": CRED_HARVEST_PATHS, "payload_re": None, "statuses": None},
    {"name": "CredHarvest-CGIShellInjection", "stage": "CredentialHarvest", "technique": "T1552",
     "severity": "high", "path_re": PREAUTH_PATHS, "payload_re": SHELL_META_RE, "statuses": None},
]
CROSS_STAGE_RULE = {"name": "CrossStage-IPCorrelation", "stage": "CredentialHarvest",
                    "technique": "T1078", "severity": "high"}
SEV = {"low": 0, "medium": 1, "high": 2}


def decode_uri(uri):
    try:
        return unquote(unquote(uri)).replace('%2e', '.').replace('%2f', '/')
    except Exception:
        return uri


def parse_line(line):
    m = COMBINED_RE.match(line)
    if m:
        return {"ip": m.group("ip"), "time": m.group("time"), "method": m.group("method"),
                "uri": decode_uri(m.group("uri")), "status": m.group("status"),
                "ua": m.group("ua") or "", "raw": line}
    m = KV_RE.search(line)
    if m:
        return {"ip": m.group("ip"), "time": "", "method": m.group("method"),
                "uri": decode_uri(m.group("uri")), "status": m.group("status"),
                "ua": "", "raw": line}
    return None


def load_iocs(path):
    with open(path) as f:
        return json.load(f)


def match_rules(entry, rules, extra_iocs, preauth_ips):
    hits = []
    uri = entry["uri"]
    status = entry["status"]
    ip = entry["ip"]
    has_credharvest = False
    for rule in rules:
        if extra_iocs.get("ips") and ip in extra_iocs["ips"]:
            hits.append((rule, "high"))
            if rule["stage"] == "PreAuthProbe":
                preauth_ips.add(ip)
            if rule["stage"] == "CredentialHarvest":
                has_credharvest = True
            continue
        path_match = rule["path_re"].search(uri) if rule["path_re"] else False
        if not path_match and not (extra_iocs.get("uri_fragments") and
                                   any(f in uri for f in extra_iocs["uri_fragments"])):
            continue
        if rule.get("statuses") and status not in rule["statuses"]:
            continue
        payload_re = rule.get("payload_re")
        if payload_re and not payload_re.search(uri):
            continue
        sev = rule["severity"]
        if rule["stage"] == "PreAuthProbe":
            preauth_ips.add(ip)
        if ip in preauth_ips and rule["stage"] != "PreAuthProbe":
            sev = "high"
        hits.append((rule, sev))
        if rule["stage"] == "CredentialHarvest":
            has_credharvest = True
    if ip in preauth_ips and has_credharvest:
        hits.append((CROSS_STAGE_RULE, "high"))
    return hits


def report_findings(log_file, extra_iocs, min_sev):
    counts = defaultdict(int)
    techniques = set()
    attacker_ips = set()
    peak_sev = "low"
    preauth_ips = set()
    dedup_window = defaultdict(list)
    has_high = False

    for raw_line in log_file:
        line = raw_line.rstrip()
        if not line or line.startswith("#") or line.lower().startswith("date"):
            continue
        entry = parse_line(line)
        if not entry:
            continue
        for rule, sev in match_rules(entry, RULES, extra_iocs, preauth_ips):
            if SEV.get(sev, 0) < SEV.get(min_sev, 0):
                continue
            key = (entry["ip"], rule["name"])
            window = dedup_window[key]
            if len(window) >= 60 and all(w == entry["uri"][:40] for w in window[-5:]):
                continue
            window.append(entry["uri"][:40])
            if len(window) > 60:
                window.pop(0)
            attacker_ips.add(entry["ip"])
            counts[rule["stage"]] += 1
            techniques.add(rule["technique"])
            if SEV.get(sev, 0) > SEV.get(peak_sev, 0):
                peak_sev = sev
            if sev == "high":
                has_high = True
            ts = entry.get("time", "")[:20]
            print(f"[{ts}] [{sev.upper()}] [{rule['stage']}] [{rule['technique']}] "
                  f"[{rule['name']}] src={entry['ip']} \"{line[:140]}\"")

    print("\n--- UTA0533 TTP Detection Summary ---")
    for stage, cnt in counts.items():
        print(f"  {stage}: {cnt} hit(s)")
    print(f"  ATT&CK techniques: {', '.join(sorted(techniques)) or 'none'}")
    print(f"  Unique attacker IPs: {len(attacker_ips)}")
    print(f"  Peak severity: {peak_sev.upper()}")
    return has_high


def main():
    parser = argparse.ArgumentParser(description="UTA0533 SonicWall SMA TTP Detector")
    parser.add_argument("log_file", help="Path to SonicWall SMA access log export")
    parser.add_argument("--iocs", help="Path to supplemental UTA0533 IOC JSON file")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum severity to emit (default: low)")
    args = parser.parse_args()

    extra_iocs = {}
    if args.iocs:
        try:
            extra_iocs = load_iocs(args.iocs)
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: Failed to load IOC file: {e}", file=sys.stderr)
            sys.exit(2)

    try:
        with open(args.log_file, errors="replace") as f:
            has_high = report_findings(f, extra_iocs, args.severity)
    except OSError as e:
        print(f"ERROR: Cannot open log file: {e}", file=sys.stderr)
        sys.exit(2)

    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()