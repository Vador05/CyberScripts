"""
VMware ESXi/vCenter Auth Bypass to VM Escape Chain Detector — BlueTeam/Detection

Scans plain-text vCenter vpxd.log, ESXi hostd.log, or shell audit log exports
for CVE-2026-59309 exploitation indicators across the auth bypass to VM escape chain.
Each finding is labeled with kill-chain stage and MITRE ATT&CK for IaaS technique ID.

Usage:
    python vmware_esxi_vcenter_escape_chain_detector.py vpxd.log
    python vmware_esxi_vcenter_escape_chain_detector.py hostd.log --severity high
    python vmware_esxi_vcenter_escape_chain_detector.py audit.log --iocs extra.json --severity medium

iocs.json format: {"attacker_ips": ["1.2.3.4"], "uri_fragments": ["/evil"], "vm_ids": ["vm-42"]}
"""
import argparse, collections, json, re, sys, time
from urllib.parse import unquote

SEV = {"low": 0, "medium": 1, "high": 2}

RULES = [
    {"stage": "AuthBypass", "tech": "T1190",    "sev": "high",   "name": "CVE-2026-59309_SOAP_bypass",
     "pattern": re.compile(r"(SessionManager\.Login|VmomiSupport|/sdk/vimService|/mob/\?moid=SessionManager)", re.I),
     "extra": re.compile(r"(malformed|unauthenticated|invalid.?session|bypass|X-VMWARE-ARBITRARY|null.?token)", re.I)},
    {"stage": "AuthBypass", "tech": "T1078.004","sev": "high",   "name": "CVE-2026-59309_REST_bypass",
     "pattern": re.compile(r"(/rest/com/vmware/cis/session|/api/session|/vcenter/authentication)", re.I),
     "extra": re.compile(r"(401|403|unauthenticated|no.?ticket|anonymous|SSPI.?bypass)", re.I)},
    {"stage": "AuthBypass", "tech": "T1078.004","sev": "high",   "name": "SSPI_bypass_vpxd",
     "pattern": re.compile(r"(SSPI|Kerberos.*fail|ntlm.*bypass|session.*establish)", re.I),
     "extra": re.compile(r"(bypass|tamper|forged|replayed|unauthenticated)", re.I)},
    {"stage": "VMEscape",   "tech": "T1611",    "sev": "high",   "name": "VMCI_backdoor_abuse",
     "pattern": re.compile(r"(vmci|backdoor.*channel|RPCI|GuestRpc|vmx.*escape|escape.*gadget)", re.I),
     "extra": None},
    {"stage": "VMEscape",   "tech": "T1611",    "sev": "high",   "name": "vmx_privilege_transition",
     "pattern": re.compile(r"(vmx.*priv|privilege.*vmx|vmx.*root|vmprocess.*uid|vmx.*escalat)", re.I),
     "extra": None},
    {"stage": "VMEscape",   "tech": "T1611",    "sev": "high",   "name": "guest_host_api_abuse",
     "pattern": re.compile(r"(guest.*host.*api|host.*call.*guest|vmkernel.*guest|escape.*path|CVE-2026-59309)", re.I),
     "extra": None},
    {"stage": "PostExploit","tech": "T1082",    "sev": "medium", "name": "esxi_shell_activation",
     "pattern": re.compile(r"(ESXiShell|ssh.*enabled|shell.*activate|busybox.*exec|dcui.*shell)", re.I),
     "extra": None},
    {"stage": "PostExploit","tech": "T1530",    "sev": "medium", "name": "datastore_enumeration",
     "pattern": re.compile(r"(datastore.*browse|ListDatastores|DatastoreNamespace|QueryVmfsDatastore|vmdk.*open)", re.I),
     "extra": None},
    {"stage": "PostExploit","tech": "T1046",    "sev": "medium", "name": "lateral_movement_scan",
     "pattern": re.compile(r"(SearchIndex|FindByIp|FindByDnsName|RetrieveAllPermissions|ListAllVMs|HostSystem.*list)", re.I),
     "extra": None},
    {"stage": "PostExploit","tech": "T1082",    "sev": "high",   "name": "credential_harvest",
     "pattern": re.compile(r"(vpxuser|dcui.*cred|vsphere-webclient.*token|thumbprint.*steal|SSO.*dump|credential.*extract)", re.I),
     "extra": None},
]

VPXD_RE  = re.compile(r"^(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)[\.\d+Z]*\s+(?:\S+\s+)?(?:info|warn|error|verbose)?\s*(?:\[([^\]]+)\])?\s+(.*)", re.I)
HOSTD_RE = re.compile(r"^(\w{3}\s+\d+\s+\d\d:\d\d:\d\d)\s+\S+\s+(?:hostd|vmx)\[?(\d*)?\]?:?\s+(.*)")
AUDIT_RE = re.compile(r"^.*?(?:time|timestamp)=(\S+).*?(?:src|srcip|ip)=(\S+).*?(?:msg|message|cmd)=(.+)")
IP_RE    = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
SID_RE   = re.compile(r"(session[:\s]+\S+|ticket[:\s]+\S+|vmomi\.client\.\S+)", re.I)


def parse_entries(path):
    with open(path, errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip()
            if not line or line.startswith("#"):
                continue
            decoded = unquote(line)
            decoded = re.sub(r"<[^:>]+:", "", decoded)
            for fmt, rx in (("vpxd", VPXD_RE), ("hostd", HOSTD_RE), ("audit", AUDIT_RE)):
                m = rx.match(decoded)
                if m:
                    ts, ctx, body = m.group(1), (m.group(2) or ""), m.group(3)
                    ip_m = IP_RE.search(body) or IP_RE.search(ctx)
                    sid_m = SID_RE.search(body)
                    yield {
                        "ts": ts, "fmt": fmt,
                        "src": ip_m.group(1) if ip_m else (sid_m.group(1)[:32] if sid_m else "unknown"),
                        "body": body, "raw": line,
                    }
                    break


def load_iocs(path):
    with open(path) as fh:
        data = json.load(fh)
    extra = []
    for ip in data.get("attacker_ips", []):
        extra.append({"stage": "AuthBypass", "tech": "T1190", "sev": "high", "name": f"IOC_IP_{ip}",
                       "pattern": re.compile(re.escape(ip)), "extra": None})
    for idx, frag in enumerate(data.get("uri_fragments", [])):
        extra.append({"stage": "AuthBypass", "tech": "T1190", "sev": "high", "name": f"IOC_URI_{idx}_{frag}",
                       "pattern": re.compile(re.escape(frag), re.I), "extra": None})
    for vm in data.get("vm_ids", []):
        extra.append({"stage": "PostExploit", "tech": "T1530", "sev": "medium", "name": f"IOC_VM_{vm}",
                       "pattern": re.compile(re.escape(vm), re.I), "extra": None})
    return extra


def match_rules(entry, rules, min_sev, dedup, window=60):
    results = []
    for rule in rules:
        if SEV[rule["sev"]] < SEV[min_sev]:
            continue
        if not rule["pattern"].search(entry["body"]):
            continue
        if rule["extra"] and not rule["extra"].search(entry["body"]):
            continue
        key = (entry["src"], rule["name"])
        now = time.monotonic()
        if now - dedup.get(key, -window - 1) < window:
            continue
        dedup[key] = now
        results.append(rule)
    return results


def report_findings(path, iocs_path, min_sev):
    rules = RULES[:]
    if iocs_path:
        rules.extend(load_iocs(iocs_path))
    dedup = {}
    stage_counts = collections.Counter()
    tech_set = set()
    attackers = set()
    peak = "low"
    found_high = False
    for entry in parse_entries(path):
        for rule in match_rules(entry, rules, min_sev, dedup):
            stage_counts[rule["stage"]] += 1
            tech_set.add(rule["tech"])
            attackers.add(entry["src"])
            if SEV[rule["sev"]] > SEV[peak]:
                peak = rule["sev"]
            if rule["sev"] == "high":
                found_high = True
            print(f"[{entry['ts']}] ALERT stage={rule['stage']} tech={rule['tech']} "
                  f"sev={rule['sev'].upper()} rule={rule['name']} src={entry['src']} | {entry['raw']}")
    print("\n=== Summary ===")
    for stage, count in sorted(stage_counts.items()):
        print(f"  {stage}: {count} hit(s)")
    print(f"  ATT&CK techniques: {', '.join(sorted(tech_set)) or 'none'}")
    print(f"  Unique attacker identifiers: {len(attackers)}")
    print(f"  Peak severity: {peak.upper()}")
    return found_high


def main():
    ap = argparse.ArgumentParser(description="VMware ESXi/vCenter CVE-2026-59309 chain detector")
    ap.add_argument("log_file", help="Path to vpxd.log, hostd.log, or shell audit log export")
    ap.add_argument("--iocs", metavar="FILE", help="Supplemental IOC JSON file")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum alert severity to emit (default: low)")
    args = ap.parse_args()
    try:
        found_high = report_findings(args.log_file, args.iocs, args.severity)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"ERROR: invalid IOC JSON — {e}", file=sys.stderr)
        sys.exit(2)
    sys.exit(1 if found_high else 0)


if __name__ == "__main__":
    main()