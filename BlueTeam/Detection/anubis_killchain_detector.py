"""
Anubis Ransomware Kill Chain Detector (CVE-2025-5777 / BYOVD / Supply Chain)

Scans plain-text log exports for indicators of the Anubis ransomware kill chain
across three stages: Citrix Bleed 2 exploitation, BYOVD kernel driver abuse, and
supply chain credential harvesting.

Usage:
    python anubis_killchain_detector.py access.log
    python anubis_killchain_detector.py netscaler.nslog --iocs extra_iocs.json --severity high
    python anubis_killchain_detector.py siem_export.log --severity medium

Exit codes:
    0 = no high-severity matches found
    1 = at least one high-severity match found
    2 = usage/runtime error
"""

import argparse
import json
import re
import sys
from collections import defaultdict, deque

BUILTIN_RULES = {
    "InitialAccess": [
        {"name": "CVE-2025-5777_oauth_probe", "severity": "high",
         "pattern": re.compile(r"/oauth/idp/[^\s]*", re.I)},
        {"name": "CVE-2025-5777_nfauth_token", "severity": "high",
         "pattern": re.compile(r"/nf/auth/[^\s]*", re.I)},
        {"name": "CVE-2025-5777_range_request", "severity": "medium",
         "pattern": re.compile(r"Range:\s*bytes=0-", re.I)},
        {"name": "CitrixADC_unauthenticated_disclosure", "severity": "high",
         "pattern": re.compile(r"/vpn/\.\./[^\s]*|/epa/[^\s]*session[^\s]*", re.I)},
        {"name": "NetScaler_session_token_exfil", "severity": "high",
         "pattern": re.compile(r"NSC_AAAC=[A-Za-z0-9+/]{20,}", re.I)},
    ],
    "DefenseEvasion": [
        {"name": "BYOVD_RTCore64", "severity": "high",
         "pattern": re.compile(r"RTCore64\.sys", re.I)},
        {"name": "BYOVD_GMER_driver", "severity": "high",
         "pattern": re.compile(r"gmer\d*\.sys|gdrv\.sys", re.I)},
        {"name": "BYOVD_vulnerable_driver_load", "severity": "medium",
         "pattern": re.compile(r"(procexp\d+\.sys|WinRing0x64\.sys|mhyprot\d*\.sys)", re.I)},
        {"name": "kernel_process_injection", "severity": "high",
         "pattern": re.compile(r"NtWriteVirtualMemory|ZwWriteVirtualMemory|kernel.*inject", re.I)},
        {"name": "driver_load_unsigned", "severity": "medium",
         "pattern": re.compile(r"LoadDriver.*failed.*signature|unsigned.*driver.*loaded", re.I)},
    ],
    "CredentialAccess": [
        {"name": "CICD_token_access", "severity": "high",
         "pattern": re.compile(r"(\.npmrc|\.pypirc|\.netrc|pip\.conf|\.docker/config\.json)", re.I)},
        {"name": "github_actions_secret_exfil", "severity": "high",
         "pattern": re.compile(r"GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN|secrets\.[A-Z_]{4,}", re.I)},
        {"name": "package_registry_auth", "severity": "medium",
         "pattern": re.compile(r"(registry\.npmjs\.org|pypi\.org|rubygems\.org).*Authorization:", re.I)},
        {"name": "anubis_c2_outbound", "severity": "high",
         "pattern": re.compile(r"(185\.220\.\d+\.\d+|193\.32\.\d+\.\d+|anubis-c2\.[a-z]+)", re.I)},
        {"name": "credential_file_read", "severity": "medium",
         "pattern": re.compile(r"(id_rsa|authorized_keys|shadow|passwd|credentials\.json)", re.I)},
    ],
}

LOG_RE = re.compile(
    r'(?P<src>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)[^"]*"\s+(?P<code>\d+)\s+\S+(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)
KV_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')


def parse_log_entries(line):
    m = LOG_RE.match(line)
    if m:
        return {"src": m.group("src"), "ts": m.group("ts"), "method": m.group("method"),
                "uri": m.group("uri"), "code": m.group("code"), "ua": m.group("ua") or "", "raw": line}
    kv = {k: v.strip('"') for k, v in KV_RE.findall(line)}
    if kv:
        return {"src": kv.get("src", kv.get("ClientIP", kv.get("host", "unknown"))),
                "ts": kv.get("timestamp", kv.get("ts", "")), "method": kv.get("method", ""),
                "uri": kv.get("uri", kv.get("url", kv.get("path", ""))), "code": kv.get("code", ""),
                "ua": kv.get("useragent", kv.get("ua", "")), "raw": line}
    return {"src": "unknown", "ts": "", "method": "", "uri": "", "code": "", "ua": "", "raw": line}


def load_extra_iocs(path, rules):
    try:
        with open(path) as f:
            iocs = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[WARN] Could not load --iocs file: {e}", file=sys.stderr)
        return
    for driver in iocs.get("byovd_drivers", []):
        pat = re.compile(re.escape(driver), re.I)
        rules["DefenseEvasion"].append({"name": f"BYOVD_custom_{driver}", "severity": "high", "pattern": pat})
    for ioc in iocs.get("c2_indicators", []):
        pat = re.compile(re.escape(ioc), re.I)
        rules["CredentialAccess"].append({"name": f"AnubisC2_custom_{ioc}", "severity": "high", "pattern": pat})
    for frag in iocs.get("cve_uri_fragments", []):
        pat = re.compile(re.escape(frag), re.I)
        rules["InitialAccess"].append({"name": f"CVE20255777_custom_{frag}", "severity": "high", "pattern": pat})


def match_rules(entry, rules, min_severity):
    severity_rank = {"low": 0, "medium": 1, "high": 2}
    min_rank = severity_rank.get(min_severity, 0)
    hits = []
    haystack = " ".join([entry["uri"], entry["ua"], entry["raw"]])
    for stage, ruleset in rules.items():
        for rule in ruleset:
            if severity_rank.get(rule["severity"], 0) < min_rank:
                continue
            if rule["pattern"].search(haystack):
                hits.append({"stage": stage, "rule": rule["name"], "severity": rule["severity"]})
    return hits


def report_findings(log_path, rules, min_severity):
    seen = defaultdict(lambda: deque(maxlen=60))
    stage_counts = defaultdict(int)
    unique_sources = defaultdict(set)
    peak_severity = "low"
    severity_rank = {"low": 0, "medium": 1, "high": 2}
    initial_access_sources = set()
    any_high = False

    try:
        with open(log_path, errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                entry = parse_log_entries(line)
                hits = match_rules(entry, rules, min_severity)
                for hit in hits:
                    dedup_key = (entry["src"], hit["rule"])
                    if dedup_key in seen[entry["src"]]:
                        continue
                    seen[entry["src"]].append(dedup_key)
                    stage_counts[hit["stage"]] += 1
                    unique_sources[hit["stage"]].add(entry["src"])
                    if hit["stage"] == "InitialAccess":
                        initial_access_sources.add(entry["src"])
                    if entry["src"] in initial_access_sources and hit["stage"] != "InitialAccess":
                        hit["severity"] = "high"
                    if severity_rank.get(hit["severity"], 0) > severity_rank.get(peak_severity, 0):
                        peak_severity = hit["severity"]
                    if hit["severity"] == "high":
                        any_high = True
                    truncated = line[:140]
                    ts_display = entry["ts"] or "no-timestamp"
                    print(f"[{ts_display}] STAGE={hit['stage']} SEV={hit['severity'].upper()} "
                          f"RULE={hit['rule']} SRC={entry['src']} | {truncated}")
    except OSError as e:
        print(f"[ERROR] Cannot read log file: {e}", file=sys.stderr)
        sys.exit(2)

    print("\n=== Anubis Kill Chain Detection Summary ===")
    for stage in ["InitialAccess", "DefenseEvasion", "CredentialAccess"]:
        count = stage_counts.get(stage, 0)
        sources = len(unique_sources.get(stage, set()))
        print(f"  {stage}: {count} hit(s), {sources} unique source(s)")
    print(f"  Peak severity observed: {peak_severity.upper()}")
    print(f"  Total unique attacker IPs: {len(set().union(*unique_sources.values()) if unique_sources else set())}")
    return any_high


def main():
    parser = argparse.ArgumentParser(
        description="Anubis Ransomware Kill Chain Detector (CVE-2025-5777 / BYOVD / Supply Chain)",
        epilog="Example: python anubis_killchain_detector.py access.log --iocs feeds.json --severity high"
    )
    parser.add_argument("log_file", help="Path to plain-text log or SIEM export to scan")
    parser.add_argument("--iocs", metavar="FILE", help="JSON file with supplemental Anubis IOCs")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum alert severity to emit (default: low)")
    args = parser.parse_args()

    rules = {stage: list(ruleset) for stage, ruleset in BUILTIN_RULES.items()}
    if args.iocs:
        load_extra_iocs(args.iocs, rules)

    any_high = report_findings(args.log_file, rules, args.severity)
    sys.exit(1 if any_high else 0)


if __name__ == "__main__":
    main()