"""
VeloCloud Orchestrator Command Injection Zero-Day Detector & Patch Verifier

Scans plain-text HTTP access log exports from VMware VeloCloud Orchestrator for
active exploitation of the command injection zero-day and verifies patch posture.

Usage:
    python velocloud_orchestrator_cmdinject_detector.py access.log
    python velocloud_orchestrator_cmdinject_detector.py access.log --severity high
    python velocloud_orchestrator_cmdinject_detector.py access.log --iocs iocs.json

Example IOC JSON: {"ips": ["1.2.3.4"], "domains": ["evil.com"], "uri_fragments": ["/api/exploit"]}
"""
import argparse, json, re, sys
from collections import defaultdict
from urllib.parse import unquote

COMBINED_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+(?P<size>\S+)(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)
PROBE_PATH = re.compile(r'/(?:orchestrator/client|rest/customer|portal/server\.pt)', re.I)
INJECT_PATH = re.compile(r'/(?:rest/customer|orchestrator/client|portal/server\.pt|vco/api)', re.I)
METACHAR = re.compile(r'[;|`]|\$\(|%0[aAdD]|%3[Bb]|%7[Cc]|%60|&&|\|\|', re.I)
B64_UA = re.compile(r'(?:wget|curl|python|libwww)|[A-Za-z0-9+/]{40,}={0,2}', re.I)
PATCH_ENDPOINTS = [
    ("/orchestrator/client", "302/404 on unauthenticated access post-patch"),
    ("/rest/customer",       "403 on unauthenticated access post-patch"),
    ("/vco/api/login",       "400 on malformed body post-patch"),
]
SEV = {"low": 0, "medium": 1, "high": 2}


def decode_uri(s):
    try: return unquote(unquote(s))
    except Exception: return s


def parse_line(line):
    m = COMBINED_RE.match(line.strip())
    if not m: return None
    return {"ip": m.group("ip"), "time": m.group("time"), "method": m.group("method"),
            "uri": decode_uri(m.group("uri")), "status": m.group("status"),
            "ua": m.group("ua") or ""}


def match_rules(entry, iocs, inject_ips):
    hits, uri, status, ip, ua = [], entry["uri"], entry["status"], entry["ip"], entry["ua"]
    if ip in iocs["ip_set"]:
        hits.append({"rule": "IOC-IP", "stage": "OrchestratorProbe", "technique": "T1190", "severity": "medium"})
    if any(f in uri for f in iocs.get("uri_fragments", [])):
        hits.append({"rule": "IOC-URI", "stage": "CmdInjection", "technique": "T1059", "severity": "high"})
    if PROBE_PATH.search(uri) and not METACHAR.search(uri):
        hits.append({"rule": "OrchestratorProbe", "stage": "OrchestratorProbe", "technique": "T1190", "severity": "low"})
    if INJECT_PATH.search(uri) and METACHAR.search(uri) and status in {"200", "500"}:
        hits.append({"rule": "CmdInjection", "stage": "CmdInjection", "technique": "T1059", "severity": "high"})
        inject_ips.add(ip)
    if ip in inject_ips and (B64_UA.search(ua) or any(d in ua for d in iocs.get("domains", []))):
        hits.append({"rule": "PostExploit-ReverseShell", "stage": "PostExploit",
                     "technique": "T1059/T1505", "severity": "high"})
    return hits


def main():
    ap = argparse.ArgumentParser(description="VeloCloud Orchestrator Command Injection Zero-Day Detector")
    ap.add_argument("log_file", help="Path to HTTP access log export")
    ap.add_argument("--iocs", help="Supplemental IOC JSON file")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low")
    args = ap.parse_args()

    iocs = {"ips": [], "domains": [], "uri_fragments": []}
    if args.iocs:
        try:
            with open(args.iocs) as f: iocs.update(json.load(f))
        except Exception as e:
            print(f"[WARN] Could not load IOCs: {e}", file=sys.stderr)
    iocs["ip_set"] = set(iocs.get("ips", []))

    min_sev = SEV[args.severity]
    stage_counts: dict = defaultdict(int)
    attacker_ips: set = set()
    inject_ips: set = set()
    dedup: dict = {}
    patch_hits: dict = defaultdict(set)
    found_high = False
    line_num = 0

    try:
        log_fh = open(args.log_file)
    except OSError as e:
        print(f"[ERROR] Cannot open log file: {e}", file=sys.stderr)
        sys.exit(1)

    with log_fh:
        for line in log_fh:
            line_num += 1
            if line.startswith("#") or not line.strip(): continue
            entry = parse_line(line)
            if not entry: continue
            for ep, _ in PATCH_ENDPOINTS:
                if ep in entry["uri"]: patch_hits[ep].add(entry["status"])
            for h in match_rules(entry, iocs, inject_ips):
                if SEV[h["severity"]] < min_sev: continue
                dk = (entry["ip"], h["rule"])
                last_seen = dedup.get(dk)
                if last_seen is not None and line_num - last_seen < 60:
                    continue
                dedup[dk] = line_num
                stage_counts[h["stage"]] += 1
                attacker_ips.add(entry["ip"])
                if h["severity"] == "high": found_high = True
                print(f"[{entry['time']}] {h['stage']} | {h['technique']} | {h['severity'].upper()} | "
                      f"{h['rule']} | src={entry['ip']} | {line.strip()[:140]}")

    print("\n=== Patch Verification Checklist ===")
    signals = []
    for ep, desc in PATCH_ENDPOINTS:
        statuses = patch_hits.get(ep, set())
        if {"302", "404", "403", "400"} & statuses and "200" not in statuses:
            label, sig = "PRESENT", True
        elif statuses:
            label, sig = "AMBIGUOUS", None
        else:
            label, sig = "MISSING", False
        signals.append(sig)
        print(f"  [{label}] {ep} — {desc}")

    techniques: set = set()
    for stage in stage_counts:
        if stage == "OrchestratorProbe": techniques.add("T1190")
        elif stage == "CmdInjection": techniques.add("T1059")
        elif stage == "PostExploit": techniques.update(["T1059", "T1505"])

    if stage_counts.get("CmdInjection", 0) > 0:
        verdict = "LIKELY-UNPATCHED"
    elif signals and not any(v is False for v in signals) and any(v is True for v in signals):
        verdict = "PATCHED"
    elif not signals or all(v is None for v in signals):
        verdict = "INSUFFICIENT-DATA"
    else:
        verdict = "LIKELY-UNPATCHED"

    print("\n=== Summary ===")
    for stage, count in stage_counts.items():
        print(f"  {stage}: {count} hit(s)")
    print(f"  Unique attacker IPs: {len(attacker_ips)}")
    print(f"  ATT&CK techniques: {', '.join(sorted(techniques)) or 'none'}")
    print(f"  Patch posture: {verdict}")
    sys.exit(1 if found_high else 0)


if __name__ == "__main__":
    main()