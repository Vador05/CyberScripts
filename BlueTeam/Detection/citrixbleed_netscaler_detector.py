"""
citrixbleed_netscaler_detector.py — CVE-2023-4966 CitrixBleed NetScaler memory-disclosure detector.
Scans NetScaler/Apache combined-format HTTP access logs for CitrixBleed exploit attempts,
stolen-session reuse, and Anubis ransomware post-exploitation IOCs across three kill-chain stages.

Usage:
    python citrixbleed_netscaler_detector.py access.log
    python citrixbleed_netscaler_detector.py access.log --iocs extra.json --severity high
IOC JSON: {"attacker_ips": ["1.2.3.4"], "c2_domains": ["evil.com"], "uri_fragments": ["/bad"]}
"""
import argparse, json, re, sys
from collections import defaultdict
from datetime import datetime
from urllib.parse import unquote

VULN_EPS = ("/oauth/idp/.well-known/openid-configuration", "/nf/auth/", "/logon/LogonPoint/")
AUTH_EPS  = ("/logon/LogonPoint/", "/nf/auth/doAuthentication")
ANUBIS_URIS = ("/anubis/", "/staging/payload", "/.svn/anubis", "/dropper/stage")
BYOVD = ("rtcore64.sys", "gdrv.sys", "capcom.sys", "mhyprotect.sys", "dbutil_2_3.sys")
C2_SEEDS = ("anubis-c2.xyz", "netscaler-update.com", "citrix-support.net", "185.220.101.", "45.142.212.")
SEV = {"low": 0, "medium": 1, "high": 2}
LOG_RE = re.compile(
    r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)[^"]*"\s+(\d+)\s+(\S+)\s+"[^"]*"\s+"([^"]*)"'
)


def parse_ts(s):
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            pass
    return 0.0


def parse_log(path):
    with open(path, errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line[0] == "#":
                continue
            m = LOG_RE.match(line)
            if not m:
                continue
            ip, ts, method, uri, code, byt, ua = m.groups()
            yield {"ip": ip, "ts": parse_ts(ts), "method": method, "uri": unquote(uri),
                   "code": int(code), "bytes": int(byt) if byt.isdigit() else 0, "ua": ua, "raw": line}


def load_iocs(path):
    with open(path) as fh:
        d = json.load(fh)
    return d.get("attacker_ips", []), d.get("c2_domains", []), d.get("uri_fragments", [])


def findings(e, auth_times, c2_all, xips, xuris):
    uri, ua, b = e["uri"], e["ua"], e["bytes"]
    combo = uri + " " + ua
    if any(uri.startswith(ep) for ep in VULN_EPS) and (b > 65536 or (24576 <= b <= 131072 and b > 200)):
        yield ("MemoryDisclosure", "T1190", "high", "CitrixBleed-OversizedResponse")
    if e["code"] == 200 and ("NSC_AAAC" in combo or "NSC_TMAA" in combo):
        no_auth = e["ts"] - auth_times.get(e["ip"], 0) > 120
        att = "T1539" if no_auth else "T1078"
        sev = "high" if no_auth else "medium"
        rule = "StolenToken-NoAuthFlow" if no_auth else "SessionCookie-Reuse"
        yield ("SessionHijack", att, sev, rule)
    if any(d in combo for d in c2_all):
        yield ("PostExploit", "T1195", "high", "CVE-2025-5777-C2Domain")
    if any(drv.lower() in combo.lower() for drv in BYOVD):
        yield ("PostExploit", "T1068", "high", "BYOVD-DriverDrop")
    if any(u in uri for u in ANUBIS_URIS + tuple(xuris)):
        yield ("PostExploit", "T1486", "high", "Anubis-StagingURI")
    if e["ip"] in xips:
        yield ("PostExploit", "T1190", "medium", "KnownAttackerIP")


def main():
    ap = argparse.ArgumentParser(description="CitrixBleed CVE-2023-4966 NetScaler log detector")
    ap.add_argument("log_file", help="NetScaler/Apache combined-format HTTP access log")
    ap.add_argument("--iocs", help='JSON file: {"attacker_ips":[], "c2_domains":[], "uri_fragments":[]}')
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low")
    args = ap.parse_args()

    xips, xdoms, xuris = [], [], []
    if args.iocs:
        try:
            xips, xdoms, xuris = load_iocs(args.iocs)
        except (OSError, json.JSONDecodeError) as exc:
            sys.exit(f"ERROR loading IOCs: {exc}")

    xips = set(xips)
    c2_all = list(C2_SEEDS) + xdoms
    min_sev = SEV[args.severity]
    counts, techs, ips_seen = defaultdict(int), set(), set()
    bleed, peak, high_hit, dedup, auth_times = 0, "low", False, {}, {}

    try:
        entries = list(parse_log(args.log_file))
    except OSError as exc:
        sys.exit(f"ERROR opening log: {exc}")

    for e in entries:
        if any(e["uri"].startswith(ep) for ep in AUTH_EPS) and e["code"] in (200, 302):
            auth_times[e["ip"]] = e["ts"]
        for stage, att, sev, rule in findings(e, auth_times, c2_all, xips, xuris):
            if SEV[sev] < min_sev:
                continue
            key = (e["ip"], rule)
            if dedup.get(key) is not None and e["ts"] - dedup[key] < 60:
                continue
            dedup[key] = e["ts"]
            ts_s = datetime.fromtimestamp(e["ts"]).strftime("%Y-%m-%dT%H:%M:%S") if e["ts"] else "UNKNOWN"
            print(f"[{ts_s}] [{stage}] [{att}] [{sev.upper()}] [{rule}] src={e['ip']} bytes={e['bytes']} | {e['raw']}")
            counts[stage] += 1
            techs.add(att)
            ips_seen.add(e["ip"])
            if stage == "MemoryDisclosure":
                bleed += e["bytes"]
            if SEV[sev] > SEV[peak]:
                peak = sev
            if sev == "high":
                high_hit = True

    print("\n--- SUMMARY ---")
    for s, c in counts.items():
        print(f"  {s}: {c} hit(s)")
    if not counts:
        print("  No findings at selected severity threshold.")
    print(f"  ATT&CK techniques: {', '.join(sorted(techs)) or 'none'}")
    print(f"  Unique attacker IPs: {len(ips_seen)}")
    print(f"  Memory-bleed bytes attributed: {bleed}")
    print(f"  Peak severity: {peak.upper()}")
    sys.exit(1 if high_hit else 0)


if __name__ == "__main__":
    main()