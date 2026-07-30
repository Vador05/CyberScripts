"""
OWAReaper Exchange OWA Module Drop & Void Blizzard TTP Detector

Scans IIS W3C access log exports from Exchange servers for OWAReaper
intrusion-set activity: OWA HttpModule drops, C2 beacon patterns,
and Void Blizzard credential-harvesting TTPs.

Usage:
    python owareaper_exchange_owa_ttp_detector.py exchange_iis.log
    python owareaper_exchange_owa_ttp_detector.py exchange_iis.log --severity high
    python owareaper_exchange_owa_ttp_detector.py exchange_iis.log --iocs iocs.json

Example IOC JSON: {"ips": ["1.2.3.4"], "uri_fragments": ["/evil/path"], "user_agents": ["EvilBot"]}
"""
import argparse, json, re, sys
from collections import defaultdict, deque
from urllib.parse import unquote

W3C_RE = re.compile(r'(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<method>\S+)\s+(?P<stem>\S+)\s+(?P<query>\S+)\s+\S+\s+\S+\s+(?P<ip>\S+)\s+(?P<ua>\S+)\s+(?P<status>\d+)')
DBLENC = re.compile(r'%25(?:2[Ee]|2[Ff]|5[Cc])', re.I)
TRAVERSAL = re.compile(r'(?:%2[Ee]|\.\.)[/%\\]|%00', re.I)
DLL_EXT = re.compile(r'\.(dll|config|aspx|ashx)([\?&]|$)', re.I)
BEACON_UA = re.compile(r'ExchangeServicesClient|OWAReaper|WinHttp.*Exchange|python-requests|curl/', re.I)
RULES = [
    {"name": "OWAModuleDrop-AuthPOST", "stage": "OWAModuleDrop", "technique": "T1505.002", "severity": "high", "method": "POST", "path": re.compile(r'/(?:owa/auth|ecp)/', re.I), "extra": DLL_EXT, "statuses": {"200", "302"}},
    {"name": "OWAModuleDrop-BackdoorAspx", "stage": "OWAModuleDrop", "technique": "T1505.003", "severity": "high", "method": None, "path": re.compile(r'/owa/auth/\w+\.aspx|/ecp/\w+Handler\.ashx', re.I), "extra": None, "statuses": {"200"}},
    {"name": "OWAModuleDrop-Traversal", "stage": "OWAModuleDrop", "technique": "T1505.002", "severity": "high", "method": None, "path": re.compile(r'/(?:owa/auth|ecp)/', re.I), "extra": TRAVERSAL, "statuses": None},
    {"name": "C2Beacon-EvOwa", "stage": "C2Beacon", "technique": "T1071.001", "severity": "high", "method": None, "path": re.compile(r'/owa/ev\.owa', re.I), "extra": re.compile(r'\?[A-Za-z0-9+/=_%-]{8,40}$'), "statuses": {"200"}},
    {"name": "C2Beacon-ServiceSvc", "stage": "C2Beacon", "technique": "T1102", "severity": "high", "method": None, "path": re.compile(r'/owa/service\.svc', re.I), "extra": re.compile(r'[Aa]ction=\w{4,20}$'), "statuses": {"200"}},
    {"name": "C2Beacon-ImplantUA", "stage": "C2Beacon", "technique": "T1071.001", "severity": "high", "method": None, "path": re.compile(r'/owa/', re.I), "extra": BEACON_UA, "statuses": {"200"}, "ua": True},
    {"name": "VoidBlizzard-ECPHarvest", "stage": "VoidBlizzardTTP", "technique": "T1552", "severity": "high", "method": "POST", "path": re.compile(r'/ecp/', re.I), "extra": None, "statuses": {"401", "403", "500"}},
    {"name": "VoidBlizzard-EWSProbe", "stage": "VoidBlizzardTTP", "technique": "T1114", "severity": "high", "method": None, "path": re.compile(r'/ews/', re.I), "extra": None, "statuses": {"401", "200"}},
    {"name": "VoidBlizzard-Autodiscover", "stage": "VoidBlizzardTTP", "technique": "T1078", "severity": "medium", "method": None, "path": re.compile(r'/autodiscover/', re.I), "extra": None, "statuses": {"401", "302", "200"}},
    {"name": "VoidBlizzard-OWASpray", "stage": "VoidBlizzardTTP", "technique": "T1110.003", "severity": "high", "method": "POST", "path": re.compile(r'/owa/auth\.owa', re.I), "extra": None, "statuses": {"403", "302"}},
]
SEV = {"low": 0, "medium": 1, "high": 2}

_SENSITIVE_PARAMS = re.compile(
    r'(?i)([?&])(password|passwd|pwd|secret|token|sessionid|session_id|auth|canary'
    r'|ticket|code|assertion|samlresponse|wctx|wresult|access_token|id_token'
    r'|refresh_token|client_secret)=([^&\s]*)',
)

_OWA_COOKIE_NAMES = re.compile(
    r'(?i)(cadata|cadatattl|X-BackEndCookie|MSExchECP|OutlookSession|UC'
    r'|exchangecookie|oaptoken|FedAuth|rtFa|sessiontoken)=[^;\s&"\']*',
)


def norm(s):
    try:
        s = unquote(unquote(s))
    except Exception:
        pass
    return DBLENC.sub("", s)


# IIS W3C logs encode spaces in URI fields as %20, not +. User-Agent fields
# also use %20 for spaces, so + characters are literal and must be preserved.
# unquote() percent-decodes without touching + characters; unquote_plus() or
# .replace("+", " ") must never be applied to UA values.
def norm_ua(s):
    try:
        s = unquote(s)
    except Exception:
        pass
    return s


def scrub_credentials(s):
    s = re.sub(r'(?i)(Authorization:\s*Basic\s+)[A-Za-z0-9+/=]+', r'\1[REDACTED]', s)
    s = re.sub(r'(?i)(Bearer\s+)[A-Za-z0-9._\-]+', r'\1[REDACTED]', s)
    s = _SENSITIVE_PARAMS.sub(r'\1\2=[REDACTED]', s)
    s = re.sub(r'(?i)(X-OWA-[A-Za-z0-9_\-]+)[=:][A-Za-z0-9+/=_%.\-]+', r'\1=[REDACTED]', s)
    s = re.sub(r'(?i)(Cookie:\s*)[^\r\n]+', r'\1[REDACTED]', s)
    s = _OWA_COOKIE_NAMES.sub(r'\1=[REDACTED]', s)
    s = re.sub(r'(?i)(https?://)[^:@/\s]+:[^@/\s]+@', r'\1[REDACTED]@', s)
    return s


def parse_line(line, fields):
    if fields:
        parts = line.split()
        if len(parts) < len(fields):
            return None
        d = dict(zip(fields, parts))
        return {"ts": d.get("date", "") + " " + d.get("time", ""), "ip": d.get("c-ip", "-"), "method": d.get("cs-method", "-").upper(),
                "stem": norm(d.get("cs-uri-stem", "-")), "query": norm(d.get("cs-uri-query", "-")), "status": d.get("sc-status", "-"), "ua": norm_ua(d.get("cs(User-Agent)", "-"))}
    m = W3C_RE.match(line)
    if not m:
        return None
    return {"ts": m["date"] + " " + m["time"], "ip": m["ip"], "method": m["method"].upper(), "stem": norm(m["stem"]), "query": norm(m["query"]), "status": m["status"], "ua": norm_ua(m["ua"])}


def check_rules(e, drop_ips, iocs):
    uri = e["stem"] + ("?" + e["query"] if e["query"] not in ("-", "") else "")
    hits = []
    for r in RULES:
        if r["method"] and e["method"] != r["method"]: continue
        if not r["path"].search(e["stem"]): continue
        if r["statuses"] and e["status"] not in r["statuses"]: continue
        if r["extra"] and not r["extra"].search(e["ua"] if r.get("ua") else uri): continue
        hits.append(r)
    if e["ip"] in drop_ips and re.search(r'/ews/', e["stem"], re.I):
        hits.append({"name": "VoidBlizzard-CrossStageLateral", "stage": "VoidBlizzardTTP", "technique": "T1078", "severity": "high"})
    if e["ip"] in iocs.get("ips", set()):
        hits.append({"name": "IOC-AttackerIP", "stage": "VoidBlizzardTTP", "technique": "T1078", "severity": "high"})
    for frag in iocs.get("uri_fragments", []):
        if frag.lower() in uri.lower():
            hits.append({"name": "IOC-URIFragment", "stage": "OWAModuleDrop", "technique": "T1505.002", "severity": "high"}); break
    for ua in iocs.get("user_agents", []):
        if ua.lower() in e["ua"].lower():
            hits.append({"name": "IOC-MaliciousUA", "stage": "C2Beacon", "technique": "T1071.001", "severity": "high"}); break
    return hits


def main():
    ap = argparse.ArgumentParser(description="OWAReaper Exchange OWA Module Drop & Void Blizzard TTP Detector")
    ap.add_argument("log_file")
    ap.add_argument("--iocs", help="JSON file with supplemental IOCs (ips, uri_fragments, user_agents)")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low")
    args = ap.parse_args()
    iocs = {"ips": set(), "uri_fragments": [], "user_agents": []}
    if args.iocs:
        try:
            with open(args.iocs) as f: d = json.load(f)
            iocs = {"ips": set(d.get("ips", [])), "uri_fragments": d.get("uri_fragments", []), "user_agents": d.get("user_agents", [])}
        except Exception as ex:
            print(f"[WARN] IOC load failed: {ex}", file=sys.stderr)
    min_sev, stage_counts, techniques, attacker_ips, drop_ips = SEV[args.severity], defaultdict(int), set(), set(), set()
    dedup, peak, fields = defaultdict(lambda: deque(maxlen=60)), "low", None
    try:
        fh = open(args.log_file, errors="replace")
    except OSError as e:
        print(f"[ERROR] {e}", file=sys.stderr); sys.exit(2)
    with fh:
        for raw in fh:
            line = raw.rstrip()
            if line.startswith("#Fields:"): fields = line[8:].split(); continue
            if line.startswith("#") or not line.strip(): continue
            e = parse_line(line, fields)
            if not e: continue
            for r in check_rules(e, drop_ips, iocs):
                if SEV[r["severity"]] < min_sev: continue
                dq = dedup[(e["ip"], r["name"])]
                dq.append(1)
                if len(dq) > 3: continue
                if r["stage"] == "OWAModuleDrop": drop_ips.add(e["ip"])
                stage_counts[r["stage"]] += 1; techniques.add(r["technique"]); attacker_ips.add(e["ip"])
                if SEV[r["severity"]] > SEV[peak]: peak = r["severity"]
                scrubbed_line = scrub_credentials(line)
                print(f"[{e['ts']}] {r['stage']} | {r['technique']} | {r['severity'].upper()} | {r['name']} | src={e['ip']} | {scrubbed_line[:140]}")
    print("\n--- Detection Summary ---")
    for s, c in sorted(stage_counts.items()): print(f"  {s}: {c} hit(s)")
    print(f"  ATT&CK Techniques: {', '.join(sorted(techniques)) or 'none'}")
    print(f"  Unique Attacker IPs: {len(attacker_ips)}")
    print(f"  Peak Severity: {peak.upper()}")
    if peak == "high": sys.exit(1)


if __name__ == "__main__":
    main()