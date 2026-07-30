"""
fastjson_cve16723_waf_detector.py - CVE-2026-16723 Fastjson 1.x RCE WAF & Sigma detection scanner.

Usage:
    python fastjson_cve16723_waf_detector.py access.log
    python fastjson_cve16723_waf_detector.py access.log --iocs iocs.json --severity medium
    python fastjson_cve16723_waf_detector.py /var/log/nginx/access.log --severity high
"""
import argparse, calendar, json, re, sys
from collections import defaultdict
from urllib.parse import unquote

SEV_RANK = {"low": 0, "medium": 1, "high": 2}
STAGES = {
    "Probe":           {"sigma": "sigma-fj-cve-2026-16723-probe-001",    "tec": "T1590",     "sev": "medium"},
    "JNDIInjection":   {"sigma": "sigma-fj-cve-2026-16723-jndi-002",     "tec": "T1190",     "sev": "high"},
    "CallbackConfirm": {"sigma": "sigma-fj-cve-2026-16723-callback-003", "tec": "T1059.007", "sev": "high"},
}
MO = dict(Jan=1,Feb=2,Mar=3,Apr=4,May=5,Jun=6,Jul=7,Aug=8,Sep=9,Oct=10,Nov=11,Dec=12)
ACTUATOR_RE = re.compile(r"/actuator/(env|beans|health|info|mappings|configprops)", re.I)
GADGET_RE   = re.compile(r"JdbcRowSetImpl|TemplatesImpl|BasicDataSource|JndiDataSourceFactory", re.I)
JNDI_RE     = re.compile(r"jndi:(ldap|rmi|dns)://", re.I)
AT_TYPE_RE  = re.compile(r"@type\s*[:\"]", re.I)
FASTJSON_RE = re.compile(r"fastjson|application/json", re.I)
LOG_RE = re.compile(r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<uri>\S+)[^"]*" (?P<stat>\d+) \S+(?: "[^"]*" "(?P<ua>[^"]*)")?')
TS_RE  = re.compile(r'(\d+)/(\w+)/(\d+):(\d+):(\d+):(\d+)')
TRIAGE = [
    "1. Enable safeMode: ParserConfig.getGlobalInstance().setSafeMode(true) at Spring Boot startup",
    "2. Refresh AutoType denyList via fastjson-denylist.properties or upgrade off Fastjson 1.x",
    "3. Restrict actuator: management.endpoints.web.exposure.include=health in application.properties",
    "4. Block attacker IPs at WAF; rotate credentials reachable via JNDI callback targets",
    "5. Redact raw JNDI callback URIs before forwarding logs — may expose internal network topology",
]


def ts2ep(ts):
    m = TS_RE.search(ts)
    if not m: return None
    d, mo, y, h, mi, s = m.groups()
    mo_int = MO.get(mo)
    if mo_int is None: return None
    return calendar.timegm((int(y), mo_int, int(d), int(h), int(mi), int(s), 0, 0, 0))


def normalize(s):
    s = unquote(unquote(s))
    for fr, to in [("\\u0040","@"),("\\u003a",":"),("\\u006c\\u0064\\u0061\\u0070","ldap"),
                   ("\\u0072\\u006d\\u0069","rmi"),("\\u0064\\u006e\\u0073","dns")]:
        s = s.replace(fr, to)
    return s


def parse_log_entries(path):
    out = []
    with open(path, errors="replace") as f:
        for line in f:
            m = LOG_RE.match(line.strip())
            if not m: continue
            g = m.groupdict()
            ep = ts2ep(g["ts"])
            if ep is None: continue
            g.update(ep=ep, raw=line.strip(),
                     norm_uri=normalize(g["uri"]), norm_ua=normalize(g.get("ua") or ""))
            out.append(g)
    return out


def load_iocs(path):
    with open(path) as f:
        return json.load(f)


def match_rules(entries, iocs, min_sev):
    extra_ips     = set(iocs.get("attacker_ips", []))
    extra_domains = set(iocs.get("jndi_domains", []))
    extra_g       = iocs.get("gadgets", [])
    gadget_re = re.compile(GADGET_RE.pattern + ("|" + "|".join(re.escape(g) for g in extra_g) if extra_g else ""), re.I)

    jndi_hits = defaultdict(list)
    dedup     = {}
    alerts    = []

    for e in entries:
        ip, ep, stat = e["ip"], e["ep"], e["stat"]
        uri, ua = e["norm_uri"], e["norm_ua"]
        combined = uri + " " + ua
        stage = None

        if ACTUATOR_RE.search(uri) and (FASTJSON_RE.search(ua) or ip in extra_ips):
            stage = "Probe"

        if JNDI_RE.search(combined) or AT_TYPE_RE.search(combined) or gadget_re.search(combined) or any(d in combined for d in extra_domains):
            stage = "JNDIInjection"
            jndi_hits[ip].append(ep)

        if stage is None and stat in ("200", "302") and ip in jndi_hits:
            if any(ep - t <= 60 for t in jndi_hits[ip]) and not gadget_re.search(combined) and not ACTUATOR_RE.search(uri):
                stage = "CallbackConfirm"

        if not stage:
            continue
        info = STAGES[stage]
        if SEV_RANK[info["sev"]] < SEV_RANK[min_sev]:
            continue
        key = (ip, stage)
        if ep - dedup.get(key, 0) < 30:
            continue
        dedup[key] = ep
        alerts.append({**info, "stage": stage, "ip": ip, "ts": e["ts"], "raw": e["raw"]})
    return alerts


def report_findings(alerts):
    counts   = defaultdict(int)
    ips      = set()
    has_high = False
    for a in alerts:
        print(f"[{a['ts']}] ALERT stage={a['stage']} sev={a['sev']} sigma={a['sigma']} tec={a['tec']} src={a['ip']}\n  >> {a['raw']}")
        counts[a["stage"]] += 1
        ips.add(a["ip"])
        has_high = has_high or a["sev"] == "high"
    print("\n=== CVE-2026-16723 Detection Summary ===")
    for s in ["Probe", "JNDIInjection", "CallbackConfirm"]:
        print(f"  {s}: {counts[s]} alert(s)")
    print(f"  Unique attacker IPs: {len(ips)}")
    print("\n=== Spring Boot Fastjson 1.x Triage Checklist ===")
    for item in TRIAGE: print(f"  {item}")
    return has_high


def main():
    ap = argparse.ArgumentParser(description="CVE-2026-16723 Fastjson 1.x RCE WAF & Sigma Detection Scanner")
    ap.add_argument("log_file", help="Path to combined-format HTTP access log")
    ap.add_argument("--iocs", help="JSON file with attacker_ips, gadgets, jndi_domains lists")
    ap.add_argument("--severity", choices=["low","medium","high"], default="low", help="Minimum alert severity (default: low)")
    args = ap.parse_args()
    iocs = {}
    if args.iocs:
        try:
            iocs = load_iocs(args.iocs)
        except Exception as e:
            print(f"[WARN] Failed to load IOCs: {e}", file=sys.stderr)
    try:
        entries = parse_log_entries(args.log_file)
    except OSError as e:
        print(f"[ERROR] Cannot read log file: {e}", file=sys.stderr)
        sys.exit(2)
    alerts = match_rules(entries, iocs, args.severity)
    sys.exit(1 if report_findings(alerts) else 0)


if __name__ == "__main__":
    main()