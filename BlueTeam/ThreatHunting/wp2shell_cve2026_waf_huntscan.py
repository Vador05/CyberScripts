"""
wp2shell_cve2026_waf_huntscan.py - WAF detection and threat-hunt scanner for CVE-2026-60137 and CVE-2026-63030.

Usage:
    python wp2shell_cve2026_waf_huntscan.py access.log
    python wp2shell_cve2026_waf_huntscan.py access.log --mode hunt --iocs iocs.json
    python wp2shell_cve2026_waf_huntscan.py /var/log/nginx/access.log --mode scan
"""
import argparse, calendar, json, re, sys
from collections import defaultdict
from urllib.parse import unquote

RULES = [
    {"stage":"Exploitation","cve":"CVE-2026-60137","sev":"high","tec":"T1190",
     "method":r"POST|PUT","uri":r"/wp-json/wp/v2/","uri2":r"\.\./|file[_-]?write|filename=","stat":r"20[01]"},
    {"stage":"ShellDeployment","cve":"CVE-2026-63030","sev":"high","tec":"T1505.003",
     "method":r"GET|POST","uri":r"/wp-cron\.php","uri2":r"callback=|[?&]\w{30,}","stat":r"2\d\d"},
    {"stage":"ShellDeployment","cve":"CVE-2026-63030","sev":"high","tec":"T1505.003",
     "method":r"POST|PUT","uri":r"/wp-content/(?:uploads|cache)/[^?]*\.php","stat":r"20[01]"},
    {"stage":"DwellBeacon","cve":"CVE-2026-63030","sev":"high","tec":"T1059.004",
     "method":r"GET","uri":r"/wp-content/(?:uploads|cache)/[^?]*\.php",
     "uri2":r"[?&](?:cmd|exec|eval|shell|system)=","stat":r"200"},
]

TRIAGE = {
    "Exploitation":["1. Block source IPs at WAF immediately","2. Disable anonymous REST API access in wp-config.php",
                    "3. Audit wp-content/ for new PHP files by mtime","4. Rotate all application passwords and API keys"],
    "ShellDeployment":["1. Block source IPs; disable wp-cron.php via .htaccess","2. Remove PHP files from wp-content/uploads and cache",
                       "3. Set DISABLE_WP_CRON=true in wp-config.php","4. Run filesystem integrity check against known-good hashes"],
    "DwellBeacon":["1. Isolate host before remediation to preserve forensic state","2. Capture memory and disk image",
                   "3. Remove shell files; restore wp-content from clean backup","4. Rotate all credentials and regenerate wp-config secret keys"],
}

MO = dict(Jan=1,Feb=2,Mar=3,Apr=4,May=5,Jun=6,Jul=7,Aug=8,Sep=9,Oct=10,Nov=11,Dec=12)
LOG_RE = re.compile(r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<uri>\S+)[^"]*" (?P<stat>\d+) \S+(?: "[^"]*" "(?P<ua>[^"]*)")?')
TS_RE = re.compile(r'(\d+)/(\w+)/(\d+):(\d+):(\d+):(\d+)')
STAGES = ["Exploitation", "ShellDeployment", "DwellBeacon"]


def ts2ep(ts):
    m = TS_RE.search(ts)
    if not m: return 0
    d, mo, y, h, mi, s = m.groups()
    return calendar.timegm((int(y), MO.get(mo, 1), int(d), int(h), int(mi), int(s), 0, 0, 0))


def parse_log_entries(path):
    entries = []
    with open(path, errors="replace") as f:
        for line in f:
            m = LOG_RE.match(line.strip())
            if not m: continue
            g = m.groupdict()
            entries.append({**g, "raw": line.strip(), "ep": ts2ep(g["ts"]), "uri": unquote(g["uri"])})
    return entries


def match_rule(entry, rules, allowlist):
    if entry["ip"] in allowlist: return None
    for r in rules:
        if not re.search(r["method"], entry["method"], re.I): continue
        if not re.search(r["uri"], entry["uri"], re.I): continue
        if "uri2" in r and not re.search(r["uri2"], entry["uri"], re.I): continue
        if not re.search(r["stat"], entry["stat"]): continue
        return r
    return None


def scan_mode(entries, rules, allowlist):
    counts = defaultdict(int); peak = -1; seen = set()
    for e in entries:
        r = match_rule(e, rules, allowlist)
        if not r: continue
        key = (e["ip"], r["stage"], e["uri"][:60])
        if key in seen: continue
        seen.add(key); counts[r["stage"]] += 1
        si = STAGES.index(r["stage"])
        if si > peak: peak = si
        print(f"[{e['ts']}] ALERT stage={r['stage']} cve={r['cve']} sev={r['sev'].upper()} tec={r['tec']} src={e['ip']}")
        print(f"  {e['raw'][:120]}")
    print("\n--- Stage Tally ---")
    for s in STAGES: print(f"  {s}: {counts[s]}")
    if peak >= 0:
        stage = STAGES[peak]
        print(f"\n--- Rapid Triage ({stage}) ---")
        for step in TRIAGE[stage]: print(f"  {step}")
    return peak >= 0


def hunt_mode(entries, rules, allowlist, attacker_ips):
    ip_stages = defaultdict(set); ip_eps = defaultdict(list); shells = defaultdict(lambda: [None, None])
    for e in entries:
        r = match_rule(e, rules, allowlist)
        if not r: continue
        ip = e["ip"]
        ip_stages[ip].add(r["stage"]); ip_eps[ip].append(e["ep"])
        if r["stage"] in ("ShellDeployment", "DwellBeacon"):
            m = re.search(r'/wp-content/[^?#]*\.php', e["uri"])
            if m:
                p = m.group(); sf = shells[p]
                sf[0] = sf[0] or e["ts"]; sf[1] = e["ts"]
    print("--- Shell File IOCs ---")
    for path, (first, last) in sorted(shells.items()):
        print(f"  {path}  first={first}  last={last}")
    print("\n--- Compromise Confidence Scores ---")
    high_conf = []
    for ip in sorted(ip_eps, key=lambda x: -len(ip_eps[x])):
        times = sorted(ip_eps[ip]); stages = ip_stages[ip]
        intervals = [times[i] - times[i-1] for i in range(1, len(times))]
        avg = sum(intervals) / len(intervals) if intervals else 9999
        score = len(stages) * 30 + (40 if avg < 60 else 20 if avg < 1800 else 0) + (20 if ip in attacker_ips else 0)
        beacon = f"avg_interval={avg:.0f}s" if intervals else "single_request"
        print(f"  {ip}  reqs={len(times)}  stages={','.join(sorted(stages))}  {beacon}  confidence={score}")
        if score >= 90: high_conf.append(ip)
    if high_conf:
        print(f"\n[!] High-confidence compromised IPs ({len(high_conf)}): {', '.join(high_conf)}")
    return bool(high_conf)


def main():
    ap = argparse.ArgumentParser(description="WP2Shell CVE-2026-60137/63030 WAF Detection & Threat-Hunt Scanner")
    ap.add_argument("log_file", help="Path to Apache or Nginx combined-format access log")
    ap.add_argument("--iocs", default=None, help="JSON file with attacker_ips, shell_filenames, allowlisted_ips")
    ap.add_argument("--mode", choices=["scan", "hunt"], default="scan", help="scan: active exploitation alerts; hunt: dwell-time IOC inventory")
    args = ap.parse_args()

    rules = list(RULES); allowlist = set(); attacker_ips = set()
    if args.iocs:
        try:
            with open(args.iocs) as f: ioc = json.load(f)
            allowlist.update(ioc.get("allowlisted_ips", []))
            attacker_ips.update(ioc.get("attacker_ips", []))
            fnames = ioc.get("shell_filenames", [])
            if fnames:
                rules.append({"stage":"ShellDeployment","cve":"IOC","sev":"high","tec":"T1505.003",
                               "method":r".*","uri":"(?:" + "|".join(re.escape(fn) for fn in fnames) + ")","stat":r".*"})
        except Exception as e:
            print(f"[warn] IOC load failed: {e}", file=sys.stderr)

    try:
        entries = parse_log_entries(args.log_file)
    except OSError as e:
        print(f"[error] {e}", file=sys.stderr); sys.exit(2)

    found = scan_mode(entries, rules, allowlist) if args.mode == "scan" else hunt_mode(entries, rules, allowlist, attacker_ips)
    sys.exit(1 if found else 0)


if __name__ == "__main__":
    main()