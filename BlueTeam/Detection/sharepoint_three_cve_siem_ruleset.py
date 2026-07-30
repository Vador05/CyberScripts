"""
SharePoint Three-CVE SIEM Detection Rule Set — BlueTeam/Detection

Scans IIS W3C access logs for CVE-2026-45659 (RCE/T1190,T1505.003),
CVE-2026-37986 (EoP/T1068,T1078), and CVE-2026-33078 (SSRF/T1190,T1071.001).

Usage:
    python sharepoint_three_cve_siem_ruleset.py /logs/u_ex260101.log
    python sharepoint_three_cve_siem_ruleset.py access.log --severity medium
    python sharepoint_three_cve_siem_ruleset.py access.log --iocs extra.json --severity low

iocs.json format: {"attacker_ips": ["1.2.3.4"], "uri_fragments": ["/evil/path"]}
"""
import argparse, json, re, sys
from urllib.parse import unquote

SEV = {"low": 0, "medium": 1, "high": 2}
_RFC1918 = re.compile(r"(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)")
RULES = [
    {"cve": "CVE-2026-45659", "stage": "Exploitation",  "tech": "T1190",     "sev": "high",
     "method": "POST",
     "uri": re.compile(r"/(_layouts/15/|_vti_bin/).+\.(aspx|asmx|svc|ashx)", re.I), "extra": None},
    {"cve": "CVE-2026-45659", "stage": "PostExploit",   "tech": "T1505.003", "sev": "high",
     "method": None,
     "uri": re.compile(r"/_layouts/15/(upload|import|sync|cmd|shell|eval|webshell|proxy)", re.I), "extra": None},
    {"cve": "CVE-2026-37986", "stage": "Exploitation",  "tech": "T1068",     "sev": "high",
     "method": None,
     "uri": re.compile(r"/_vti_bin/authentication\.asmx", re.I),
     "extra": re.compile(r"(token=|%3Csaml|saml.*assertion|Bearer\s+[A-Za-z0-9+/]{8,}[^A-Za-z0-9+/=])", re.I)},
    {"cve": "CVE-2026-37986", "stage": "PostExploit",   "tech": "T1078",     "sev": "medium",
     "method": None,
     "uri": re.compile(r"/_api/(web/currentuser|site/owner|roleassignments|userinformation)", re.I), "extra": None},
    {"cve": "CVE-2026-33078", "stage": "Exploitation",  "tech": "T1190",     "sev": "medium",
     "method": None,
     "uri": re.compile(r"/_layouts/15/(getpreview|linkpreview|expandlink|redirect|pagerender)", re.I),
     "extra": _RFC1918},
    {"cve": "CVE-2026-33078", "stage": "PostExploit",   "tech": "T1071.001", "sev": "medium",
     "method": None,
     "uri": re.compile(r"/(_layouts/15/fetch|_api/SP\.Utilities\.Utility|_api/web/getfilebyurl)", re.I),
     "extra": _RFC1918},
]
LOG_RE = re.compile(
    r"^(\d{4}-\d\d-\d\d)\s+(\d\d:\d\d:\d\d)\s+\S+\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s+(\d+)"
)


def parse_entries(path):
    with open(path, errors="replace") as fh:
        for raw in fh:
            raw = raw.rstrip()
            if raw.startswith("#"):
                continue
            m = LOG_RE.match(raw)
            if not m:
                continue
            date, t, method, stem, query, src, ua, status = m.groups()
            uri = unquote(stem) + ("" if query == "-" else "?" + unquote(query))
            yield {"ts": f"{date} {t}", "src": src, "method": method.upper(),
                   "uri": uri, "ua": ua, "status": int(status), "raw": raw}


def check_entry(entry, rules, attacker_ips):
    hits = []
    ctx = entry["uri"] + " " + entry["ua"] + " " + entry["src"]
    for r in rules:
        if r.get("method") and entry["method"] != r["method"]:
            continue
        if not r["uri"].search(entry["uri"]):
            continue
        if r.get("extra") and not r["extra"].search(ctx):
            continue
        hits.append(r)
    if not hits and entry["src"] in attacker_ips:
        hits.append({"cve": "CUSTOM-IOC", "stage": "Exploitation", "tech": "T-IOC", "sev": "medium"})
    return hits


def load_iocs(path):
    with open(path) as fh:
        data = json.load(fh)
    extra = [{"cve": "CUSTOM", "stage": "Exploitation", "tech": "T-CUSTOM", "sev": "medium",
              "uri": re.compile(re.escape(f), re.I), "extra": None}
             for f in data.get("uri_fragments", [])]
    return set(data.get("attacker_ips", [])), extra


def main():
    ap = argparse.ArgumentParser(description="SharePoint three-CVE SIEM detection rule set",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("log_file", help="Path to IIS W3C access log")
    ap.add_argument("--iocs", metavar="FILE", help="Supplemental IOC JSON file")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum alert severity to emit (default: low)")
    args = ap.parse_args()

    attacker_ips, extra_rules = set(), []
    if args.iocs:
        try:
            attacker_ips, extra_rules = load_iocs(args.iocs)
        except Exception as e:
            print(f"[WARN] IOC load failed: {e}", file=sys.stderr)

    rules = RULES + extra_rules
    min_sev, seen = SEV[args.severity], {}
    cve_counts, cve_techs, unique_ips, all_techs, peak = {}, {}, set(), set(), 0

    try:
        entries = list(parse_entries(args.log_file))
    except OSError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(2)

    for entry in entries:
        for r in check_entry(entry, rules, attacker_ips):
            if SEV[r["sev"]] < min_sev:
                continue
            key = (entry["src"], r["cve"], r["tech"], entry["ts"][:16])
            if key in seen:
                continue
            seen[key] = True
            cve = r["cve"]
            cve_counts[cve] = cve_counts.get(cve, 0) + 1
            cve_techs.setdefault(cve, set()).add(r["tech"])
            unique_ips.add(entry["src"])
            all_techs.add(r["tech"])
            peak = max(peak, SEV[r["sev"]])
            print(f"[{entry['ts']}] ALERT {r['cve']} | {r['stage']} | {r['tech']} | "
                  f"SEV={r['sev'].upper()} | src={entry['src']} | {entry['raw']}")

    sev_name = {v: k for k, v in SEV.items()}
    print("\n--- Summary ---")
    print(f"Alerts: {sum(cve_counts.values())} | Peak: {sev_name.get(peak, 'low').upper()} | "
          f"Unique attacker IPs: {len(unique_ips)}")
    print(f"ATT&CK coverage: {', '.join(sorted(all_techs)) or 'none'}")
    for cve in sorted(cve_counts):
        print(f"  {cve}: {cve_counts[cve]} hit(s) — techniques: {', '.join(sorted(cve_techs[cve]))}")
    sys.exit(1 if peak == SEV["high"] else 0)


if __name__ == "__main__":
    main()