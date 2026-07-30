"""
ACR Stealer Browser Vault Access & Token Exfiltration Detector

Scans plain-text Sysmon or EDR log exports for ACR Stealer's browser credential
vault access and authentication token exfiltration patterns, labeling each match
with a MITRE ATT&CK technique, kill-chain stage, and severity.

Usage:
    python acr_stealer_browser_vault_detector.py system.log
    python acr_stealer_browser_vault_detector.py system.log --severity high
    python acr_stealer_browser_vault_detector.py system.log --iocs iocs.json

Example IOC JSON:
    {"domains": ["evil.cc"], "ips": ["1.2.3.4"], "exclude_procs": ["1password.exe"]}
"""
import argparse, json, re, sys
from collections import defaultdict, deque

BROWSER  = {"chrome.exe", "firefox.exe", "msedge.exe"}
CLICKFIX = {"mshta.exe", "wscript.exe", "cscript.exe", "powershell.exe"}
SEV      = {"low": 0, "medium": 1, "high": 2}
VAULT_RE = re.compile(
    r'AppData[/\\]Local[/\\]Google[/\\]Chrome[/\\]User Data[/\\][^|"\']*(?:Login Data|Cookies|Web Data)'
    r'|AppData[/\\]Roaming[/\\]Mozilla[/\\]Firefox[/\\]Profiles[/\\][^|"\']*(?:logins\.json|key4\.db|cookies\.sqlite)'
    r'|AppData[/\\]Local[/\\]Microsoft[/\\]Edge[/\\]User Data[/\\][^|"\']*(?:Login Data|Cookies|Web Data)', re.I)
BPROF_RE = re.compile(
    r'AppData[/\\](?:Local[/\\](?:Google[/\\]Chrome|Microsoft[/\\]Edge)|Roaming[/\\]Mozilla[/\\]Firefox)[/\\]', re.I)
C2DOM_RE = re.compile(r'\.(?:top|xyz|ru|su|pw|cc|ws)(?:\b|$)', re.I)
C2IP_RE  = re.compile(r'^(?:185\.220\.|193\.233\.|91\.215\.|45\.142\.)')
EID_RE   = re.compile(r'(?:EventI[Dd]|event_id)[\s=:]+(\d+)', re.I)
TIME_RE  = re.compile(r'(?:UtcTime|TimeCreated|timestamp)[\s=:]+([^\s,|]+(?:\s[^\s,|]+)?)', re.I)
PROC_RE  = re.compile(r'(?:Image|Process(?!Id)|process_name)[\s=:]+["\']?([^\s"\'|,]+)', re.I)
PAR_RE   = re.compile(r'(?:ParentImage|ParentProcess|parent_process)[\s=:]+["\']?([^\s"\'|,]+)', re.I)
NET_RE   = re.compile(r'(?:DestinationIp|DestinationHostname|dst_ip|dst_host)[\s=:]+["\']?([^\s"\'|,]+)', re.I)

def _f(rx, s): m = rx.search(s); return m.group(1).strip() if m else ""
def bn(p): return re.split(r'[/\\]', p.strip())[-1].lower() if p else ""

def _domain_match(net, domain):
    n, d = net.lower(), domain.lower()
    return n == d or n.endswith('.' + d)

def _ip_match(net, ip_prefix):
    return net.startswith(ip_prefix)

def parse(line):
    pp = _f(PROC_RE, line)
    return {"eid": _f(EID_RE, line), "time": _f(TIME_RE, line), "proc": bn(pp),
            "parent": bn(_f(PAR_RE, line)), "net": _f(NET_RE, line)}

def check(e, line, vault_procs, cf_procs, excl, ioc_d, ioc_i):
    hits = []; eid, proc, parent, net = e["eid"], e["proc"], e["parent"], e["net"]
    if eid == "1" and parent in CLICKFIX:
        cf_procs.add(proc)
    if eid == "11":
        if VAULT_RE.search(line) and proc not in BROWSER and proc not in excl:
            hits.append(("VaultAccess", "T1555.003", "high", "BrowserVaultFileAccess"))
            vault_procs.add(proc)
        if proc in cf_procs and BPROF_RE.search(line):
            hits.append(("TokenHarvest", "T1539", "high", "ClickFixBrowserProfileAccess"))
    if eid == "3" and net:
        vp = proc in vault_procs
        c2 = (any(_domain_match(net, d) for d in ioc_d) or C2DOM_RE.search(net)
              or any(_ip_match(net, i) for i in ioc_i) or C2IP_RE.match(net))
        if vp or c2:
            hits.append(("Exfiltration", "T1041", "high" if vp else "medium",
                         "PostVaultNetworkExfil" if vp else "C2NetworkIndicator"))
    return hits

def main():
    ap = argparse.ArgumentParser(description="Detect ACR Stealer browser vault access and exfiltration in Sysmon/EDR logs.")
    ap.add_argument("log_file", help="Path to plain-text Sysmon or EDR log export")
    ap.add_argument("--iocs", help="JSON file with supplemental domains, ips, and exclude_procs")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum alert severity to emit (default: low)")
    args = ap.parse_args()

    ioc_d, ioc_i, excl = [], [], set(BROWSER)
    if args.iocs:
        try:
            with open(args.iocs) as f:
                d = json.load(f)
            ioc_d, ioc_i = d.get("domains", []), d.get("ips", [])
            excl.update(p.lower() for p in d.get("exclude_procs", []))
        except Exception as e:
            print(f"[WARN] IOC file error: {e}", file=sys.stderr)

    minsev = SEV[args.severity]
    vault_procs, cf_procs = set(), set()
    counts, techs, procs = defaultdict(int), set(), set()
    peak, any_high, recent = "low", False, deque(maxlen=50)

    try:
        with open(args.log_file, errors="replace") as f:
            for n, line in enumerate(f, 1):
                line = line.rstrip()
                if not line or line[0] == "#":
                    continue
                try:
                    e = parse(line)
                except Exception:
                    continue
                for stage, tech, sev, rule in check(e, line, vault_procs, cf_procs, excl, ioc_d, ioc_i):
                    if SEV[sev] < minsev:
                        continue
                    key = (e["proc"], rule)
                    if key in recent:
                        continue
                    recent.append(key)
                    ts = e["time"] or f"line:{n}"
                    print(f"[{ts}] [{stage}] [{tech}] [{sev.upper()}] {rule} proc={e['proc'] or '?'} | {line[:140]}")
                    counts[stage] += 1; techs.add(tech); procs.add(e["proc"] or "?")
                    if SEV[sev] > SEV[peak]:
                        peak = sev
                    if sev == "high":
                        any_high = True
    except (FileNotFoundError, PermissionError) as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(2)

    print("\n--- Summary ---")
    for s, c in sorted(counts.items()):
        print(f"  {s}: {c} hit(s)")
    print(f"  ATT&CK techniques: {', '.join(sorted(techs)) or 'none'}")
    print(f"  Unique suspicious processes: {len(procs)}")
    print(f"  Peak severity: {peak.upper()}")
    sys.exit(1 if any_high else 0)

if __name__ == "__main__":
    main()