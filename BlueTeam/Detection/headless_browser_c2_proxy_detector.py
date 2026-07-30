"""
headless_browser_c2_proxy_detector.py - Detects headless Chrome/Edge C2 proxy implants and
msaRAT pre-encryptor behaviors in Windows process-creation log exports.

Usage:
    python headless_browser_c2_proxy_detector.py sysmon.log
    python headless_browser_c2_proxy_detector.py events.csv --iocs extra.json --severity high
    python headless_browser_c2_proxy_detector.py process.txt --severity medium

Exit code 1 on any high-severity match.
"""

import argparse, json, re, sys
from collections import defaultdict

NON_USER_PARENTS = {"svchost","wscript","cscript","powershell","mshta","wmiprvse","regsvr32","taskhost","taskeng","services"}
HEADLESS_FLAGS   = {"--headless","--headless=new","--disable-gpu","--remote-debugging-port"}
BROWSER_IMAGES   = {"chrome.exe","msedge.exe"}
REG_KEYS         = {"currentversion\\run","wow6432node\\microsoft\\windows\\currentversion\\run"}
SHADOW_PATS      = [r"vssadmin\s+list\s+shadows", r"wmic\s+shadowcopy", r"bcdedit.*recoveryenabled"]
SEV_RANK         = {"low":0,"medium":1,"high":2}

LOG_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})"
    r".*?(?:ParentImage|Creator Process Name)[:\s=]+(?P<parent>\S+)"
    r".*?(?:(?<!Parent)Image|New Process Name)[:\s=]+(?P<image>\S+)"
    r".*?(?:CommandLine|Process Command Line)[:\s=]+(?P<cmd>.+)",
    re.IGNORECASE | re.DOTALL,
)

def _base(p): return re.sub(r'.*[/\\]', '', p).strip('"').lower()

def parse_log_entries(path):
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip()
            if not line or line.startswith("#"):
                continue
            m = LOG_RE.search(line)
            if m:
                out.append({"ts": m["ts"], "parent": _base(m["parent"]),
                            "image": _base(m["image"]),
                            "cmd": m["cmd"].strip().strip('"').lower(), "line": line})
                continue
            cols = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', line)
            cols = [c.strip().strip('"') for c in cols]
            if len(cols) >= 6 and re.match(r'\d{4}', cols[1]):
                out.append({"ts": cols[1], "parent": _base(cols[4]),
                            "image": _base(cols[5]),
                            "cmd": (cols[8] if len(cols) > 8 else "").lower(), "line": line})
    return out

def match_rules(entries, nu_parents, hl_flags, reg_keys, shadow_pats, min_sev):
    findings, dedup, spawned = [], defaultdict(set), set()
    for e in entries:
        img, par, cmd, ts, ln = e["image"], e["parent"], e["cmd"], e["ts"], e["line"]
        is_browser = img in BROWSER_IMAGES
        has_rdp    = "--remote-debugging-port" in cmd
        hits = []

        if is_browser and any(f in cmd for f in hl_flags) and par in nu_parents:
            spawned.add(par)
            hits.append(("BrowserSpawn", "headless_browser_non_user_parent", "high", "T1218/T1059"))

        if is_browser and has_rdp:
            if re.search(r"(?:0\.0\.0\.0|127\.0\.0\.1|localhost)", cmd):
                hits.append(("C2Proxy", "remote_debug_loopback_bind", "high", "T1071.001/T1090"))
            if re.search(r"devtools[/\\]", cmd):
                hits.append(("C2Proxy", "devtools_socket_path", "high", "T1071.001/T1090"))
            if "--user-data-dir" in cmd and re.search(r"(?:\\temp\\|\\appdata\\)", cmd):
                hits.append(("C2Proxy", "browser_temp_userdata", "medium", "T1071.001"))

        if re.search(r"reg(?:\.exe)?\s+add", cmd) and any(k in cmd for k in reg_keys):
            if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', cmd):
                hits.append(("PreEncryptor", "msa_reg_run_b64", "high", "T1547.001"))

        if "lsass" in cmd and is_browser:
            hits.append(("PreEncryptor", "lsass_access_browser", "high", "T1003.001"))

        if spawned and any(re.search(p, cmd) for p in shadow_pats):
            hits.append(("PreEncryptor", "shadow_copy_enum", "high", "T1490"))

        for stage, rule, sev, tech in hits:
            if SEV_RANK.get(sev, 0) < SEV_RANK[min_sev]:
                continue
            dk = f"{par}:{rule}:{ts[:16]}"
            if dk in dedup[stage]:
                continue
            dedup[stage].add(dk)
            findings.append({"stage": stage, "rule": rule, "severity": sev,
                             "technique": tech, "ts": ts, "parent": par, "image": img, "line": ln})
    return findings

def report_findings(findings):
    counts, techs, ptids, peak = defaultdict(int), set(), set(), "low"
    for f in findings:
        print(f"[{f['ts']}] [{f['stage']}] [{f['technique']}] [{f['severity'].upper()}] "
              f"{f['rule']} | parent={f['parent']} image={f['image']}")
        print(f"  >> {f['line'][:200]}")
        counts[f["stage"]] += 1
        techs.add(f["technique"])
        ptids.add(f"{f['parent']}:{f['image']}")
        if SEV_RANK[f["severity"]] > SEV_RANK[peak]:
            peak = f["severity"]
    print("\n--- Summary ---")
    for stage, cnt in sorted(counts.items()):
        print(f"  {stage}: {cnt} hit(s)")
    print(f"  ATT&CK techniques: {', '.join(sorted(techs)) or 'none'}")
    print(f"  Unique process trees: {len(ptids)} | Peak severity: {peak.upper()}")
    return peak == "high"

def main():
    ap = argparse.ArgumentParser(description="Headless Browser C2 Proxy & msaRAT Pre-Encryptor Detector")
    ap.add_argument("log_file", help="Sysmon plaintext or Security Event 4688 CSV log path")
    ap.add_argument("--iocs", help="Supplemental IOC JSON (non_user_parents, headless_flags, reg_keys, shadow_cmds)")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum alert severity to emit (default: low)")
    args = ap.parse_args()

    nu_parents  = set(NON_USER_PARENTS)
    hl_flags    = set(HEADLESS_FLAGS)
    reg_keys    = set(REG_KEYS)
    shadow_pats = list(SHADOW_PATS)

    if args.iocs:
        try:
            with open(args.iocs) as fh:
                d = json.load(fh)
            nu_parents.update(s.lower()  for s in d.get("non_user_parents", []))
            hl_flags.update(s.lower()    for s in d.get("headless_flags", []))
            reg_keys.update(s.lower()    for s in d.get("reg_keys", []))
            shadow_pats.extend(d.get("shadow_cmds", []))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[WARN] IOC load failed: {exc}", file=sys.stderr)

    try:
        entries = parse_log_entries(args.log_file)
    except OSError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(2)

    findings = match_rules(entries, nu_parents, hl_flags, reg_keys, shadow_pats, args.severity)
    if not findings:
        print("No matches.")
        sys.exit(0)
    sys.exit(1 if report_findings(findings) else 0)

if __name__ == "__main__":
    main()