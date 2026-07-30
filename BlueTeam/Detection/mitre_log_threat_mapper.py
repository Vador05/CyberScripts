"""
MITRE ATT&CK Log Threat Mapper — BlueTeam/Detection

Maps syslog, Apache/Nginx, SSH auth.log, and Windows security event text to
MITRE ATT&CK techniques with plain-English summaries for tier-1 SOC triage.

Usage:
    python mitre_log_threat_mapper.py auth.log
    python mitre_log_threat_mapper.py access.log --severity medium
    python mitre_log_threat_mapper.py syslog.txt --techniques extra.json

--techniques JSON: [{"id":"T1190","tactic":"Initial Access","severity":"high","pattern":"<regex>","description":"..."}]
"""
import argparse, json, re, sys
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import unquote

SEV = {"low": 0, "medium": 1, "high": 2}
SIGS = [
    ("T1190",    "Initial Access",       "high",   r"(?:\.php\?|/cgi-bin/|union.select|<script|%3cscript|eval\(|/etc/passwd|\.\./\.\./)","Exploit probe URI — attacker testing vulnerable web endpoints to gain initial foothold."),
    ("T1078",    "Initial Access",       "medium", r"Accepted (?:password|publickey) for root","Root login accepted — valid account may be reused by attacker from an anomalous source."),
    ("T1059",    "Execution",            "high",   r"(?:/bin/(?:ba)?sh|cmd\.exe|powershell|python\s+-c|perl\s+-e|wget\s+https?|curl\s+https?)","Scripting engine invoked — attacker likely executing commands via an interpreter on the target."),
    ("T1203",    "Execution",            "medium", r"\.(?:doc[xm]?|xls[xm]?|rtf|pdf)\?","Document-exploit staging URI — malicious document may trigger code execution on a victim host."),
    ("T1505.003","Persistence",          "high",   r"(?:webshell|c99\.php|r57\.php|b374k|/uploads/[^\s]+\.php|/tmp/[^\s]+\.php)","Web shell path — attacker may have planted a persistent backdoor on the web server."),
    ("T1136",    "Persistence",          "medium", r"(?:useradd|adduser|net user .*/add|New-LocalUser)","Account creation event — new user account may grant attacker persistent access to the system."),
    ("T1068",    "Privilege Escalation", "high",   r"(?:kernel exploit|local root|CVE-\d{4}-\d{4,}|dirty.?cow|polkit)","Local exploit pattern — attacker may be escalating privileges via a known vulnerability."),
    ("T1548",    "Privilege Escalation", "medium", r"(?:chmod [4-7][0-7]{2,}|sudo -l\b|NOPASSWD|suid bit)","SUID/sudo abuse — misconfigured permissions being exploited to gain elevated privileges."),
    ("T1110",    "Credential Access",    "high",   r"(?:Failed password|authentication failure|Invalid user|FAILED LOGIN|failed logon|failed to log)","Repeated auth failure — likely brute-force or credential-stuffing attack in progress."),
    ("T1003",    "Credential Access",    "high",   r"(?:mimikatz|lsass\.exe|procdump|secretsdump|hashdump|ntds\.dit|/etc/shadow)","Credential dumping tool — attacker harvesting stored credentials for lateral movement."),
    ("T1046",    "Discovery",            "medium", r"(?:\bnmap\b|masscan|zmap|nikto|gobuster|\bdirb\b|port.?scan)","Port scan activity — attacker mapping network topology to find exploitable services."),
    ("T1083",    "Discovery",            "medium", r"(?:\.\./|%2e%2e%2f|%252e%252e|/proc/self/|/var/log/|/windows/system32)","Directory traversal probe — attacker attempting to read sensitive files outside the web root."),
    ("T1021",    "Lateral Movement",     "medium", r"(?:\brdp\b|psexec|wmiexec|winrm|xfreerdp|smbclient)","Remote service auth detected — possible lateral movement between internal hosts."),
    ("T1550",    "Lateral Movement",     "high",   r"(?:pass.the.hash|overpass.the.hash|ntlm.relay|ntlmrelayx)","Pass-the-hash indicator — attacker reusing captured credential hashes without a plaintext password."),
    ("T1071",    "Command and Control",  "medium", r"(?:/beacon|/check.in|/gate\.php|/submit\.php|/heartbeat|/tasks\.php)","C2 beacon URI — compromised host polling attacker-controlled command-and-control server."),
    ("T1048",    "Exfiltration",         "high",   r"(?:bytes_sent|content.length)[^\d]*[5-9]\d{5,}|(?<!\d)[1-9]\d{7,}(?!\d)","Large outbound transfer — significant data volume may indicate active data exfiltration."),
]
_APACHE  = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)[^"]*"\s+(\d+)\s+(\S+)')
_SYSLOG  = re.compile(r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+\S+?(?:\[\d+\])?:\s+(.*)')
_WINLINE = re.compile(r'(?:Event.?ID|Security ID|Account Name|Logon Type|Workstation)', re.I)
_ANSI    = re.compile(r'\x1b\[[0-9;]*m')
_IP      = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
_TS      = re.compile(r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})')

def _epoch(ts):
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(ts.strip(), fmt)
            return dt.replace(tzinfo=timezone.utc).timestamp() if not dt.tzinfo else dt.timestamp()
        except ValueError: pass
    return 0.0

def parse_log_entries(path):
    fails = 0
    with open(path, errors="replace") as fh:
        for n, raw in enumerate(fh, 1):
            line = _ANSI.sub("", raw.rstrip())
            if not line or line.startswith("#"): continue
            m = _APACHE.match(line)
            if m:
                yield {"ts": m.group(2), "src": m.group(1),
                       "body": f"{m.group(3)} {unquote(m.group(4))} {m.group(5)} {m.group(6)}", "raw": line}
                continue
            m = _SYSLOG.match(line)
            if m:
                ip = _IP.search(m.group(3)); src = ip.group(1) if ip else m.group(2)
                yield {"ts": m.group(1), "src": src, "body": m.group(3), "raw": line}
                continue
            if _WINLINE.search(line):
                ip = _IP.search(line); ts = _TS.search(line)
                yield {"ts": ts.group(1) if ts else "", "src": ip.group(1) if ip else "unknown",
                       "body": line, "raw": line}
                continue
            fails += 1
            print(f"[WARN] line {n}: unparseable — {line[:80]}", file=sys.stderr)
    if fails: print(f"[INFO] Parse failures: {fails}", file=sys.stderr)

def map_to_attack(entries, sigs, min_sev):
    window = {}
    for e in entries:
        hay = e["body"] + " " + e["raw"]
        ep  = _epoch(e["ts"])
        for tid, tactic, sev, pat, desc in sigs:
            if SEV[sev] < SEV[min_sev]: continue
            if not re.search(pat, hay, re.I): continue
            key = (e["src"], tid)
            if ep - window.get(key, 0) < 60: continue
            window[key] = ep
            yield {**e, "tech": tid, "tactic": tactic, "sev": sev, "desc": desc}

def report_findings(findings):
    counts, srcs, tacs = defaultdict(int), set(), set()
    has_high = False
    for f in findings:
        print(f"[{f['ts']}] src={f['src']} {f['tech']} ({f['tactic']}) [{f['sev'].upper()}]")
        print(f"  WHAT: {f['desc']}")
        print(f"  LOG:  {f['raw'][:120]}")
        counts[f["tech"]] += 1; srcs.add(f["src"]); tacs.add(f["tactic"])
        if f["sev"] == "high": has_high = True
    top5 = sorted(counts, key=lambda k: -counts[k])[:5]
    print("\n=== SUMMARY ===")
    print(f"Top techniques : {', '.join(f'{t}({counts[t]})' for t in top5) or 'none'}")
    print(f"Unique sources : {len(srcs)} — {', '.join(sorted(srcs)[:10])}")
    print(f"Tactic breadth : {len(tacs)}/9 — {', '.join(sorted(tacs))}")
    acts = ["Block or monitor flagged source IPs immediately"]
    if has_high:                    acts.append("Escalate high-severity findings for forensic review")
    if "Lateral Movement"   in tacs: acts.append("Audit adjacent hosts for signs of compromise")
    if "Credential Access"  in tacs: acts.append("Reset affected credentials; audit privilege grants")
    if "Persistence"        in tacs: acts.append("Scan web dirs and accounts for attacker artifacts")
    print("Recommended    : " + "; ".join(f"{i+1}. {a}" for i, a in enumerate(acts)))
    return has_high

def main():
    ap = argparse.ArgumentParser(description="Map log events to MITRE ATT&CK techniques.")
    ap.add_argument("log_file")
    ap.add_argument("--techniques", metavar="JSON")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low")
    args = ap.parse_args()
    sigs = list(SIGS)
    if args.techniques:
        try:
            with open(args.techniques) as fh:
                for t in json.load(fh):
                    sigs.append((t["id"], t["tactic"], t["severity"], t["pattern"], t["description"]))
        except (OSError, KeyError, json.JSONDecodeError) as e:
            print(f"ERROR loading techniques: {e}", file=sys.stderr); sys.exit(2)
    try:
        entries = list(parse_log_entries(args.log_file))
    except OSError as e:
        print(f"ERROR: {e}", file=sys.stderr); sys.exit(2)
    has_high = report_findings(map_to_attack(entries, sigs, args.severity))
    sys.exit(1 if has_high else 0)

if __name__ == "__main__":
    main()