#!/usr/bin/env python3
"""FortiGate VPN Credential Dump Reuse & Inc/Lynx Staging Detector

Usage:
    python fortigate_credential_reuse_detector.py auth.log
    python fortigate_credential_reuse_detector.py auth.log --iocs extra.json --severity medium

Example log line (syslog KV):
    2024-01-15T02:31:00 devname=FGT60E logid=0101039426 type=event subtype=vpn
    action=ssl-login-fail user=jsmith srcip=198.51.100.5 msg="SSL user failed to logged in"
"""
import argparse, json, re, sys
from collections import defaultdict
from datetime import datetime

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

BUNDLED = {
    "dumped_users": ["admin", "test", "vpnuser", "sslvpn", "fortinet", "guest", "user1", "cisco", "svc_vpn"],
    "bad_ips": ["185.220.101.", "45.142.212.", "91.108.4.", "194.165.16.", "185.220.100.", "185.130.5."],
    "c2_ips": ["45.9.148.", "194.40.243.", "185.234.218.", "91.92.109.", "87.251.64.", "45.61.136."],
}

KV_RE = re.compile(r'(\w+)=(".*?"|[^\s]+)')

def parse_ts(s):
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S", "%Y-%m-%dT%H:%M:%S+%f"):
        try:
            return datetime.strptime(s[:19], fmt)
        except ValueError:
            pass
    return None

def parse_line(line, csv_keys):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if csv_keys:
        parts = line.split(",")
        if len(parts) < len(csv_keys):
            return None
        d = dict(zip(csv_keys, parts))
        ts = parse_ts(d.get("date", "") + "T" + d.get("time", ""))
        return {"ts": ts, "src": d.get("srcip", d.get("src", "")),
                "user": d.get("user", d.get("username", "")), "action": d.get("action", ""), "raw": line}
    kvs = dict(KV_RE.findall(line))
    if not kvs:
        return None
    ts = parse_ts(kvs.get("date", "") + "T" + kvs.get("time", "")) or parse_ts(line[:19])
    return {"ts": ts, "src": kvs.get("srcip", kvs.get("src", "")),
            "user": kvs.get("user", kvs.get("username", "")), "action": kvs.get("action", ""), "raw": line}

def load_iocs(path, iocs):
    try:
        with open(path) as f:
            data = json.load(f)
        for k in ("dumped_users", "bad_ips", "c2_ips"):
            if k in data:
                if not isinstance(data[k], list):
                    print(f"[WARN] IOC field '{k}' is not a list, skipping", file=sys.stderr)
                    continue
                if not all(isinstance(v, str) for v in data[k]):
                    print(f"[WARN] IOC field '{k}' contains non-string values, filtering", file=sys.stderr)
                    data[k] = [v for v in data[k] if isinstance(v, str)]
                iocs[k] = list(set(iocs[k] + data[k]))
    except Exception as e:
        print(f"[WARN] IOC load failed: {e}", file=sys.stderr)

def ip_matches(ip, prefixes):
    for p in prefixes:
        if not p.endswith("."):
            print(f"[WARN] IOC prefix '{p}' does not end with '.', skipping", file=sys.stderr)
            continue
        if ip.startswith(p):
            return True
    return False

def check_rules(entry, state, iocs):
    hits = []
    ts, src = entry["ts"], entry["src"]

    if ts is None:
        return hits

    now = ts.timestamp()
    user, action = entry["user"].lower(), entry["action"].lower()

    if user in [u.lower() for u in iocs["dumped_users"]]:
        hits.append(("CredentialReuse", "T1078", "high", "FortiBleed-ExposedAccount"))
    if ip_matches(src, iocs["bad_ips"]):
        hits.append(("CredentialReuse", "T1552", "high", "KnownBadSourceIP"))
    fails = state["fails"][src]
    fails[:] = [t for t in fails if now - t < 300]
    if "fail" in action or "error" in action:
        fails.append(now)
    elif ("success" in action or "login" in action) and len(fails) >= 3:
        hits.append(("CredentialReuse", "T1078", "high", "SuccessAfterFailureBurst"))
        fails.clear()

    if ts.hour < 6 or ts.hour >= 22:
        hits.append(("VPNAuthAnomaly", "T1078", "medium", "OffHoursLogin"))
    burst = state["burst"][src]
    burst[:] = [t for t in burst if now - t < 60]
    burst.append(now)
    if len(burst) >= 10:
        hits.append(("VPNAuthAnomaly", "T1110", "medium", "CredentialStuffingBurst"))
        burst.clear()
    seen = state["user_src"][user]
    if len(seen) >= 2 and src not in seen:
        hits.append(("VPNAuthAnomaly", "T1078", "medium", "SourceShiftAnomaly"))
    seen.add(src)

    if ip_matches(src, iocs["c2_ips"]):
        hits.append(("RansomwareStaging", "T1486", "high", "IncLynxC2Contact"))
    session_start = state["sessions"].get(user)
    if "success" in action or "login" in action:
        if session_start and now - session_start > 14400:
            hits.append(("RansomwareStaging", "T1021", "high", "AbnormalSessionPersistence"))
        state["sessions"][user] = now
    recon = state["recon"][src]
    recon[:] = [t for t in recon if now - t < 120]
    recon.append(now)
    if len(recon) >= 15:
        hits.append(("RansomwareStaging", "T1021", "medium", "ReconBeaconCadence"))
        recon.clear()

    return hits

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log_file", help="Path to FortiGate VPN auth log (syslog KV or CSV)")
    ap.add_argument("--iocs", help="Supplemental IOC JSON with dumped_users, bad_ips, c2_ips lists")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum alert severity to emit (default: low)")
    args = ap.parse_args()

    iocs = {k: list(v) for k, v in BUNDLED.items()}
    if args.iocs:
        load_iocs(args.iocs, iocs)

    min_sev = SEVERITY_ORDER[args.severity]
    state = {"fails": defaultdict(list), "burst": defaultdict(list),
             "user_src": defaultdict(set), "sessions": {}, "recon": defaultdict(list)}
    dedup, counts = {}, defaultdict(int)
    techs, flagged_ips, flagged_users = set(), set(), set()
    peak, exit_code, csv_keys = "low", 0, None

    try:
        fh = open(args.log_file, errors="replace")
    except OSError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(2)

    with fh:
        for raw in fh:
            if csv_keys is None and "," in raw and "=" not in raw:
                csv_keys = [h.strip().lower() for h in raw.split(",")]
                continue
            entry = parse_line(raw, csv_keys)
            if not entry:
                continue
            for stage, tech, sev, rule in check_rules(entry, state, iocs):
                if SEVERITY_ORDER[sev] < min_sev:
                    continue
                key = (stage, rule, entry["src"], entry["user"])
                now = entry["ts"].timestamp()
                if key in dedup and now - dedup[key] < 60:
                    continue
                dedup[key] = now
                ts_str = entry["ts"].isoformat() if entry["ts"] else "unknown"
                print(f"[{ts_str}] STAGE={stage} ATT&CK={tech} SEV={sev.upper()} "
                      f"RULE={rule} SRC={entry['src']} USER={entry['user']} | {entry['raw'][:120]}")
                counts[stage] += 1
                techs.add(tech)
                flagged_ips.add(entry["src"])
                flagged_users.add(entry["user"])
                if SEVERITY_ORDER[sev] > SEVERITY_ORDER[peak]:
                    peak = sev
                if sev == "high":
                    exit_code = 1

    print("\n--- Summary ---")
    for s, c in counts.items():
        print(f"  {s}: {c} hit(s)")
    print(f"  ATT&CK techniques: {', '.join(sorted(techs)) or 'none'}")
    print(f"  Unique flagged IPs: {len(flagged_ips)}  Usernames: {len(flagged_users)}")
    print(f"  Peak severity: {peak.upper()}")
    sys.exit(exit_code)

if __name__ == "__main__":
    main()