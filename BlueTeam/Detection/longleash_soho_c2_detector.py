#!/usr/bin/env python3
"""
LongLeash / DogLeash / JarLeash SOHO Router C2 & Persistence Detector

Scans plain-text SOHO router syslog exports for IOCs tied to LongLeash,
DogLeash, and JarLeash implant families across three kill-chain stages with
MITRE ATT&CK technique attribution to support immediate network defender triage.

Usage:
    python longleash_soho_c2_detector.py router.log
    python longleash_soho_c2_detector.py router.log --iocs extra_iocs.json --severity high
"""

import argparse, json, re, sys
from collections import defaultdict
from datetime import datetime

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}
_PRIV = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.0\.)")

RULES = [
    ("C2Establishment", "T1071", "high", "LongLeash_Beacon_URI",
     lambda e, x: bool(re.search(r"/api/v\d+/status|/check-?in(\?|$)", e["raw"]) or any(u in e["raw"] for u in x.get("uris", []))),
    ("C2Establishment", "T1571", "high", "DogLeash_AltPort_Handshake",
     lambda e, x: e["dpt"] in {"4443", "8443"} and int(e["len"] or 999) < 200),
    ("C2Establishment", "T1071", "high", "JarLeash_Java_UA",
     lambda e, x: bool(re.search(r"Java/\d", e["raw"])) or any(ua in e["raw"] for ua in x.get("useragents", []))),
    ("C2Establishment", "T1071", "high", "JarLeash_Campaign_Domain",
     lambda e, x: bool(re.search(r"update-cdn\.net|telemetry-push\.com|svc-check\.org", e["dst"])) or any(h in e["dst"] for h in x.get("hostnames", []))),
    ("C2Communication", "T1041", "high", "LongLeash_LowBW_LongSession",
     lambda e, x: bool(e["dpt"]) and e["dpt"] not in {"80", "443", "53", "22"} and int(e["len"] or 999) < 150 and e["dst"] and not _PRIV.match(e["dst"])),
    ("C2Communication", "T1041", "medium", "DogLeash_Fixed_Interval_Poll",
     lambda e, x: e["dpt"] in {"4443", "8443"} or any(ip in e["dst"] for ip in x.get("ips", []))),
    ("C2Communication", "T1048", "medium", "JarLeash_Subdomain_Exfil",
     lambda e, x: bool(re.search(r"[a-f0-9]{12,}\.[a-z0-9-]+\.(com|net|org|io)$", e["dst"]))),
    ("Persistence", "T1053", "high", "Cron_Outbound_Spawn",
     lambda e, x: bool(re.search(r"cron[d ].*(wget|curl|sh\s+-c)|CRON.*CMD.*(wget|curl|nc\b|bash)", e["raw"], re.I))),
    ("Persistence", "T1098", "high", "SSH_AuthKey_Write",
     lambda e, x: bool(re.search(r"authorized_keys|Accepted publickey from (?!192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)", e["raw"]))),
    ("Persistence", "T1556", "high", "IPTables_Inbound_Insert",
     lambda e, x: bool(re.search(r"(-I|--insert)\s+INPUT.*ACCEPT|rule inserted.*INPUT.*ACCEPT", e["raw"], re.I))),
]

_TS_FMTS = [
    (re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"), "%Y-%m-%dT%H:%M:%S"),
    (re.compile(r"(\w{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})"), "%b %d %H:%M:%S"),
    (re.compile(r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})"), "%Y/%m/%d %H:%M:%S"),
]

def _first(patterns, line, flags=0):
    for pat in patterns:
        m = re.search(pat, line, flags)
        if m:
            return m.group(1)
    return ""

def parse_entry(line):
    dst = _first([r"DST=([^\s]+)", r"dst=([^\s,]+)", r"(?:to|destination)[:\s]+([0-9a-zA-Z._-]+)"], line, re.I)
    e = {
        "raw": line,
        "ts": None,
        "dst": dst.lower().split(":")[0].rstrip(".,") if dst else "",
        "dpt": _first([r"DPT=(\d+)", r"dport=(\d+)", r"port[:\s]+(\d{2,5})\b"], line),
        "len": _first([r"LEN=(\d+)", r"\blen=(\d+)", r"bytes=(\d+)"], line, re.I),
    }
    for rx, fmt in _TS_FMTS:
        m = rx.search(line)
        if m:
            try:
                e["ts"] = datetime.strptime(m.group(1), fmt)
                break
            except ValueError:
                pass
    return e

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log_file", help="Path to plain-text SOHO router syslog export")
    ap.add_argument("--iocs", metavar="FILE", help="JSON file with extra C2 IPs, hostnames, URIs, user-agents")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum alert severity to emit (default: low)")
    args = ap.parse_args()

    extra = {"ips": [], "hostnames": [], "uris": [], "useragents": []}
    if args.iocs:
        try:
            with open(args.iocs) as f:
                extra.update(json.load(f))
        except Exception as ex:
            print(f"[WARN] IOC file error: {ex}", file=sys.stderr)

    min_sev = SEVERITY_ORDER[args.severity]
    stage_counts = defaultdict(int)
    technique_hits = set()
    unique_dsts = set()
    peak_sev = "low"
    dedup: dict = {}
    high_found = False

    try:
        fh = open(args.log_file)
    except Exception as ex:
        print(f"[ERROR] Cannot open log: {ex}", file=sys.stderr)
        sys.exit(2)

    with fh:
        for line in fh:
            line = line.rstrip()
            if not line:
                continue
            e = parse_entry(line)
            for stage, technique, sev, name, check in RULES:
                if SEVERITY_ORDER[sev] < min_sev:
                    continue
                try:
                    if not check(e, extra):
                        continue
                except Exception:
                    continue
                dst = e["dst"] or "unknown"
                key = (name, dst)
                now = e["ts"]
                prev = dedup.get(key)
                if prev is not None and now is not None and (now - prev).total_seconds() < 120:
                    continue
                dedup[key] = now
                stage_counts[stage] += 1
                technique_hits.add(technique)
                if dst != "unknown":
                    unique_dsts.add(dst)
                if SEVERITY_ORDER[sev] > SEVERITY_ORDER[peak_sev]:
                    peak_sev = sev
                if sev == "high":
                    high_found = True
                ts_str = now.isoformat() if now else "no-timestamp"
                print(f"[{ts_str}] {stage} | {technique} | {sev.upper():<6} | {name:<35} | dst={dst} | {line[:100]}")

    print("\n--- Summary ---")
    for st in ("C2Establishment", "C2Communication", "Persistence"):
        print(f"  {st}: {stage_counts[st]} hit(s)")
    print(f"  ATT&CK techniques covered : {', '.join(sorted(technique_hits)) or 'none'}")
    print(f"  Unique suspicious destinations: {len(unique_dsts)}")
    print(f"  Peak severity: {peak_sev.upper()}")
    sys.exit(1 if high_found else 0)

if __name__ == "__main__":
    main()