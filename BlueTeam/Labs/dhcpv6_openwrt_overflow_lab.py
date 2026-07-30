#!/usr/bin/env python3
"""
DHCPv6 CVE-2026-53921 OpenWrt Stack Overflow Lab

Byte-level walkthrough of the malformed DHCPv6 SOLICIT packet that triggers
CVE-2026-53921 in OpenWrt's DHCPv6 option parser, a Suricata detection rule,
and optional scanning of Suricata fast.log or eve.json exports.

Usage:
    python dhcpv6_openwrt_overflow_lab.py                        # lab + rule
    python dhcpv6_openwrt_overflow_lab.py fast.log --mode scan   # scan only
    python dhcpv6_openwrt_overflow_lab.py eve.json --mode both   # lab + scan
    python dhcpv6_openwrt_overflow_lab.py fast.log --severity high
"""
import argparse, calendar, datetime, json, re, sys
from collections import defaultdict, deque

RANK = {"low": 0, "medium": 1, "high": 2}
MIT = {
    "MalformedOptionLength": "Upgrade OpenWrt >= 23.05.4; enforce DHCPv6 option-length validation at perimeter.",
    "OversizePayload":       "Block UDP/547 from untrusted sources; Suricata threshold on payloads > 512 B.",
    "SolicitFlood":          "Rate-limit DHCPv6 SOLICIT per src via ip6tables; whitelist known relay IPs.",
}
FAST_RE = re.compile(r'(\d{2}/\d{2}/\d{4}-[\d:.]+)\s+\[\*\*\].*?\[\*\*\]\s+(.*?)\s+\[\*\*\]\s+\{(\w+)\}\s+([\w:.]+)(?::\d+)?\s*->\s*([\w:.]+)')
CVE_RE  = re.compile(r'CVE[\-.]?2026[\-.]?53921|dhcpv6.*option\.length|ia\.na.*overflow', re.I)
OPT_RE  = re.compile(r'option[-_.]*len|optlen|option_length|ia_na', re.I)
TS_RE   = re.compile(r'(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d+)|(\d{2})/(\d{2})/(\d{4})-(\d{2}):(\d{2}):(\d{2})\.(\d+)')

FIELDS = [
    ("msg_type", "01",                          "DHCPv6 SOLICIT (type=1); routes to IA_NA parser in odhcp6c"),
    ("xid",      "a1 b2 c3",                   "Transaction ID, 3 bytes; attacker-controlled, no overflow role"),
    ("opt_code", "00 03",                       "IA_NA option code (0x0003); dispatches to fixed-size stack buffer"),
    ("opt_len",  "ff 00",                       "OVERSIZED: 65280 B declared; stack buffer ~256 B — triggers overflow"),
    ("iaid",     "de ad be ef",                 "IA Identifier, 4 bytes; attacker-controlled prefix of IA_NA body"),
    ("t1",       "00 00 00 01",                 "T1 timer, 4 bytes; lands inside overflow region"),
    ("t2",       "00 00 00 01",                 "T2 timer, 4 bytes; lands inside overflow region"),
    ("payload",  " ".join(["41"]*8) + " …", "Overflow bytes ('A'×N); overwrites saved return address on stack"),
]

def build_lab():
    S = "=" * 72
    print(f"{S}\nCVE-2026-53921 – OpenWrt DHCPv6 IA_NA Stack Overflow: Packet Walkthrough\n{S}")
    print(f"{'FIELD':<14}{'HEX BYTES':<30}NOTE\n{'-'*72}")
    for name, hx, note in FIELDS:
        print(f"{name:<14}{hx:<30}{note}")
    print("\nATTACK CHAIN:")
    for s in ("1. Attacker sends SOLICIT with IA_NA opt_len=0xFF00 (65280 bytes).",
              "2. odhcp6c calls memcpy(stack_buf, opt_data, opt_len) with no bounds check.",
              "3. Stack buffer (~256 B) overflows; saved return address overwritten.",
              "4. Vulnerable OpenWrt <= 23.05.3: crash (DoS) or arbitrary code execution.",
              "5. Patched in CVE-2026-53921 fix: length guard added before memcpy."):
        print(f"  {s}")
    print(f"\n{S}\nSURICATA DETECTION RULE (copy-paste ready)\n{S}")
    print('alert udp any any -> any 547 (msg:"CVE-2026-53921 OpenWrt DHCPv6 IA_NA Oversized Option Length"; '
          'content:"|00 03|"; offset:4; depth:2; content:"|ff|"; distance:0; within:3; '
          'threshold:type limit,track by_src,count 1,seconds 60; '
          'classtype:attempted-dos; sid:2026053921; rev:1;)')
    print("\nTune threshold count/seconds to suppress burst noise on busy segments.\n")

def _ts_float(ts):
    m = TS_RE.search(ts)
    if not m: return None
    g = m.groups()
    if g[0]:
        y, mo, d, h, mi, s, us = int(g[0]), int(g[1]), int(g[2]), int(g[3]), int(g[4]), int(g[5]), g[6]
    else:
        mo, d, y, h, mi, s, us = int(g[7]), int(g[8]), int(g[9]), int(g[10]), int(g[11]), int(g[12]), g[13]
    try:
        dt = datetime.datetime(y, mo, d, h, mi, s)
    except ValueError:
        return None
    return calendar.timegm(dt.timetuple()) + float(f"0.{us}")

def scan_logs(path, min_sev):
    try:
        with open(path, errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        sys.exit(f"ERROR: {e}")
    eve = path.endswith(".json") or (lines and lines[0].strip().startswith("{"))
    solicit_times, min_r = defaultdict(list), RANK[min_sev]
    for raw in lines:
        line = raw.strip()
        if not line: continue
        if eve:
            try: ev = json.loads(line)
            except json.JSONDecodeError: continue
            src = ev.get("src_ip", "")
            sig = (ev.get("alert") or {}).get("signature", "")
            proto, dport, ts = ev.get("proto", ""), str(ev.get("dest_port", "")), ev.get("timestamp", "")
            byt = max(ev.get("bytes_toserver", 0) or 0, ev.get("bytes", 0) or 0)
        else:
            m = FAST_RE.match(line)
            if not m: continue
            ts, sig, proto, src = m.group(1), m.group(2), m.group(3), m.group(4)
            dport, byt = ("547" if "dhcpv6" in sig.lower() else ""), 0
        snip = line[:120]
        if (CVE_RE.search(sig) or OPT_RE.search(sig)) and RANK["high"] >= min_r:
            yield "MalformedOptionLength", "high", src, ts, snip, MIT["MalformedOptionLength"]
        if proto.upper() == "UDP" and (dport == "547" or "dhcpv6" in sig.lower()) and not re.match(r'^fe80:', src, re.I):
            big = byt > 512 or bool(re.search(r'(len|size|bytes)\s*[=:]\s*(51[3-9]|5[2-9]\d|[6-9]\d{2}|[1-9]\d{3,})', sig, re.I))
            if big and RANK["medium"] >= min_r:
                yield "OversizePayload", "medium", src, ts, snip, MIT["OversizePayload"]
        if re.search(r'solicit|dhcpv6', sig, re.I):
            tf = _ts_float(ts)
            if tf is not None:
                solicit_times[src] = [t for t in solicit_times[src] if t >= tf - 60] + [tf]
                if len(solicit_times[src]) > 10 and RANK["medium"] >= min_r:
                    yield "SolicitFlood", "medium", src, ts, snip, MIT["SolicitFlood"]

def report(findings):
    tally, uniq, seen, peak, found_high = defaultdict(int), defaultdict(set), deque(maxlen=20), "low", False
    print("=" * 72 + "\nSCAN FINDINGS\n" + "=" * 72)
    count = 0
    for tech, sev, src, ts, snip, mit in findings:
        tally[tech] += 1; uniq[tech].add(src)
        if RANK[sev] > RANK[peak]: peak = sev
        if sev == "high": found_high = True
        key = (tech, src)
        if key in seen: continue
        seen.append(key); count += 1
        print(f"[{sev.upper():<6}] {tech}\n  Source: {src}  Time: {ts}\n  Snippet: {snip}\n  Fix: {mit}\n")
    if not count: print("No findings above specified severity threshold.\n")
    print("=" * 72 + "\nSUMMARY\n" + "=" * 72)
    for t in sorted(tally): print(f"  {t:<30} hits={tally[t]}  unique_src={len(uniq[t])}")
    print(f"  Total unique IPs: {len({ip for ips in uniq.values() for ip in ips})}  Peak: {peak.upper()}\n")
    return found_high

def main():
    ap = argparse.ArgumentParser(
        description="DHCPv6 CVE-2026-53921 OpenWrt Stack Overflow Lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  %(prog)s                        # lab walkthrough + Suricata rule\n  %(prog)s fast.log --mode scan   # scan Suricata logs\n  %(prog)s eve.json --mode both   # lab + scan")
    ap.add_argument("log_file", nargs="?", help="Suricata fast.log or eve.json to scan")
    ap.add_argument("--mode", choices=["lab", "scan", "both"], default="both", help="Phases to run (default: both)")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low", help="Minimum alert level (default: low)")
    args = ap.parse_args()
    if not args.log_file:
        if args.mode == "scan": ap.error("scan mode requires log_file")
        args.mode = "lab"
    if args.mode in ("lab", "both"): build_lab()
    if args.mode in ("scan", "both"):
        sys.exit(1 if report(scan_logs(args.log_file, args.severity)) else 0)

if __name__ == "__main__": main()