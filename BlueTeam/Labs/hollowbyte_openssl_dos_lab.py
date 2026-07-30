Looking at the two issues:
1. The `except ValueError` block in `match_rules` must set `delta = 999` (not `0`) to avoid false positives.
2. The second `run_lab` scenario must use `ext_type=65500` (not `10`, which is in `KNOWN_EXT` and gets skipped by the rule).

"""
HollowByte OpenSSL DoS IDS Rule Lab & Validator

Scans plain-text TLS session logs, Suricata fast.log, and Zeek conn.log exports
for the HollowByte 11-byte ClientHello extension DoS trigger signature.

Usage:
    python hollowbyte_openssl_dos_lab.py tls.log
    python hollowbyte_openssl_dos_lab.py fast.log --severity high
    python hollowbyte_openssl_dos_lab.py --lab-only
    python hollowbyte_openssl_dos_lab.py - < tls.log
"""

import argparse, re, sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

SID_HA, SID_CB = 9900001, 9900002
SIG_HA, SIG_CB = "hollowbyte-tls-ext-11b", "hollowbyte-burst-dos"
KNOWN_EXT = set(range(57)) | {65281, 65282, 65283}
SEV = {"low": 0, "medium": 1, "high": 2}

_ENTRY_RE = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\S*'
    r'\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+):\d+'
    r'.*?(?:->|>)\s*(?P<dst_ip>\d+\.\d+\.\d+\.\d+)'
    r'.*?ext_len=(?P<ext_len>\d+)'
    r'(?:.*?ext_type=(?P<ext_type>\d+))?'
    r'(?:.*?record=(?P<tls_type>\w+))?'
    r'(?:.*?term=(?P<term>\w+))?'
)
_SUR_RE = re.compile(
    r'(?P<ts>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2})\.\d+.*?'
    r'(?P<src_ip>\d+\.\d+\.\d+\.\d+):\d+\s+->\s+(?P<dst_ip>\d+\.\d+\.\d+\.\d+)'
)
_ZEEK_RE = re.compile(
    r'(?P<ts>\d+\.\d+)\t\S+\t(?P<src_ip>\d+\.\d+\.\d+\.\d+)\t\d+\t(?P<dst_ip>\d+\.\d+\.\d+\.\d+)'
)


def parse_log_entry(line):
    line = line.strip()
    if not line or line[0] in '#%':
        return None
    e = {"raw": line, "src_ip": "unknown", "ts": "", "ext_len": None,
         "ext_type": None, "tls_type": "ClientHello", "term": ""}
    m = _ENTRY_RE.search(line)
    if m:
        d = {k: v for k, v in m.groupdict().items() if v is not None}
        e.update(d)
        e["ext_len"] = int(d["ext_len"])
        if "ext_type" in d:
            e["ext_type"] = int(d["ext_type"])
        return e
    for rx in (_SUR_RE, _ZEEK_RE):
        m = rx.search(line)
        if m:
            e.update({k: v for k, v in m.groupdict().items() if v})
            el = re.search(r'ext_len=(\d+)', line)
            if el:
                e["ext_len"] = int(el.group(1))
                return e
    return None


def match_rules(entries, min_sev="low"):
    min_r = SEV[min_sev]
    alerts, burst = [], defaultdict(list)
    for ent in entries:
        if ent.get("ext_len") != 11:
            continue
        if ent.get("ext_type") is not None and ent["ext_type"] in KNOWN_EXT:
            continue
        if ent.get("term") not in ("fatal", "rst"):
            continue
        burst[ent["src_ip"]].append(ent)
        if SEV["high"] >= min_r:
            alerts.append(dict(
                stage="HandshakeAnomaly", technique="T1499.004", severity="high",
                rule=f"suricata:sid={SID_HA} / zeek:{SIG_HA}",
                src_ip=ent["src_ip"], tls_type=ent.get("tls_type", "ClientHello"),
                payload_len=11, raw=ent["raw"]
            ))
    for ip, evs in burst.items():
        if len(evs) < 5 or SEV["medium"] < min_r:
            continue
        for i in range(len(evs) - 4):
            w = evs[i:i + 5]
            try:
                delta = abs((datetime.fromisoformat(w[-1]["ts"].replace(" ", "T")) -
                             datetime.fromisoformat(w[0]["ts"].replace(" ", "T"))).total_seconds())
            except ValueError:
                delta = 999
            if delta <= 30:
                alerts.append(dict(
                    stage="ConnectionBurst", technique="T1499/T1071", severity="medium",
                    rule=f"suricata:sid={SID_CB} / zeek:{SIG_CB}",
                    src_ip=ip, tls_type="ClientHello", payload_len=11, raw=w[0]["raw"]
                ))
                break
    return alerts


def _emit(a):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] stage={a['stage']} technique={a['technique']} sev={a['severity']} "
          f"rule={a['rule']} src={a['src_ip']} tls={a['tls_type']} len={a['payload_len']}")
    print(f"       {a['raw'][:120]}")


def run_lab(min_sev="low"):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    ip, dst = "10.0.0.99", "192.168.1.1:443"
    base = f"{now} {ip}:54321 -> {dst}"
    scenarios = [
        ("BareExtTrigger", "HandshakeAnomaly", SID_HA, SIG_HA,
         [f"{base} record=ClientHello ext_len=11 ext_type=65500 term=fatal payload=48656c6c6f576f726c6421"]),
        ("SupportedGroupsOffset", "HandshakeAnomaly", SID_HA, SIG_HA,
         [f"{base} record=ClientHello ext_type=65500 ext_len=11 term=rst payload=deadbeef01020304"]),
        ("BurstSequence", "ConnectionBurst", SID_CB, SIG_CB,
         [f"{now} {ip}:{54000+i} -> {dst} record=ClientHello ext_len=11 ext_type=65500 term=rst" for i in range(5)]),
    ]
    all_pass, rows = True, []
    for name, exp_stage, sid, zsig, lines in scenarios:
        entries = [e for l in lines for e in [parse_log_entry(l)] if e]
        alerts = match_rules(entries, min_sev)
        hit = any(a["stage"] == exp_stage for a in alerts)
        if not hit:
            all_pass = False
        for a in alerts:
            a["stage"] = "LabValidation"
            _emit(a)
        rows.append((name, exp_stage, f"sid={sid}", zsig, "PASS" if hit else "FAIL"))
    print("\n--- Lab Fidelity Report ---")
    print(f"{'Scenario':<26} {'ExpStage':<20} {'SuricataSID':<16} {'ZeekSig':<32} Status")
    print("-" * 100)
    for r in rows:
        print(f"{r[0]:<26} {r[1]:<20} {r[2]:<16} {r[3]:<32} {r[4]}")
    return all_pass


def main():
    ap = argparse.ArgumentParser(
        description="HollowByte OpenSSL DoS IDS Rule Lab & Validator",
        epilog="Examples:\n  %(prog)s tls.log\n  %(prog)s fast.log --severity high\n  %(prog)s --lab-only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("log_file", nargs="?", help="TLS session log, Suricata fast.log, or Zeek conn.log (- for stdin)")
    ap.add_argument("--lab-only", action="store_true", help="Run only controlled lab simulation")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum alert severity to emit (default: low)")
    args = ap.parse_args()
    if not args.lab_only and not args.log_file:
        ap.error("log_file is required unless --lab-only is specified")
    if args.lab_only and args.log_file:
        ap.error("--lab-only and log_file are mutually exclusive")

    exit_code, all_alerts = 0, []
    if args.log_file and not args.lab_only:
        try:
            if args.log_file == "-":
                with sys.stdin as fh:
                    entries = [e for line in fh for e in [parse_log_entry(line)] if e]
            else:
                with open(args.log_file, encoding="utf-8", errors="replace") as fh:
                    entries = [e for line in fh for e in [parse_log_entry(line)] if e]
        except OSError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(2)
        alerts = match_rules(entries, args.severity)
        for a in alerts:
            _emit(a)
        all_alerts.extend(alerts)
        if any(a["severity"] == "high" for a in alerts):
            exit_code = 1

    if args.lab_only:
        if not run_lab(args.severity):
            exit_code = 1

    if all_alerts:
        stages = Counter(a["stage"] for a in all_alerts)
        techs = sorted({a["technique"] for a in all_alerts})
        peak = max(all_alerts, key=lambda a: SEV[a["severity"]])["severity"]
        print("\n--- Summary ---")
        for s, c in stages.items():
            print(f"  {s}: {c}")
        print(f"  Techniques: {', '.join(techs)}  IPs: {len({a['src_ip'] for a in all_alerts})}  Peak: {peak}")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()