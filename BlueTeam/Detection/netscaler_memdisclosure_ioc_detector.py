"""
NetScaler Memory-Disclosure IOC Feed & Session-Cookie Exfiltration Detector

Scans plain-text NetScaler ADC/Gateway HTTP access log exports for active exploitation
of NetScaler memory-disclosure CVEs by matching PoC-derived request patterns and
detecting anomalous NSC session-cookie exfiltration sequences.

Usage:
    python netscaler_memdisclosure_ioc_detector.py /var/log/ns.log
    python netscaler_memdisclosure_ioc_detector.py /var/log/ns.log --iocs iocs.json --severity high

IOC feed JSON format:
    {"ips": ["1.2.3.4"], "domains": ["evil.com"], "uri_fragments": ["/malicious/"]}
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from urllib.parse import unquote

MEMDISCLOSURE_URIS = [
    r"/oauth/idp/\.well-known/openid-configuration",
    r"/nf/auth/",
    r"/logon/LogonPoint/",
    r"/gwtest/portalroute/",
]

POC_QUERY_PARAMS = ["rstate", "reqtype", "aaaglobal", "NSC_TASS", "NSC_RAN", "pwcount", "nonce="]

MEM_BLEED_MIN = 32768
MEM_BLEED_MAX = 131072

COMBINED_LOG_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+\S+"\s+(?P<code>\d+)\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    r'(?:\s+Cookie:\s*(?P<cookie>\S+))?'
)

NETSCALER_LOG_RE = re.compile(
    r'(?P<ts>\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\s+'
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+(?P<method>\S+)\s+(?P<uri>\S+)\s+'
    r'(?P<code>\d+)\s+(?P<bytes>\S+)'
)

NSC_COOKIE_RE = re.compile(r'(NSC_AAAC|NSC_TMAA)=([A-Za-z0-9+/=%_\-\.]+)')


def load_iocs(path):
    try:
        with open(path) as f:
            data = json.load(f)
        return {
            "ips": set(data.get("ips", [])),
            "domains": set(data.get("domains", [])),
            "uri_fragments": list(data.get("uri_fragments", [])),
        }
    except Exception as e:
        print(f"[WARN] Failed to load IOC feed {path}: {e}", file=sys.stderr)
        return {"ips": set(), "domains": set(), "uri_fragments": []}


def parse_log_entries(log_file):
    entries = []
    with open(log_file, errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or line.lower().startswith("date"):
                continue
            m = COMBINED_LOG_RE.match(line) or NETSCALER_LOG_RE.match(line)
            if not m:
                continue
            d = m.groupdict()
            uri = unquote(d.get("uri", ""))
            raw_cookie = d.get("cookie", "") or ""
            referer = d.get("referer", "") or ""
            nsc_in_cookie = {k: v for k, v in NSC_COOKIE_RE.findall(raw_cookie)}
            nsc_in_uri = {k: v for k, v in NSC_COOKIE_RE.findall(uri)}
            nsc_in_referer = {k: v for k, v in NSC_COOKIE_RE.findall(referer)}
            try:
                resp_bytes = int(d.get("bytes", 0))
            except (ValueError, TypeError):
                resp_bytes = 0
            try:
                ts_raw = d.get("ts", "")
                ts = datetime.strptime(ts_raw[:20].strip(), "%d/%b/%Y:%H:%M:%S") if "/" in ts_raw else datetime.now()
            except Exception:
                ts = datetime.now()
            entries.append({
                "ts": ts, "ip": d.get("ip", ""), "method": d.get("method", "GET"),
                "uri": uri, "code": d.get("code", "0"), "bytes": resp_bytes,
                "cookie": raw_cookie, "referer": referer,
                "nsc_in_cookie": nsc_in_cookie, "nsc_in_uri": nsc_in_uri,
                "nsc_in_referer": nsc_in_referer, "raw": line,
            })
    return entries


def match_rules(entries, iocs):
    findings = []
    auth_events = defaultdict(list)
    for e in entries:
        uri = e["uri"]
        is_vuln_endpoint = any(re.search(p, uri, re.I) for p in MEMDISCLOSURE_URIS)
        has_poc_param = any(p in uri for p in POC_QUERY_PARAMS)
        in_bleed_window = MEM_BLEED_MIN <= e["bytes"] <= MEM_BLEED_MAX

        if is_vuln_endpoint and (in_bleed_window or has_poc_param):
            sev = "high"
            rule = "memdisclosure_poc_request" if has_poc_param else "memdisclosure_response_size"
            findings.append({
                "stage": "MemDisclosure", "technique": "T1190", "severity": sev,
                "rule": rule, "ip": e["ip"], "bytes": e["bytes"], "raw": e["raw"], "ts": e["ts"],
            })

        leaked_keys = set(e["nsc_in_uri"]) | set(e["nsc_in_referer"])
        if leaked_keys:
            prior_auth = any(
                a["ip"] == e["ip"] and 0 <= (e["ts"] - a["ts"]).total_seconds() <= 120
                for a in auth_events[e["ip"]]
            )
            sev = "medium" if prior_auth else "high"
            findings.append({
                "stage": "CookieExfil", "technique": "T1539", "severity": sev,
                "rule": "nsc_cookie_in_uri_or_referer", "ip": e["ip"], "bytes": e["bytes"],
                "raw": e["raw"], "ts": e["ts"],
            })

        if e["nsc_in_cookie"]:
            auth_events[e["ip"]].append(e)

        if e["ip"] in iocs["ips"] or any(d in e["uri"] for d in iocs["domains"]) or \
                any(frag in e["uri"] for frag in iocs["uri_fragments"]):
            findings.append({
                "stage": "PostExploit", "technique": "T1078", "severity": "medium",
                "rule": "ioc_feed_match", "ip": e["ip"], "bytes": e["bytes"],
                "raw": e["raw"], "ts": e["ts"],
            })

    return findings


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def report_findings(findings, min_severity):
    seen = defaultdict(dict)
    threshold = SEVERITY_ORDER.get(min_severity, 0)
    emitted = []
    stage_counts = defaultdict(int)
    techniques = set()
    attacker_ips = set()
    total_bytes = 0
    peak_sev = "low"

    for f in findings:
        if SEVERITY_ORDER.get(f["severity"], 0) < threshold:
            continue
        key = (f["ip"], f["rule"])
        last_ts = seen[key].get("ts")
        if last_ts and (f["ts"] - last_ts).total_seconds() < 60:
            continue
        seen[key]["ts"] = f["ts"]
        ts_str = f["ts"].strftime("%Y-%m-%dT%H:%M:%S")
        print(f"[{ts_str}] ALERT stage={f['stage']} technique={f['technique']} "
              f"severity={f['severity'].upper()} rule={f['rule']} src={f['ip']} "
              f"bytes={f['bytes']} | {f['raw'][:200]}")
        emitted.append(f)
        stage_counts[f["stage"]] += 1
        techniques.add(f["technique"])
        attacker_ips.add(f["ip"])
        total_bytes += f["bytes"]
        if SEVERITY_ORDER.get(f["severity"], 0) > SEVERITY_ORDER.get(peak_sev, 0):
            peak_sev = f["severity"]

    print("\n--- Summary ---")
    for stage, count in sorted(stage_counts.items()):
        print(f"  {stage}: {count} hit(s)")
    print(f"  ATT&CK techniques: {', '.join(sorted(techniques)) or 'none'}")
    print(f"  Unique attacker IPs: {len(attacker_ips)}")
    print(f"  Total anomalous response bytes: {total_bytes}")
    print(f"  Peak severity: {peak_sev.upper()}")

    return peak_sev == "high" and any(SEVERITY_ORDER.get(f["severity"], 0) == 2 for f in emitted)


def main():
    parser = argparse.ArgumentParser(
        description="NetScaler Memory-Disclosure IOC Feed & Session-Cookie Exfiltration Detector"
    )
    parser.add_argument("log_file", help="Path to NetScaler or Apache/Nginx combined-format log")
    parser.add_argument("--iocs", help="Path to supplemental JSON IOC feed file")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum alert severity to emit (default: low)")
    args = parser.parse_args()

    iocs = load_iocs(args.iocs) if args.iocs else {"ips": set(), "domains": set(), "uri_fragments": []}

    try:
        entries = parse_log_entries(args.log_file)
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {args.log_file}", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print(f"[ERROR] Permission denied reading: {args.log_file}", file=sys.stderr)
        sys.exit(2)

    findings = match_rules(entries, iocs)
    has_high = report_findings(findings, args.severity)
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()