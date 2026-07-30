"""
GitHub Org Enumeration Abuse Monitor

Usage:
    python github_org_enum_monitor.py access.log [--org myorg] [--threshold 30]
"""

import argparse
import json
import re
import sys
from collections import defaultdict, deque
from datetime import datetime

SCRAPER_UA = re.compile(r"python-requests|curl/7|Go-http-client/|okhttp/|libwww-perl", re.I)
FALLBACK_RE = re.compile(r'(\S+) \S+ \S+ \[([^\]]+)\] "(\w+) (\S+)[^"]*" (\d+).*"([^"]*)"$')
SEV_RANK = {"medium": 1, "high": 2}
TS_FMTS = ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z")


def parse_ts(s):
    for fmt in TS_FMTS:
        try:
            return datetime.strptime(s.strip(), fmt).replace(tzinfo=None)
        except ValueError:
            pass
    return None


def parse_entries(log_path):
    entries, dropped = [], 0
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                auth = r.get("auth_header") or r.get("Authorization") or r.get("authorization") or ""
                entries.append({
                    "ts": r.get("timestamp", ""), "ip": str(r.get("source_ip") or r.get("ip") or ""),
                    "method": str(r.get("method", "GET")).upper(), "path": str(r.get("path", "")),
                    "status": int(r.get("status") or r.get("status_code") or 0),
                    "auth": bool(auth), "ua": str(r.get("user_agent") or r.get("user-agent") or ""),
                })
            except (json.JSONDecodeError, ValueError, TypeError):
                m = FALLBACK_RE.search(line)
                if m:
                    entries.append({
                        "ts": m.group(2), "ip": m.group(1), "method": m.group(3),
                        "path": m.group(4), "status": int(m.group(5)), "auth": False, "ua": m.group(6),
                    })
                else:
                    dropped += 1
    return entries, dropped


def detect_abuse(entries, org_re, member_re, threshold):
    ip_reqs = defaultdict(list)
    for e in entries:
        if org_re.search(e["path"]):
            ip_reqs[e["ip"]].append(e)
    for ip, reqs in ip_reqs.items():
        reqs.sort(key=lambda x: parse_ts(x["ts"]) or datetime.min)
        win = deque()
        for e in reqs:
            t = parse_ts(e["ts"])
            if t is None:
                continue
            win.append((t, e))
            while win and (t - win[0][0]).total_seconds() >= 60:
                win.popleft()
            if len(win) > threshold:
                yield "RateAnomaly", "high", ip, e["method"], e["path"], e["status"], e["ts"]
    for e in entries:
        if not org_re.search(e["path"]):
            continue
        if e["method"] == "GET" and not e["auth"] and e["status"] == 200 and member_re.search(e["path"]):
            yield "UnauthMemberQuery", "high", e["ip"], e["method"], e["path"], e["status"], e["ts"]
        ua = e["ua"]
        if SCRAPER_UA.search(ua) or not ua.strip():
            yield "ScraperUserAgent", "medium", e["ip"], e["method"], e["path"], e["status"], e["ts"]


def report_findings(findings, dropped):
    counts = defaultdict(int)
    ips, critical, peak, rate_last = set(), False, "medium", {}
    for sig, sev, ip, method, path, status, ts in findings:
        if sig == "RateAnomaly":
            t = parse_ts(ts)
            if t is not None:
                last = rate_last.get(ip)
                if last and (t - last).total_seconds() < 60:
                    continue
                rate_last[ip] = t
        print(f"[{sig}] {sev.upper()} ip={ip} {method} {path} status={status} ts={ts}")
        counts[sig] += 1
        ips.add(ip)
        if SEV_RANK.get(sev, 0) > SEV_RANK.get(peak, 0):
            peak = sev
        if sig in ("UnauthMemberQuery", "RateAnomaly"):
            critical = True
    print("\n--- Summary ---")
    for sig, cnt in counts.items():
        print(f"  {sig}: {cnt}")
    print(f"  Unique source IPs: {len(ips)}")
    print(f"  Peak signal class: {peak}")
    if dropped:
        print(f"  Dropped (malformed) lines: {dropped}")
    return critical


def main():
    ap = argparse.ArgumentParser(description="GitHub org API log enumeration abuse detector")
    ap.add_argument("log_file", help="Path to JSON-lines or common-log-format GitHub API access log")
    ap.add_argument("--org", help="GitHub org name to scope path matching (default: all /orgs/*)")
    ap.add_argument("--threshold", type=int, default=30,
                    help="Requests per minute per IP for RateAnomaly (default: 30)")
    args = ap.parse_args()
    if args.org:
        org_re = re.compile(rf"/orgs/{re.escape(args.org)}/")
        member_re = re.compile(rf"/orgs/{re.escape(args.org)}/(members|teams|outside_collaborators)")
    else:
        org_re = re.compile(r"/orgs/[^/]+/")
        member_re = re.compile(r"/orgs/[^/]+/(members|teams|outside_collaborators)")
    try:
        entries, dropped = parse_entries(args.log_file)
    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)
    findings = list(detect_abuse(entries, org_re, member_re, args.threshold))
    critical = report_findings(findings, dropped)
    sys.exit(1 if critical else 0)


if __name__ == "__main__":
    main()