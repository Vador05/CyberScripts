"""
MCP Server Endpoint & AI Credential Path Scan Detector

Analyzes web server access logs for MCP server reconnaissance and
AI credential path enumeration activity.

Usage:
    python mcp_scan_detector.py access.log [--threshold 10] [--severity low]

Example:
    python mcp_scan_detector.py /var/log/nginx/access.log --threshold 5 --severity medium
"""

import argparse
import re
import sys
from collections import defaultdict, deque
from datetime import datetime
from urllib.parse import unquote

LOG_RE = re.compile(r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)[^"]*"\s+(\d+)')
TS_FMTS = ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S")
MCP_RE = re.compile(r'^(/v1)?/mcp(/|$|\.json$)|^/\.mcp(/|$)|^/mcp/v1(/|$)|^/sse(/|$)|^/mcp\.json$', re.I)
CRED_RE = re.compile(
    r'/\.claude(/|$)|/\.config/claude(/|$)|/mcp\.json|/\.anthropic(/|$)'
    r'|/\.cursor/mcp\.json|\.\./[^?#]*\.claude|%2e%2e[%2f/][^?#]*claude',
    re.I,
)
SEV_RANK = {"low": 0, "medium": 1, "high": 2}


def parse_ts(s):
    for fmt in TS_FMTS:
        try:
            dt = datetime.strptime(s.strip(), fmt)
            return dt.replace(tzinfo=None)
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
            m = LOG_RE.search(line)
            if not m:
                dropped += 1
                continue
            ts = parse_ts(m.group(2))
            if ts is None:
                dropped += 1
                continue
            entries.append({
                "ts": ts, "ip": m.group(1), "method": m.group(3).upper(),
                "path": unquote(m.group(4)), "raw_path": m.group(4),
                "status": int(m.group(5)), "ts_iso": ts.strftime("%Y-%m-%dT%H:%M:%S"),
            })
    return entries, dropped


def detect_signals(entries, threshold):
    ip_window = defaultdict(deque)
    for e in entries:
        path, raw, method = e["path"], e["raw_path"], e["method"]
        is_mcp = method in ("GET", "POST") and bool(MCP_RE.search(path))
        is_cred = bool(CRED_RE.search(path) or CRED_RE.search(raw))
        if is_mcp:
            yield ("MCPEndpointProbe", "T1046/T1595", "medium",
                   e["ip"], method, path, e["status"], e["ts_iso"])
        if is_cred:
            yield ("CredentialPathEnum", "T1552/T1083", "high",
                   e["ip"], method, path, e["status"], e["ts_iso"])
        if is_mcp or is_cred:
            dq = ip_window[e["ip"]]
            ts = e["ts"]
            dq.append(ts)
            while dq and (ts - dq[0]).total_seconds() > 60:
                dq.popleft()
            if len(dq) >= threshold:
                yield ("ScannerBurst", "T1595", "high",
                       e["ip"], method, path, e["status"], e["ts_iso"])


def report_findings(detections, min_sev, dropped):
    min_rank = SEV_RANK[min_sev]
    counts = defaultdict(int)
    flagged_ips = set()
    mitre_ids = set()
    peak_sev = "low"
    has_high = False
    burst_dedup = {}

    for sig, mitre, sev, ip, method, path, status, ts_iso in detections:
        if SEV_RANK[sev] < min_rank:
            continue
        if sig == "ScannerBurst":
            last = burst_dedup.get(ip)
            if last:
                try:
                    delta = (datetime.strptime(ts_iso, "%Y-%m-%dT%H:%M:%S") -
                             datetime.strptime(last, "%Y-%m-%dT%H:%M:%S")).total_seconds()
                    if delta < 60:
                        continue
                except ValueError:
                    pass
            burst_dedup[ip] = ts_iso
        counts[sig] += 1
        flagged_ips.add(ip)
        mitre_ids.add(mitre)
        if SEV_RANK[sev] > SEV_RANK[peak_sev]:
            peak_sev = sev
        if sev == "high":
            has_high = True
        print(f"[{ts_iso}] {sig} | {mitre} | SEV:{sev.upper()} | {ip} | {method} {path} | HTTP {status}")

    print("\n--- Summary ---")
    for cls in ("MCPEndpointProbe", "CredentialPathEnum", "ScannerBurst"):
        if counts[cls]:
            print(f"  {cls}: {counts[cls]}")
    print(f"  Unique flagged IPs: {len(flagged_ips)}")
    print(f"  MITRE techniques: {', '.join(sorted(mitre_ids)) if mitre_ids else 'none'}")
    print(f"  Peak severity: {peak_sev.upper()}")
    if dropped:
        print(f"  Malformed/dropped lines: {dropped}")
    return has_high


def main():
    parser = argparse.ArgumentParser(
        description="Detect MCP server reconnaissance and AI credential path enumeration in web access logs."
    )
    parser.add_argument("log_file", help="Path to web server access log (Combined Log Format)")
    parser.add_argument("--threshold", type=int, default=10,
                        help="Requests per 60s window triggering ScannerBurst (default: 10)")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum alert severity to emit (default: low)")
    args = parser.parse_args()
    try:
        entries, dropped = parse_entries(args.log_file)
    except OSError as e:
        print(f"Error reading log file: {e}", file=sys.stderr)
        sys.exit(2)
    detections = list(detect_signals(entries, args.threshold))
    has_high = report_findings(detections, args.severity, dropped)
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()