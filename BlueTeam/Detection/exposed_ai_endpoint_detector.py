"""
Exposed AI Service Endpoint Detector

Analyzes web server access logs for request patterns matching exposed AI service
endpoints (Ollama, ComfyUI, Langflow, Open WebUI, Gradio), flagging active
inference API access, service enumeration probes, and scanner burst activity.

Usage:
    python exposed_ai_endpoint_detector.py <log_file> [--services SERVICES] [--severity LEVEL]

Example:
    python exposed_ai_endpoint_detector.py /var/log/nginx/access.log --severity high
    python exposed_ai_endpoint_detector.py access.log --services ollama,gradio --severity medium
"""

import argparse
import re
import sys
from collections import defaultdict, deque
from datetime import datetime

LOG_RE = re.compile(r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)[^"]*"\s+(\d+)')
TS_FMTS = ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S")
SEV_RANK = {"low": 0, "medium": 1, "high": 2}
_EPOCH = datetime(1970, 1, 1)

INFERENCE = {
    "ollama":    ["/api/generate", "/api/chat"],
    "comfyui":   ["/prompt", "/queue/prompt"],
    "langflow":  ["/api/v1/run", "/api/v1/predict"],
    "openwebui": ["/ollama/api/generate", "/api/chat/completions"],
    "gradio":    ["/run/predict", "/queue/join"],
}

ENUM = {
    "/api/tags": "ollama",      "/api/version": "ollama",
    "/api/models": "openwebui", "/queue/status": "comfyui",
    "/info": "gradio",          "/sdapi/v1/options": "comfyui",
    "/api/v1/flows": "langflow",
}

BURST_LIMIT, BURST_WIN = 10, 60


def _epoch(ts):
    return (ts - _EPOCH).total_seconds()


def _parse_ts(s):
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
            m = LOG_RE.search(line)
            if not m:
                dropped += 1
                continue
            ts = _parse_ts(m.group(2))
            if ts is None:
                dropped += 1
                continue
            entries.append((m.group(1), ts, m.group(3), m.group(4).split("?")[0], int(m.group(5))))
    return entries, dropped


def detect_signals(entries, services):
    inf_map = {p: svc for svc in services for p in INFERENCE.get(svc, [])}
    enum_map = {p: s for p, s in ENUM.items() if s in services}
    all_ai = set(inf_map) | set(enum_map)
    ip_wins = defaultdict(deque)
    signals = []

    for ip, ts, method, path, status in entries:
        if path in inf_map and 200 <= status <= 299:
            signals.append(("ActiveExposure", "T1090", "high", inf_map[path], ip, method, path, status, ts))
        if path in enum_map:
            signals.append(("ServiceEnumeration", "T1590", "medium", enum_map[path], ip, method, path, status, ts))
        if path in all_ai:
            ep = _epoch(ts)
            dq = ip_wins[ip]
            dq.append(ep)
            while dq and dq[0] < ep - BURST_WIN:
                dq.popleft()
            if len(dq) > BURST_LIMIT:
                svc = inf_map.get(path, enum_map.get(path, "multiple"))
                signals.append(("ScannerBurst", "T1595", "high", svc, ip, method, path, status, ts))

    return signals


def report_findings(signals, min_sev):
    min_rank = SEV_RANK[min_sev]
    cls_counts, svc_counts = defaultdict(int), defaultdict(int)
    unique_ips, mitre_seen = set(), set()
    peak, any_high = "low", False
    burst_dedup = {}

    for cls, mitre, sev, svc, ip, method, path, status, ts in signals:
        if SEV_RANK[sev] < min_rank:
            continue
        if cls == "ScannerBurst":
            ep = _epoch(ts)
            if ep - burst_dedup.get(ip, 0) < BURST_WIN:
                continue
            burst_dedup[ip] = ep
        iso = ts.strftime("%Y-%m-%dT%H:%M:%S")
        print(f"[{iso}] {cls} | {mitre} | {sev.upper()} | {svc} | {ip} | {method} {path} | HTTP {status}")
        cls_counts[cls] += 1
        svc_counts[svc] += 1
        unique_ips.add(ip)
        mitre_seen.add(mitre)
        if SEV_RANK[sev] > SEV_RANK[peak]:
            peak = sev
        if sev == "high":
            any_high = True

    print("\n--- Summary ---")
    print(f"  Signal classes : {dict(cls_counts)}")
    print(f"  Per-service    : {dict(svc_counts)}")
    print(f"  Unique IPs     : {len(unique_ips)}")
    print(f"  MITRE coverage : {', '.join(sorted(mitre_seen)) or 'none'}")
    print(f"  Peak severity  : {peak.upper()}")
    return any_high


def main():
    ap = argparse.ArgumentParser(description="Exposed AI Service Endpoint Detector")
    ap.add_argument("log_file", help="Path to web server access log")
    ap.add_argument("--services", default="ollama,comfyui,langflow,openwebui,gradio",
                    help="Comma-separated AI services to scope detection to (default: all)")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum alert severity to emit (default: low)")
    args = ap.parse_args()

    valid = {"ollama", "comfyui", "langflow", "openwebui", "gradio"}
    services = [s.strip().lower() for s in args.services.split(",")]
    bad = set(services) - valid
    if bad:
        ap.error(f"Unknown services: {', '.join(sorted(bad))}. Valid: {', '.join(sorted(valid))}")

    try:
        entries, dropped = parse_entries(args.log_file)
    except OSError as e:
        print(f"Error reading log: {e}", file=sys.stderr)
        sys.exit(2)

    if dropped:
        print(f"Warning: {dropped} malformed lines skipped", file=sys.stderr)

    signals = detect_signals(entries, services)
    any_high = report_findings(signals, args.severity)
    sys.exit(1 if any_high else 0)


if __name__ == "__main__":
    main()