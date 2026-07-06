"""
BitM Phish Detector - Scans proxy/access logs for browser-in-the-middle phishing indicators.

Usage:
    python bitm_phish_detect.py access.log
    python bitm_phish_detect.py access.log --iocs custom_iocs.json --min-score 7

IOC JSON format:
    {"hostnames": ["evil.example.com"], "patterns": ["suspicious-pattern\\.com"]}
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime

BLUEKIT_HOSTNAME_PATTERNS = [
    r"(?:login|auth|secure|account|signin|sso)\.[a-z0-9-]+\.[a-z]{2,6}",
    r"[a-z0-9-]+-(?:login|auth|portal|secure)\.[a-z]{2,6}",
    r"(?:microsoft|google|apple|amazon|paypal|facebook|linkedin)-[a-z0-9-]+\.[a-z]{2,6}",
    r"[a-z0-9-]+\.(?:verify|validation|confirm|update)-[a-z0-9-]+\.[a-z]{2,6}",
]

COOKIE_RELAY_PATTERNS = [
    r"__Host-[A-Za-z0-9_]+=[A-Za-z0-9%+/=]{20,}",
    r"ESTSAUTH[A-Z]*=[A-Za-z0-9%+/=_-]{30,}",
    r"X-Ms-[A-Za-z-]+=[A-Za-z0-9%+/=_-]{10,}",
    r"(?:session|sess|auth|token)[_-]?(?:id|key|token)=[A-Za-z0-9%+/=_-]{30,}",
]

TLS_RELAY_HEADERS = [
    "x-forwarded-host",
    "x-original-url",
    "x-rewrite-url",
    "x-forwarded-server",
    "x-proxy-id",
    "via",
]

LOG_PATTERNS = [
    re.compile(
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<url>\S+)\s+\S+"\s+(?P<status>\d{3})\s+\S+'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?(?P<rest>.*)'
    ),
    re.compile(
        r'(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
        r'\s+(?P<method>\w+)\s+(?P<url>\S+)\s+(?P<status>\d{3})(?P<rest>.*)'
    ),
]

HOST_RE = re.compile(r'(?:host|Host):\s*([^\s,;"]+)', re.IGNORECASE)
COOKIE_RE = re.compile(r'[Cc]ookie:\s*([^\r\n"]+)')
HEADER_RE = re.compile(r'(x-[a-z-]+):\s*([^\s,;"]+)', re.IGNORECASE)


def parse_entry(line):
    for pattern in LOG_PATTERNS:
        m = pattern.match(line.strip())
        if not m:
            continue
        g = m.groupdict()
        rest = g.get("rest", "")
        host_m = HOST_RE.search(rest) or HOST_RE.search(g.get("url", ""))
        host = host_m.group(1) if host_m else ""
        if not host:
            url = g.get("url", "")
            url_m = re.match(r'https?://([^/]+)', url)
            host = url_m.group(1) if url_m else ""
        cookies_m = COOKIE_RE.search(rest)
        cookies = cookies_m.group(1) if cookies_m else ""
        headers = {hm.group(1).lower(): hm.group(2) for hm in HEADER_RE.finditer(rest)}
        return {
            "timestamp": g.get("ts", ""),
            "ip": g.get("ip", ""),
            "method": g.get("method", ""),
            "url": g.get("url", ""),
            "status": g.get("status", ""),
            "host": host,
            "cookies": cookies,
            "user_agent": g.get("ua", ""),
            "headers": headers,
            "raw": line.strip(),
        }
    return None


def score_indicators(entry, iocs):
    findings = []
    host = entry.get("host", "")
    headers = entry.get("headers", {})
    cookies = entry.get("cookies", "")
    raw = entry.get("raw", "")

    relay_hits = [h for h in TLS_RELAY_HEADERS if h in headers]
    has_xff = "x-forwarded-for" in headers
    has_via = "via" in headers
    tls_score = len(relay_hits) * 2 + (1 if has_xff else 0) + (1 if has_via else 0)
    if tls_score >= 2:
        note = f"Reverse-proxy headers present: {relay_hits + (['x-forwarded-for'] if has_xff else []) + (['via'] if has_via else [])}"
        findings.append(("TLS_RELAY", min(tls_score + 1, 10), note))

    for pat in COOKIE_RELAY_PATTERNS:
        if re.search(pat, cookies, re.IGNORECASE) or re.search(pat, raw, re.IGNORECASE):
            findings.append(("COOKIE_RELAY", 7, f"Cookie relay pattern matched: {pat}"))
            break

    cluster_matched = False
    for pat in BLUEKIT_HOSTNAME_PATTERNS:
        if host and re.search(pat, host, re.IGNORECASE):
            findings.append(("HOSTNAME_CLUSTER", 6, f"Bluekit hostname pattern: {pat} on {host}"))
            cluster_matched = True
            break

    if not cluster_matched and iocs:
        for ioc_host in iocs.get("hostnames", []):
            if ioc_host.lower() in host.lower():
                findings.append(("HOSTNAME_CLUSTER", 9, f"IOC hostname match: {ioc_host}"))
                break
        for ioc_pat in iocs.get("patterns", []):
            if re.search(ioc_pat, host, re.IGNORECASE) or re.search(ioc_pat, raw, re.IGNORECASE):
                findings.append(("HOSTNAME_CLUSTER", 8, f"IOC pattern match: {ioc_pat}"))
                break

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="BitM Phish Detector: scan proxy/access logs for browser-in-the-middle phishing indicators."
    )
    parser.add_argument("logfile", help="Path to plain-text proxy or access log")
    parser.add_argument("--iocs", help="Path to JSON file with custom hostname/pattern IOCs")
    parser.add_argument("--min-score", type=int, default=5, dest="min_score",
                        help="Minimum confidence score (1-10) to emit findings (default: 5)")
    args = parser.parse_args()

    log_path = os.path.abspath(args.logfile)
    if not os.path.isfile(log_path):
        print(json.dumps({"error": f"Log file not found: {log_path}"}), file=sys.stderr)
        sys.exit(1)

    iocs = {}
    if args.iocs:
        ioc_path = os.path.abspath(args.iocs)
        if not os.path.isfile(ioc_path):
            print(json.dumps({"error": f"IOC file not found: {ioc_path}"}), file=sys.stderr)
            sys.exit(1)
        try:
            with open(ioc_path, "r", encoding="utf-8") as f:
                iocs = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(json.dumps({"error": f"Failed to load IOC file: {e}"}), file=sys.stderr)
            sys.exit(1)

    min_score = max(1, min(10, args.min_score))

    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as lf:
            for line in lf:
                if not line.strip():
                    continue
                entry = parse_entry(line)
                if not entry:
                    continue
                for indicator_type, score, note in score_indicators(entry, iocs):
                    if score < min_score:
                        continue
                    finding = {
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "log_timestamp": entry["timestamp"],
                        "source_ip": entry["ip"],
                        "matched_indicator_type": indicator_type,
                        "confidence_score": score,
                        "notes": note,
                        "raw_log_line": entry["raw"],
                    }
                    print(json.dumps(finding))
    except OSError as e:
        print(json.dumps({"error": f"Failed to read log file: {e}"}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()