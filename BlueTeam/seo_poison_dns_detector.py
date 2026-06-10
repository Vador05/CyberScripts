"""
SEO Poison DNS Detector

Parses plain-text DNS or proxy logs to flag domains matching indicators
associated with SEO-poisoned fake open-source package sites delivering
Remus Stealer and SessionGate via traffic distribution systems.

Usage example:
    python seo_poison_dns_detector.py /var/log/dns.log --blocklist blocked_ips.txt --verbose
    python seo_poison_dns_detector.py proxy.log
"""

import argparse
import re
import sys
from datetime import datetime, timezone

TDS_REDIRECTOR_PATTERNS = [
    re.compile(r'(?i)\b(?:track|redirect|go|click|traffic)\d*\.[a-z0-9-]{4,}\.[a-z]{2,6}\b'),
    re.compile(r'(?i)\b(?:cdn|static|assets)\d+\.[a-z0-9-]{6,}\.(xyz|top|club|icu|site|online)\b'),
    # Require subdomain structure (two labels before TLD) to avoid matching every short-TLD domain
    re.compile(r'(?i)\b[a-z0-9-]{4,}\.[a-z0-9-]{8,}\.(xyz|top|club|icu|site|online|buzz|fun)\b'),
]

TYPOSQUAT_PATTERNS = [
    re.compile(r'(?i)\b(?:numpy|pandas|requests|flask|django|react|lodash|axios|express|webpack)'
               r'(?:-[a-z]{2,}|-\d+|[0-9]+|[_-]security|[_-]update|[_-]patch|[_-]fix)\b'),
    re.compile(r'(?i)\b(?:pip|npm|pypi|pkg|package)[_-](?:install|update|mirror|cdn|repo)\.[a-z]{2,6}\b'),
    re.compile(r'(?i)\bpypi-(?:mirror|cdn|packages|download)\.[a-z]{2,6}\b'),
    re.compile(r'(?i)\bnpm-(?:mirror|cdn|registry|download)\.[a-z]{2,6}\b'),
]

C2_PATTERNS = [
    re.compile(r'(?i)\b(?:remus|sessiongate|stlr|sgate)\d*\.[a-z0-9-]{4,}\.[a-z]{2,6}\b'),
    re.compile(r'(?i)\b(?:gate|panel|c2|cmd|ctrl|agent|bot)\d*\.[a-z0-9-]{6,}\.'
               r'(?:xyz|top|club|icu|site|online)\b'),
    re.compile(r'(?i)\b[a-z0-9]{16,32}\.(?:xyz|top|club|icu|site|online|buzz)\b'),
]

LOG_FIELD_RE = re.compile(
    r'(?P<domain>(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6})'
    r'|(?P<ip>\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b)'
)

# Leading (?:^|\.) ensures "evil-npmjs.com" does NOT match as safe
SAFE_DOMAIN_RE = re.compile(
    r'(?i)(?:^|\.)(?:npmjs\.com|pypi\.org|python\.org|github\.com|githubusercontent\.com'
    r'|cloudflare\.com|amazonaws\.com|fastly\.net|googleapis\.com|gstatic\.com'
    r'|microsoft\.com|apple\.com|mozilla\.org|ubuntu\.com|debian\.org)$'
)

INDICATOR_GROUPS = [
    ("TDS_REDIRECTOR", TDS_REDIRECTOR_PATTERNS),
    ("TYPOSQUAT_PKG", TYPOSQUAT_PATTERNS),
    ("C2_HOSTNAME", C2_PATTERNS),
]


def _is_private_ip(ip):
    if ip.startswith(("127.", "10.", "192.168.")):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        try:
            # RFC 1918: only 172.16.0.0/12 (second octets 16-31) is private
            return 16 <= int(parts[1]) <= 31
        except (IndexError, ValueError):
            return False
    return False


def parse_log_line(line):
    domains, ips = [], []
    seen_domains: set = set()
    seen_ips: set = set()
    for m in LOG_FIELD_RE.finditer(line):
        if m.group("domain"):
            d = m.group("domain")
            if d not in seen_domains and not SAFE_DOMAIN_RE.search(d):
                seen_domains.add(d)
                domains.append(d)
        elif m.group("ip"):
            raw = m.group("ip")
            if raw not in seen_ips and not _is_private_ip(raw):
                seen_ips.add(raw)
                ips.append(raw)
    return domains, ips


def match_indicators(domains):
    findings = []
    for artifact in domains:
        matched = False
        for label, patterns in INDICATOR_GROUPS:
            if matched:
                break
            for pat in patterns:
                if pat.search(artifact):
                    findings.append((label, artifact))
                    matched = True
                    break
    return findings


def emit_alert(lineno, severity, indicator_type, artifact, raw_line, verbose):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] ALERT severity={severity} type={indicator_type} artifact={artifact} line={lineno}")
    if verbose:
        safe_line = "".join(c for c in raw_line.rstrip() if c.isprintable() and c != "\x1b")
        print(f"  >> {safe_line}")


def severity_for(indicator_type):
    return {"C2_HOSTNAME": "HIGH", "TYPOSQUAT_PKG": "HIGH",
            "TDS_REDIRECTOR": "MEDIUM"}.get(indicator_type, "INFO")


def _write_blocklist(ips, blocklist_path):
    try:
        with open(blocklist_path, "a") as fh:
            for ip in ips:
                fh.write(ip + "\n")
    except OSError as exc:
        print(f"[WARN] Could not write to blocklist {blocklist_path}: {exc}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Detect DNS/proxy log entries linked to SEO-poison campaigns (Remus Stealer / SessionGate)."
    )
    parser.add_argument("log_file", help="Path to plain-text DNS or proxy log")
    parser.add_argument("--blocklist", metavar="FILE", help="Append flagged IPs to this file")
    parser.add_argument("--verbose", action="store_true", help="Print matched log line alongside each alert")
    args = parser.parse_args()

    try:
        fh = open(args.log_file, "r", errors="replace")
    except OSError as exc:
        print(f"[ERROR] Cannot open log file: {exc}", file=sys.stderr)
        sys.exit(1)

    alert_count = 0
    with fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            domains, ips = parse_log_line(line)
            findings = match_indicators(domains)
            if findings:
                for indicator_type, artifact in findings:
                    sev = severity_for(indicator_type)
                    emit_alert(lineno, sev, indicator_type, artifact, line, args.verbose)
                    alert_count += 1
                # Only write IPs to blocklist when a domain indicator matched on the same line
                if args.blocklist and ips:
                    _write_blocklist(ips, args.blocklist)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] SCAN_COMPLETE total_alerts={alert_count} log={args.log_file}")


if __name__ == "__main__":
    main()
