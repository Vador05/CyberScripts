"""
splunk_unauth_file_triage.py — Triage unauthenticated file-op attempts against
Splunk Enterprise (CVE-2026-20253) from plain-text access logs.

Usage:
    python splunk_unauth_file_triage.py splunkd_access.log --version 9.3.1
    python splunk_unauth_file_triage.py splunkd_access.log --version 9.2.2 --verbose
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone


VULN_ENDPOINTS = re.compile(
    r"(?:GET|POST|PUT|DELETE)\s+"
    r"(/services/data/inputs/monitor"
    r"|/en-US/splunkd/__raw/services/server/inputs"
    r"|/services/server/inputs"
    r"|/servicesNS/[^/]+/[^/]+/data/inputs)"
    r"[^\s]*\s+HTTP/\d\.\d\"\s+(?:200|201)\b",
    re.IGNORECASE,
)

NO_AUTH = re.compile(
    r'(?:Authorization|Bearer|Splunk\s+[A-Za-z0-9+/=]{16,})',
    re.IGNORECASE,
)

IP_PATTERN = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})')
ENDPOINT_EXTRACT = re.compile(
    r'(?:GET|POST|PUT|DELETE)\s+(/\S+)',
    re.IGNORECASE,
)

FIRST_FIXED = {
    (9, 1): (9, 1, 5),
    (9, 2): (9, 2, 3),
    (9, 3): (9, 3, 2),
}


def parse_logs(path: str, verbose: bool):
    hits = []
    try:
        with open(path, "r", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                if not VULN_ENDPOINTS.search(line):
                    continue
                if NO_AUTH.search(line):
                    continue
                ip_match = IP_PATTERN.match(line.strip())
                ip = ip_match.group(1) if ip_match else "unknown"
                ep_match = ENDPOINT_EXTRACT.search(line)
                endpoint = ep_match.group(1) if ep_match else "unknown"
                hits.append({
                    "lineno": lineno,
                    "ip": ip,
                    "endpoint": endpoint,
                    "raw": line.rstrip(),
                })
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied reading: {path}", file=sys.stderr)
        sys.exit(1)
    return hits


def check_patch(version: str):
    parts = version.strip().split(".")
    if len(parts) < 3:
        return None, "Version string must be in MAJOR.MINOR.PATCH format (e.g. 9.3.1)"
    try:
        major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
    except ValueError:
        return None, "Non-numeric version component detected"

    branch = (major, minor)
    fixed = FIRST_FIXED.get(branch)
    if fixed is None:
        return None, (
            f"Branch {major}.{minor}.x is not covered by the CVE-2026-20253 advisory. "
            "Consult Splunk's security bulletin for your version."
        )

    installed = (major, minor, patch)
    vulnerable = installed < fixed
    fixed_str = ".".join(str(x) for x in fixed)
    if vulnerable:
        note = (
            f"VULNERABLE — upgrade to {fixed_str} or later. "
            "See https://advisory.splunk.com/ for patch details."
        )
    else:
        note = f"PATCHED — {version} >= {fixed_str} (first fixed release)."
    return vulnerable, note


def severity(hit_count: int) -> str:
    if hit_count == 0:
        return "INFORMATIONAL"
    if hit_count < 5:
        return "LOW"
    if hit_count < 20:
        return "MEDIUM"
    return "HIGH"


def main():
    parser = argparse.ArgumentParser(
        description="Triage unauthenticated file-op attempts (CVE-2026-20253) in Splunk access logs."
    )
    parser.add_argument("log_file", help="Path to plain-text Splunk access log")
    parser.add_argument("--version", metavar="VERSION", help="Splunk Enterprise version string (e.g. 9.3.1)")
    parser.add_argument("--verbose", action="store_true", help="Emit full matching log lines")
    args = parser.parse_args()

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    hits = parse_logs(args.log_file, args.verbose)

    ip_counts: dict = defaultdict(int)
    endpoint_counts: dict = defaultdict(int)
    for h in hits:
        ip_counts[h["ip"]] += 1
        endpoint_counts[h["endpoint"]] += 1

    sev = severity(len(hits))

    print("=" * 66)
    print(f"  Splunk Unauth File-Op Triage — CVE-2026-20253")
    print(f"  Generated : {ts}")
    print(f"  Log file  : {args.log_file}")
    print("=" * 66)
    print(f"\n[+] Total suspicious hits : {len(hits)}")
    print(f"[+] Severity              : {sev}\n")

    if hits:
        print("  Source IPs:")
        for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1]):
            print(f"    {ip:<18} {count} hit(s)")
        print("\n  Targeted endpoints:")
        for ep, count in sorted(endpoint_counts.items(), key=lambda x: -x[1]):
            print(f"    {ep:<52} {count} hit(s)")

    if args.verbose and hits:
        print("\n  Matching log lines:")
        for h in hits:
            print(f"    [{h['lineno']:>6}] {h['raw']}")

    print()
    if args.version:
        vulnerable, note = check_patch(args.version)
        if vulnerable is None:
            print(f"[!] Patch check inconclusive: {note}")
        elif vulnerable:
            print(f"[VULNERABLE] {note}")
        else:
            print(f"[PATCHED]    {note}")
    else:
        print("[*] No --version supplied; skipping patch verification.")

    print("\n[NOTE] Regex patterns are heuristics. Confirm auth bypass with")
    print("       full packet capture or Splunk internal audit logs.")
    print("=" * 66)


if __name__ == "__main__":
    main()