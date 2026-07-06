"""
Gravity SMTP Secret Exposure Scanner

Scans web server access logs for unauthenticated exploitation of the
Gravity SMTP plugin's info disclosure vulnerability (CVE-style detection).

Usage:
    python gravity_smtp_exposure_scanner.py /var/log/nginx/access.log
    python gravity_smtp_exposure_scanner.py /var/log/apache2/access.log --threshold 5
    python gravity_smtp_exposure_scanner.py access.log --since 2026-06-23T00:00:00
"""

import re
import sys
import argparse
from datetime import datetime


SIGMA_RULE = {
    "id": "gravity-smtp-info-disclosure-001",
    "title": "Gravity SMTP Unauthenticated Credential Disclosure Attempt",
    "severity": "HIGH",
    "references": ["https://wpscan.com/plugins/gravitysmtp"],
    "patterns": [
        r"/wp-json/gf/v2/settings",
        r"/wp-json/gravitysmtp/v1/settings",
        r"/wp-admin/admin-ajax\.php.*action=gravitysmtp",
        r"/wp-json/wp/v2/gravitysmtp",
        r"gravitysmtp.*smtp_pass",
        r"gravitysmtp.*api_key",
        r"gravitysmtp.*credentials",
        r"gravity-smtp.*export",
        r"gravity_smtp_get_settings",
        r"gravity_smtp_credentials",
    ],
}


def load_sigma_rule():
    return {
        "id": SIGMA_RULE["id"],
        "title": SIGMA_RULE["title"],
        "severity": SIGMA_RULE["severity"],
        "compiled": [re.compile(p, re.IGNORECASE) for p in SIGMA_RULE["patterns"]],
    }


LOG_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+\S+"\s+(?P<status>\d{3})'
)

TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_log_line(line):
    m = LOG_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("ts"), TS_FORMAT)
    except ValueError:
        return None
    return {
        "ip": m.group("ip"),
        "ts": ts,
        "method": m.group("method"),
        "uri": m.group("uri"),
        "status": m.group("status"),
    }


def scan_log(log_path, threshold, since):
    rule = load_sigma_rule()
    ip_hits = {}
    findings = []

    try:
        fh = open(log_path, "r", encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"[ERROR] Cannot open log file: {e}", file=sys.stderr)
        sys.exit(1)

    with fh:
        for raw in fh:
            entry = parse_log_line(raw.rstrip("\n"))
            if entry is None:
                continue
            if since and entry["ts"] < since:
                continue

            matched = [p.pattern for p in rule["compiled"] if p.search(entry["uri"])]
            if not matched:
                continue

            ip = entry["ip"]
            ip_hits[ip] = ip_hits.get(ip, 0) + 1
            severity = "HIGH" if ip_hits[ip] >= threshold else "INFO"

            findings.append({
                "ts": entry["ts"].isoformat(),
                "ip": ip,
                "uri": entry["uri"],
                "status": entry["status"],
                "severity": severity,
                "indicators": matched,
                "rule_id": rule["id"],
            })

    for f in findings:
        escalated = ip_hits.get(f["ip"], 0) >= threshold
        sev = "HIGH" if escalated else "INFO"
        indicators = "; ".join(f["indicators"])
        print(
            f"[{sev}] {f['ts']} | IP: {f['ip']} | "
            f"URI: {f['uri']} | Status: {f['status']} | "
            f"Rule: {f['rule_id']} | Matched: {indicators}"
        )

    unique_ips = set(f["ip"] for f in findings)
    print(f"\n--- Summary ---")
    print(f"Total matches : {len(findings)}")
    print(f"Unique IPs    : {len(unique_ips)}")
    if unique_ips:
        print(f"Attacker IPs  : {', '.join(sorted(unique_ips))}")


def parse_since(value):
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            naive = datetime.strptime(value, fmt)
            return naive.replace(tzinfo=None)
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(f"Unrecognized datetime format: {value}")


def main():
    parser = argparse.ArgumentParser(
        description="Scan access logs for Gravity SMTP unauthenticated info disclosure exploitation."
    )
    parser.add_argument("log_file", help="Path to Apache/Nginx combined-format access log")
    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Minimum hits per IP to escalate severity to HIGH (default: 3)",
    )
    parser.add_argument(
        "--since",
        type=parse_since,
        default=None,
        help="Only process log entries after this ISO datetime (e.g. 2026-06-23T00:00:00)",
    )
    args = parser.parse_args()

    since = args.since
    if since is not None and since.tzinfo is None:
        since = since.replace(tzinfo=datetime.now().astimezone().tzinfo)

    scan_log(args.log_file, args.threshold, since)


if __name__ == "__main__":
    main()