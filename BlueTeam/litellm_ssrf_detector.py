"""
LiteLLM SSRF-to-RCE Detector

Scans LiteLLM and AI gateway plain-text logs for SSRF-to-RCE exploit chain
indicators using regex-based IOC matching.

Usage:
    python litellm_ssrf_detector.py --log /var/log/litellm/access.log
    python litellm_ssrf_detector.py --log app.log --mode scan --host gateway-prod
    python litellm_ssrf_detector.py --log app.log --mode checklist
    python litellm_ssrf_detector.py --log app.log --mode both --host my-litellm
"""

import argparse
import re
import sys
from datetime import datetime, timezone


PATTERNS = [
    (
        "CRITICAL",
        r"(?i)(?:POST|GET)\s+/config/update",
        "Attempt to abuse /config/update endpoint",
    ),
    (
        "CRITICAL",
        r"(?i)model[_\s\"'=:]+https?://(?:169\.254\.|127\.|0\.0\.0\.0|::1|\[::1\])",
        "Model name contains SSRF callback URI (RCE chain)",
    ),
    (
        "CRITICAL",
        r"(?i)callback[_\s\"'=:]+https?://(?:169\.254\.|127\.|0\.0\.0\.0|::1|\[::1\])",
        "Callback URI pointing to loopback/metadata service",
    ),
    (
        "HIGH",
        r"169\.254\.169\.254",
        "AWS/GCP metadata service IP probed",
    ),
    (
        "HIGH",
        r"169\.254\.170\.2",
        "ECS task metadata endpoint probed",
    ),
    (
        "HIGH",
        r"(?i)(?:http|https)://(?:metadata\.google\.internal|metadata\.goog)",
        "GCP metadata FQDN probed",
    ),
    (
        "HIGH",
        r"(?i)/latest/meta-data/iam/security-credentials",
        "AWS IMDS credential path accessed",
    ),
    (
        "HIGH",
        r"(?i)(?:POST|PUT|PATCH)\s+/model/new",
        "Dynamic model registration attempted",
    ),
    (
        "HIGH",
        r"(?i)\"?success_callback\"?\s*[:=]\s*\[?[\"']https?://(?:127\.|localhost|0\.0\.0\.0)",
        "Success callback set to internal loopback host",
    ),
    (
        "HIGH",
        r"(?i)\"?failure_callback\"?\s*[:=]\s*\[?[\"']https?://(?:127\.|localhost|0\.0\.0\.0)",
        "Failure callback set to internal loopback host",
    ),
    (
        "INFO",
        r"(?i)/health/liveliness|/health/readiness",
        "Health probe — may be reconnaissance",
    ),
    (
        "INFO",
        r"(?i)x-forwarded-for\s*:\s*(?:127\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)",
        "X-Forwarded-For spoofing with RFC-1918 address",
    ),
    (
        "INFO",
        r"(?i)model[_\s\"'=:]+https?://(?!(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com))[a-z0-9.\-]+",
        "Model URI pointing to non-standard provider host",
    ),
]

COMPILED = [(sev, re.compile(pat), desc) for sev, pat, desc in PATTERNS]

CHECKLIST = [
    ("CRITICAL", "Block outbound traffic to 169.254.0.0/16 (IMDS) and 100.64.0.0/10 at the host or VPC egress firewall."),
    ("CRITICAL", "Restrict /config/update and /model/new to 127.0.0.1 or an admin CIDR behind mTLS."),
    ("CRITICAL", "Enforce LITELLM_MASTER_KEY and rotate any keys exposed in logs immediately."),
    ("HIGH",     "Set LITELLM_DROP_PARAMS=true and whitelist only known provider base URLs via ALLOWED_LITELLM_URLS."),
    ("HIGH",     "Disable or ACL-gate unauthenticated passthrough model-provider routing."),
    ("HIGH",     "Validate and sanitize success_callback / failure_callback values server-side; reject loopback/RFC-1918 targets."),
    ("HIGH",     "Run LiteLLM container with no IAM instance profile or a least-privilege role; disable IMDS v1."),
    ("MEDIUM",   "Enable structured JSON logging and ship to a SIEM with alerting on /config/update POST events."),
    ("MEDIUM",   "Pin litellm package to a known-good version; subscribe to advisories at github.com/BerriAI/litellm/security."),
    ("INFO",     "Conduct periodic egress scanning (e.g., nmap -sn 169.254.0.0/16) from within the container network to detect misconfigured routes."),
]


def scan_logs(path: str) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "INFO": 0}
    scan_ts = datetime.now(timezone.utc).isoformat()
    try:
        with open(path, "r", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        print(f"[ERROR] Cannot open log file: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"=== LiteLLM SSRF-to-RCE Scan  |  {scan_ts}  |  {len(lines)} lines ===\n")
    hits = []
    for lineno, raw in enumerate(lines, start=1):
        line = raw.rstrip()
        for severity, regex, desc in COMPILED:
            if regex.search(line):
                hits.append((lineno, severity, desc, line))
                counts[severity] += 1
                break

    if not hits:
        print("No SSRF/RCE indicators detected.\n")
    else:
        for lineno, severity, desc, line in hits:
            print(f"[{severity}] line {lineno:>6}  {desc}")
            print(f"           {line[:200]}")
            print()

    print(f"Summary — CRITICAL: {counts['CRITICAL']}  HIGH: {counts['HIGH']}  INFO: {counts['INFO']}\n")
    return counts


def print_checklist() -> None:
    print("=== LiteLLM Hardening Checklist (ordered by exploitation chain stage) ===\n")
    for idx, (priority, item) in enumerate(CHECKLIST, start=1):
        print(f"  {idx:>2}. [{priority}] {item}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan LiteLLM logs for SSRF-to-RCE indicators and emit a hardening checklist.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python litellm_ssrf_detector.py --log access.log\n"
            "  python litellm_ssrf_detector.py --log access.log --mode scan --host prod-gateway\n"
            "  python litellm_ssrf_detector.py --log access.log --mode checklist\n"
        ),
    )
    parser.add_argument("--log", metavar="<path>", help="Plain-text log file to scan.")
    parser.add_argument(
        "--mode",
        choices=["scan", "checklist", "both"],
        default="both",
        help="Output scan findings, hardening checklist, or both (default: both).",
    )
    parser.add_argument("--host", metavar="<hostname>", default="", help="LiteLLM instance label for report header.")
    args = parser.parse_args()

    if args.host:
        print(f"Target host: {args.host}\n")

    if args.mode in ("scan", "both") and not args.log:
        parser.error("--log is required when --mode is 'scan' or 'both'.")

    counts = {"CRITICAL": 0, "HIGH": 0, "INFO": 0}

    if args.mode in ("scan", "both"):
        counts = scan_logs(args.log)

    if args.mode in ("checklist", "both"):
        print_checklist()

    if counts.get("CRITICAL", 0) > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()