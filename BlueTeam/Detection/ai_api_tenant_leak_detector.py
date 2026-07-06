"""
AI API Cross-Tenant Leak Detector

Scans plain-text AI platform API access logs for cross-tenant data leakage
patterns modeled on known Dify vulnerabilities.

Usage:
    python ai_api_tenant_leak_detector.py access.log
    python ai_api_tenant_leak_detector.py access.log --tenant-id a1b2c3d4-e5f6-7890-abcd-ef1234567890
    python ai_api_tenant_leak_detector.py access.log --strict
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone

MAX_LINE_LEN = 8192

LOG_PATTERN = re.compile(
    r'(?P<timestamp>\S+\s+\S+|\S+)'
    r'\s+"?(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?P<path>\S+)\s+HTTP/[^"]*"?'
    r'.*?\s(?P<status_code>\d{3})\s'
    r'(?:.*?(?:X-Tenant-ID|tenant[_-]id)[:=]\s*(?P<tenant>[0-9a-f-]{36}))?',
    re.IGNORECASE,
)

UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)

RULES = [
    {
        "rule_id": "DIFY-001",
        "severity": "HIGH",
        "description": "Document preview bypass — successful access to document preview endpoint",
        "pattern": re.compile(r'/datasets/[^/]+/documents/[^/]+/preview', re.IGNORECASE),
        "methods": {"GET"},
        "status_trigger": lambda s: s in {200, 206},
        "detail": "Document preview endpoint returned success; authentication state not derivable from log — review request for authorization controls, possible CVE-pattern preview bypass",
    },
    {
        "rule_id": "DIFY-002",
        "severity": "CRITICAL",
        "description": "Internal console API exposed — non-admin context reaching /console/api/",
        "pattern": re.compile(r'/console/api/', re.IGNORECASE),
        "methods": {"GET", "POST", "PUT", "DELETE", "PATCH"},
        "status_trigger": lambda s: s < 403,
        "detail": "Internal console API reached without admin context; possible privilege escalation path",
    },
    {
        "rule_id": "DIFY-003",
        "severity": "HIGH",
        "description": "Cross-tenant IDOR on dataset endpoint — path tenant differs from auth scope",
        "pattern": re.compile(r'/datasets/(?P<path_tenant>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.IGNORECASE),
        "methods": {"GET", "POST", "PUT", "DELETE", "PATCH"},
        "status_trigger": lambda s: s < 400,
        "detail": "Tenant UUID in dataset path does not match authenticated tenant scope",
    },
]


def parse_log_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, 1):
                if len(raw) > MAX_LINE_LEN:
                    continue
                line = raw.rstrip("\n")
                m = LOG_PATTERN.search(line)
                if not m:
                    continue
                try:
                    status = int(m.group("status_code"))
                except (TypeError, ValueError):
                    continue
                yield {
                    "lineno": lineno,
                    "raw": line,
                    "timestamp": m.group("timestamp") or "",
                    "method": m.group("method").upper(),
                    "path": m.group("path"),
                    "status_code": status,
                    "log_tenant": m.group("tenant"),
                }
    except OSError as exc:
        print(f"ERROR: cannot open log file: {exc}", file=sys.stderr)
        sys.exit(2)


def detect_violations(entries, tenant_id):
    for entry in entries:
        method = entry["method"]
        path = entry["path"]
        status = entry["status_code"]
        log_tenant = entry.get("log_tenant")

        for rule in RULES:
            if method not in rule["methods"]:
                continue
            m = rule["pattern"].search(path)
            if not m:
                continue
            if not rule["status_trigger"](status):
                continue

            matched_tenant = log_tenant
            detail = rule["detail"]

            if rule["rule_id"] == "DIFY-003":
                path_tenant = m.group("path_tenant")
                if not tenant_id and not log_tenant:
                    matched_tenant = path_tenant
                    detail = f"{detail} (path tenant: {path_tenant}, no auth scope present)"
                elif tenant_id and path_tenant:
                    if path_tenant.lower() == tenant_id.lower():
                        continue
                    matched_tenant = path_tenant
                    detail = f"{detail} (path: {path_tenant}, expected: {tenant_id})"
                elif log_tenant and path_tenant and log_tenant.lower() != path_tenant.lower():
                    matched_tenant = path_tenant
                    detail = f"{detail} (path: {path_tenant}, header: {log_tenant})"
                else:
                    continue

            yield {
                "timestamp": entry["timestamp"],
                "rule_id": rule["rule_id"],
                "severity": rule["severity"],
                "method": method,
                "path": path,
                "status_code": status,
                "matched_tenant": matched_tenant,
                "detail": detail,
                "lineno": entry["lineno"],
            }


def emit_findings(findings, strict):
    count = 0
    for finding in findings:
        out = {k: v for k, v in finding.items() if k != "lineno"}
        print(json.dumps(out, separators=(",", ":")))
        count += 1
        if strict:
            summary = {
                "summary": f"{count} finding(s) detected",
                "count": count,
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            }
            print(json.dumps(summary, separators=(",", ":")), file=sys.stderr)
            sys.exit(1)

    summary = {
        "summary": f"{count} finding(s) detected",
        "count": count,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    print(json.dumps(summary, separators=(",", ":")), file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Detect cross-tenant data leakage in AI platform API logs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("log_file", help="Path to plain-text API access log, one request per line")
    parser.add_argument("--tenant-id", metavar="UUID", help="Expected tenant UUID to scope analysis")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero on first finding (CI/CD gate mode)")
    args = parser.parse_args()

    if args.tenant_id and not UUID_RE.fullmatch(args.tenant_id):
        print(f"ERROR: --tenant-id must be a valid UUID, got: {args.tenant_id}", file=sys.stderr)
        sys.exit(2)

    entries = parse_log_lines(args.log_file)
    findings = detect_violations(entries, args.tenant_id)
    emit_findings(findings, args.strict)


if __name__ == "__main__":
    main()