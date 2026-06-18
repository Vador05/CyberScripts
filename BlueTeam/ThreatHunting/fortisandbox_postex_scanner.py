#!/usr/bin/env python3
"""
FortiSandbox Post-Exploitation Scanner

Applies embedded Sigma-style detection rules to plain text FortiSandbox/FortiGate
logs to surface post-exploitation indicators consistent with the 30,000-credential
compromise baseline.

Usage:
    python fortisandbox_postex_scanner.py /var/log/fortigate.log
    python fortisandbox_postex_scanner.py /var/log/fortigate.log --severity high
    python fortisandbox_postex_scanner.py /var/log/fortigate.log --json
    python fortisandbox_postex_scanner.py /var/log/fortigate.log --severity critical --json
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MAX_LINE_BYTES = 8192


def load_rules():
    raw = [
        {
            "id": "FSB-001",
            "name": "credential_dump_attempt",
            "severity": "critical",
            "patterns": [
                r"(passwd|shadow|\.htpasswd|/etc/passwd)",
                r"(cat|more|less|type|strings)\s",
            ],
        },
        {
            "id": "FSB-002",
            "name": "config_export_via_cli",
            "severity": "critical",
            "patterns": [
                r"(show\s+full-configuration|execute\s+backup|config\s+system\s+global)",
                r"(admin|root|superadmin)",
            ],
        },
        {
            "id": "FSB-003",
            "name": "admin_session_hijack",
            "severity": "high",
            "patterns": [
                r"(session[_\-]?id|APSCOOKIE|auth[_\-]?token)",
                r"(stolen|replay|reuse|forged|invalid\s+session)",
            ],
        },
        {
            "id": "FSB-004",
            "name": "lateral_movement_ssh",
            "severity": "high",
            "patterns": [
                r"(ssh|scp|sftp)\s+.*@",
                r"(accepted\s+password|publickey\s+for)",
            ],
        },
        {
            "id": "FSB-005",
            "name": "vpn_credential_spray",
            "severity": "high",
            "patterns": [
                r"(ssl-vpn|sslvpn|tunnel\s+login)",
                r"(failed|invalid|wrong|bad)\s+(password|credential|auth)",
            ],
        },
        {
            "id": "FSB-006",
            "name": "reverse_shell_indicator",
            "severity": "critical",
            "patterns": [
                r"(bash\s+-i|nc\s+-[el]|/dev/tcp/|python.*socket|perl.*socket)",
                r"(exec|spawn|popen|system|shell_exec)",
            ],
        },
        {
            "id": "FSB-007",
            "name": "privilege_escalation_attempt",
            "severity": "high",
            "patterns": [
                r"(sudo|su\s+-|chmod\s+[0-9]*[67][0-9]*|chown\s+root)",
                r"(permission\s+denied|operation\s+not\s+permitted|setuid)",
            ],
        },
        {
            "id": "FSB-008",
            "name": "suspicious_file_download",
            "severity": "medium",
            "patterns": [
                r"(wget|curl|fetch|invoke-webrequest)",
                r"(http://|https://|ftp://)",
            ],
        },
        {
            "id": "FSB-009",
            "name": "log_tampering",
            "severity": "high",
            "patterns": [
                r"(rm\s+-rf?|truncate|>\s*/var/log|shred)",
                r"(log|audit|syslog|messages)",
            ],
        },
        {
            "id": "FSB-010",
            "name": "known_exploit_path",
            "severity": "critical",
            "patterns": [
                r"(CVE-2022-4[0-9]{4}|CVE-2023-2[0-9]{4}|FG-IR-22|FG-IR-23)",
                r"(exploit|poc|payload|shellcode)",
            ],
        },
        {
            "id": "FSB-011",
            "name": "mass_credential_access",
            "severity": "critical",
            "patterns": [
                r"(30[,.]?000|mass\s+credential|credential\s+dump)",
                r"(fortigate|fortisandbox|forticlient)",
            ],
        },
        {
            "id": "FSB-012",
            "name": "anomalous_admin_login",
            "severity": "medium",
            "patterns": [
                r"(login\s+successful|admin\s+login|authenticated)",
                r"(unusual|unexpected|foreign|unknown)\s+(ip|source|location|country)",
            ],
        },
    ]
    compiled = []
    for rule in raw:
        compiled.append({
            "id": rule["id"],
            "name": rule["name"],
            "severity": rule["severity"],
            "field_patterns": [re.compile(p, re.IGNORECASE) for p in rule["patterns"]],
        })
    return compiled


def scan_log(path, rules, min_severity):
    min_rank = SEVERITY_RANK[min_severity]
    abs_path = os.path.abspath(path)
    cwd = os.path.abspath(os.getcwd())
    if not (abs_path.startswith(cwd) or os.path.exists(abs_path)):
        raise ValueError(f"Path not accessible: {path}")
    if not os.path.isfile(abs_path):
        raise FileNotFoundError(f"Log file not found: {abs_path}")
    with open(abs_path, "r", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            if len(raw.encode("utf-8", errors="replace")) > MAX_LINE_BYTES:
                continue
            line = raw.rstrip("\n")
            for rule in rules:
                if SEVERITY_RANK[rule["severity"]] < min_rank:
                    continue
                if all(p.search(line) for p in rule["field_patterns"]):
                    ts_match = re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", line)
                    timestamp = ts_match.group(0) if ts_match else datetime.utcnow().isoformat(timespec="seconds")
                    yield {
                        "timestamp": timestamp,
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "lineno": lineno,
                        "raw_line": line,
                    }


def main():
    parser = argparse.ArgumentParser(
        description="Detect post-exploitation indicators in FortiSandbox/FortiGate logs."
    )
    parser.add_argument("log_file", help="Path to plain-text FortiSandbox/FortiGate log file")
    parser.add_argument(
        "--severity",
        choices=list(SEVERITY_RANK),
        default="medium",
        help="Minimum severity threshold to report (default: medium)",
    )
    parser.add_argument("--json", dest="json_out", action="store_true", help="Emit newline-delimited JSON")
    args = parser.parse_args()

    try:
        rules = load_rules()
        matches = list(scan_log(args.log_file, rules, args.severity))
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)

    matches.sort(key=lambda m: (-SEVERITY_RANK[m["severity"]], m["lineno"]))

    has_critical = False
    for m in matches:
        if m["severity"] == "critical":
            has_critical = True
        if args.json_out:
            print(json.dumps(m))
        else:
            print(f"[{m['severity'].upper():8s}] {m['timestamp']}  {m['rule_id']} {m['rule_name']}  line {m['lineno']}: {m['raw_line'][:120]}")

    if not matches:
        msg = {"status": "no_findings", "min_severity": args.severity}
        print(json.dumps(msg) if args.json_out else f"No findings at or above '{args.severity}' severity.")

    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()