"""
NPM IOC Log Scanner - Detects TeamPCP supply chain campaign indicators in CI/CD and npm audit logs.

Usage:
    python npm_ioc_log_scanner.py /var/log/ci/build.log
    python npm_ioc_log_scanner.py /var/log/ci/ --severity high
    python npm_ioc_log_scanner.py audit.log --rules extra_iocs.json --severity medium

Example extra_iocs.json:
    [{"name": "custom_pkg", "pattern": "evil-package", "severity": "high", "description": "Custom IOC"}]
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

BUILTIN_RULES = [
    {"name": "teampcp_pkg_colors2", "pattern": r"\bcolors2\b", "severity": "high", "description": "Known malicious TeamPCP package"},
    {"name": "teampcp_pkg_node_colors", "pattern": r"\bnode-colors\b", "severity": "high", "description": "Known malicious TeamPCP package"},
    {"name": "teampcp_pkg_npmutils", "pattern": r"\bnpmutils\b", "severity": "high", "description": "Known malicious TeamPCP package"},
    {"name": "teampcp_pkg_loadyaml", "pattern": r"\bload-yaml\b", "severity": "high", "description": "Known malicious TeamPCP package"},
    {"name": "teampcp_pkg_discordjs_v11", "pattern": r"\bdiscord\.js@11\b", "severity": "high", "description": "Known malicious TeamPCP lookalike"},
    {"name": "teampcp_pkg_logutil", "pattern": r"\blog-util\b", "severity": "high", "description": "Known malicious TeamPCP package"},
    {"name": "teampcp_pkg_eslint_scopes", "pattern": r"\belectron-native-notify\b", "severity": "high", "description": "Known supply chain package"},
    {"name": "postinstall_curl_pipe", "pattern": r"postinstall.*curl\s+.*\|.*sh", "severity": "high", "description": "Postinstall curl pipe to shell"},
    {"name": "postinstall_wget_pipe", "pattern": r"postinstall.*wget\s+.*\|.*sh", "severity": "high", "description": "Postinstall wget pipe to shell"},
    {"name": "postinstall_node_exec", "pattern": r"postinstall.*node\s+-e\s+['\"]", "severity": "high", "description": "Postinstall inline node execution"},
    {"name": "postinstall_base64_decode", "pattern": r"postinstall.*base64\s+--decode", "severity": "high", "description": "Postinstall base64 decode execution"},
    {"name": "exfil_dns_lookup", "pattern": r"nslookup\s+\S+\.burpcollaborator\.net", "severity": "high", "description": "DNS exfiltration to Burp Collaborator"},
    {"name": "exfil_interactsh", "pattern": r"[a-z0-9\-]+\.interact\.sh", "severity": "high", "description": "Exfiltration via interactsh"},
    {"name": "env_exfil_home", "pattern": r"process\.env\.HOME.*http", "severity": "high", "description": "Environment variable exfiltration"},
    {"name": "env_exfil_npm_token", "pattern": r"NPM_TOKEN.*curl|curl.*NPM_TOKEN", "severity": "high", "description": "NPM token exfiltration attempt"},
    {"name": "suspicious_registry", "pattern": r"registry\s*=\s*https?://(?!registry\.npmjs\.org)[^\s]+", "severity": "medium", "description": "Non-standard npm registry"},
    {"name": "postinstall_powershell", "pattern": r"postinstall.*powershell\s+-[Ee]nc", "severity": "high", "description": "Postinstall PowerShell encoded command"},
    {"name": "typosquat_lodash", "pattern": r"\b(lodahs|Iodash|lodash-|l0dash)\b", "severity": "medium", "description": "Lodash typosquat candidate"},
    {"name": "typosquat_express", "pattern": r"\b(expresss|expres|xpress-)\b", "severity": "medium", "description": "Express typosquat candidate"},
    {"name": "crypto_miner_stratum", "pattern": r"stratum\+tcp://", "severity": "high", "description": "Crypto miner stratum protocol"},
    {"name": "reverse_shell_bash", "pattern": r"bash\s+-i\s+>&\s+/dev/tcp/", "severity": "high", "description": "Bash reverse shell"},
    {"name": "npm_lifecycle_preinstall_exec", "pattern": r"npm\s+lifecycle.*preinstall.*node\s", "severity": "medium", "description": "Suspicious preinstall lifecycle hook"},
    {"name": "outbound_aws_metadata", "pattern": r"169\.254\.169\.254", "severity": "high", "description": "AWS metadata service access attempt"},
    {"name": "suspicious_npm_publish", "pattern": r"npm\s+publish\s+--access\s+public\b", "severity": "low", "description": "Public npm publish in CI context"},
    {"name": "bundled_binary_sh", "pattern": r"\.(sh|bash)\s+.*node_modules/[^/]+/", "severity": "medium", "description": "Shell script execution from node_modules"},
]

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def load_rules(rules_path=None):
    rules = list(BUILTIN_RULES)
    if rules_path:
        try:
            with open(rules_path, "r", encoding="utf-8") as f:
                extra = json.load(f)
            if not isinstance(extra, list):
                raise ValueError("Rules JSON must be a list of rule objects")
            for r in extra:
                if not all(k in r for k in ("name", "pattern", "severity")):
                    raise ValueError(f"Rule missing required fields: {r}")
                if r["severity"] not in SEVERITY_ORDER:
                    raise ValueError(f"Invalid severity '{r['severity']}' in rule '{r['name']}'")
            rules.extend(extra)
        except (OSError, json.JSONDecodeError, ValueError) as e:
            print(f"[ERROR] Failed to load rules from {rules_path}: {e}", file=sys.stderr)
            sys.exit(2)
    compiled = []
    for rule in rules:
        try:
            compiled.append({**rule, "_re": re.compile(rule["pattern"], re.IGNORECASE)})
        except re.error as e:
            print(f"[ERROR] Invalid regex in rule '{rule['name']}': {e}", file=sys.stderr)
            sys.exit(2)
    return compiled


def scan_log(file_path, rules, min_severity):
    min_level = SEVERITY_ORDER[min_severity]
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                line = line.rstrip("\n")
                for rule in rules:
                    if SEVERITY_ORDER[rule["severity"]] < min_level:
                        continue
                    m = rule["_re"].search(line)
                    if m:
                        yield {
                            "file": str(file_path),
                            "lineno": lineno,
                            "rule": rule["name"],
                            "severity": rule["severity"],
                            "description": rule.get("description", ""),
                            "snippet": line.strip()[:120],
                        }
    except OSError as e:
        print(f"[ERROR] Cannot read {file_path}: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Scan npm/CI logs for TeamPCP supply chain IOCs.")
    parser.add_argument("log_path", help="Path to log file or directory of log files")
    parser.add_argument("--rules", metavar="FILE", help="JSON file with additional IOC patterns")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low", help="Minimum severity to report (default: low)")
    args = parser.parse_args()

    rules = load_rules(args.rules)
    target = Path(args.log_path)

    if target.is_dir():
        log_files = [p for p in target.rglob("*") if p.is_file()]
    elif target.is_file():
        log_files = [target]
    else:
        print(f"[ERROR] Path not found: {target}", file=sys.stderr)
        sys.exit(2)

    counts = {"low": 0, "medium": 0, "high": 0}
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for log_file in sorted(log_files):
        for hit in scan_log(log_file, rules, args.severity):
            counts[hit["severity"]] += 1
            print(f"[{ts}] [{hit['severity'].upper():6}] {hit['rule']} | {hit['file']}:{hit['lineno']} | {hit['description']} | {hit['snippet']}")

    total = sum(counts.values())
    print(f"\nSummary: {total} finding(s) — high={counts['high']} medium={counts['medium']} low={counts['low']}")

    if counts["high"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()