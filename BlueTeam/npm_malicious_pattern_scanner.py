"""
NPM Malicious Pattern Scanner - Detects credential-stealer IOCs in npm logs.

Usage:
    python npm_malicious_pattern_scanner.py install.log
    python npm_malicious_pattern_scanner.py - < install.log
    python npm_malicious_pattern_scanner.py install.log --patterns custom.json --strict
    npm install 2>&1 | python npm_malicious_pattern_scanner.py -

Output (TSV): timestamp<TAB>severity<TAB>rule<TAB>package<TAB>matched_line
Exit codes: 0=clean, 1=findings detected, 2=error
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone

BUILTIN_PATTERNS = [
    {
        "name": "postinstall_curl_wget",
        "severity": "CRITICAL",
        "regex": r"\b(?:postinstall|install)\b.*(?:curl|wget)\s+https?://",
    },
    {
        "name": "env_bulk_read",
        "severity": "CRITICAL",
        "regex": r"process\.env\b(?!\.\w)",
    },
    {
        "name": "base64_decode_exec",
        "severity": "CRITICAL",
        "regex": r"(?:base64\s+-d|atob|Buffer\.from\([^)]+,\s*['\"]base64['\"])\s*\|?\s*(?:sh|bash|exec|eval)",
    },
    {
        "name": "ssh_key_access",
        "severity": "HIGH",
        "regex": r"~/\.ssh/|/root/\.ssh/|\$HOME/\.ssh/",
    },
    {
        "name": "aws_credential_access",
        "severity": "HIGH",
        "regex": r"~/\.aws/credentials|/\.aws/credentials|\$AWS_SECRET",
    },
    {
        "name": "shell_drop_postinstall",
        "severity": "HIGH",
        "regex": r"\"postinstall\"\s*:\s*\"(?:sh|bash|node)\s+-[ce]",
    },
    {
        "name": "outbound_exfil",
        "severity": "HIGH",
        "regex": r"(?:curl|wget|\bfetch\b|http\.request)\s+.*(?:\$HOME|\$USER|\$PATH|process\.env)",
    },
    {
        "name": "encoded_payload",
        "severity": "HIGH",
        "regex": r"(?:eval\s*\(|Function\s*\()[^)]*(?:atob|base64|unescape|decodeURI)",
    },
    {
        "name": "npm_hook_hijack",
        "severity": "MEDIUM",
        "regex": r"\"(?:preinstall|postinstall|prepublish)\"\s*:\s*\".*(?:&&|\|\|).*\"",
    },
    {
        "name": "suspicious_dns_lookup",
        "severity": "MEDIUM",
        "regex": r"(?:dns\.lookup|nslookup|dig)\s+.*(?:\$|process\.env|`)",
    },
    {
        "name": "write_to_system_path",
        "severity": "MEDIUM",
        "regex": r"(?:cp|mv|tee|>)\s+/(?:etc|usr|bin|sbin|lib)/",
    },
    {
        "name": "git_credential_steal",
        "severity": "HIGH",
        "regex": r"~/\.gitconfig|git\s+config\s+--global\s+credential",
    },
]

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

PACKAGE_RE = re.compile(
    r"(?:npm\s+\w+\s+|added\s+\d+\s+packages.*\s+|postinstall\s+)"
    r"([a-zA-Z0-9@/._-]+@[\d][^\s]*)"
)

# Protect against adversarially long lines causing backtracking DoS.
_MAX_LINE_LEN = 4096

# Control characters that corrupt TSV output or terminal display.
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _tsv_safe(s):
    """Replace ASCII control characters (including CR, LF, TAB) with spaces."""
    return _CTRL_RE.sub(" ", s)


def load_patterns(path=None):
    rules = []
    seen_names = set()

    if path:
        try:
            with open(path, encoding="utf-8") as f:
                custom = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Failed to load custom patterns from {path}: {exc}") from exc

        if not isinstance(custom, list):
            raise ValueError(f"Custom pattern file must be a JSON array, got {type(custom).__name__}")

        for entry in custom:
            if not isinstance(entry, dict) or "name" not in entry or "regex" not in entry:
                raise ValueError(f"Each pattern must have 'name' and 'regex' keys: {entry}")
            severity = entry.get("severity", "MEDIUM").upper()
            if severity not in VALID_SEVERITIES:
                raise ValueError(
                    f"Invalid severity '{entry.get('severity')}' in pattern '{entry['name']}'; "
                    f"must be one of {sorted(VALID_SEVERITIES)}"
                )
            try:
                compiled = re.compile(entry["regex"])
            except re.error as exc:
                raise ValueError(f"Invalid regex in pattern '{entry['name']}': {exc}") from exc
            rules.append({
                "name": entry["name"],
                "severity": severity,
                "compiled": compiled,
            })
            seen_names.add(entry["name"])

    for p in BUILTIN_PATTERNS:
        if p["name"] not in seen_names:
            rules.append({
                "name": p["name"],
                "severity": p["severity"],
                "compiled": re.compile(p["regex"]),
            })

    return rules


def extract_package(line):
    m = PACKAGE_RE.search(line)
    return m.group(1) if m else "unknown"


def scan_log(lines, patterns):
    for raw_line in lines:
        line = raw_line.rstrip("\n")
        if len(line) > _MAX_LINE_LEN:
            line = line[:_MAX_LINE_LEN]
        for rule in patterns:
            if rule["compiled"].search(line):
                yield rule["severity"], rule["name"], extract_package(line), line


def main():
    parser = argparse.ArgumentParser(
        description="Scan npm install/audit logs for malicious behavioral patterns.",
        epilog="Exit 0=clean, 1=findings, 2=error",
    )
    parser.add_argument("log_file", help="Path to npm log file, or '-' for stdin")
    parser.add_argument("--patterns", metavar="FILE", help="JSON file with custom regex rules")
    parser.add_argument("--strict", action="store_true", help="Exit 1 on any finding, not just CRITICAL")
    args = parser.parse_args()

    try:
        patterns = load_patterns(args.patterns)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)

    try:
        if args.log_file == "-":
            lines = sys.stdin
        else:
            lines = open(args.log_file, encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"ERROR: Cannot open log file: {exc}", file=sys.stderr)
        sys.exit(2)

    found_critical = False
    found_any = False
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        for severity, rule, package, line in scan_log(lines, patterns):
            found_any = True
            if severity == "CRITICAL":
                found_critical = True
            safe_line = _tsv_safe(line)
            safe_rule = _tsv_safe(rule)
            print(f"{ts}\t{severity}\t{safe_rule}\t{package}\t{safe_line}")
    except OSError as exc:
        print(f"ERROR: Failed reading log: {exc}", file=sys.stderr)
        sys.exit(2)
    finally:
        if args.log_file != "-":
            lines.close()

    if found_critical or (args.strict and found_any):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
