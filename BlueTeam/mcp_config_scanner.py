"""
MCP Config Scanner - Detects misconfigurations and supply-chain risks in MCP server configs.

Usage:
    python mcp_config_scanner.py path/to/mcp_config.json
    python mcp_config_scanner.py path/to/configs/ --severity high
    python mcp_config_scanner.py path/to/mcp_config.json --rules custom_rules.json --severity medium
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime

BUILTIN_RULES = [
    {
        "name": "hardcoded_api_key",
        "description": "Hardcoded API key detected",
        "pattern": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}",
        "severity": "high",
        "remediation": "Use environment variables or a secrets manager instead of hardcoding API keys."
    },
    {
        "name": "hardcoded_password",
        "description": "Hardcoded password or secret detected",
        "pattern": r"(?i)(?<![a-z0-9_])(password|passwd|secret|token)(?![a-z0-9_])\s*[:=]\s*['\"]?[A-Za-z0-9+/=_\-]{20,}",
        "severity": "high",
        "remediation": "Replace hardcoded credentials with environment variable references."
    },
    {
        "name": "aws_access_key",
        "description": "AWS access key ID detected",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "high",
        "remediation": "Rotate this AWS key immediately and use IAM roles or environment variables."
    },
    {
        "name": "aws_secret_key",
        "description": "AWS secret access key detected",
        "pattern": r"(?i)aws.{0,20}secret.{0,20}['\"]?[A-Za-z0-9/+]{40}",
        "severity": "high",
        "remediation": "Rotate this AWS secret key and use IAM roles or environment variables."
    },
    {
        "name": "unverified_npm_package",
        "description": "NPM package installed from unverified or local source",
        "pattern": r"(npx|npm\s+install)\s+[^-].*\.(git|tgz|tar\.gz)|file:",
        "severity": "high",
        "remediation": "Use packages from the official NPM registry with pinned versions."
    },
    {
        "name": "unpinned_package_version",
        "description": "Package installed without pinned version",
        "pattern": r"(npx|pip\s+install|npm\s+install)\s+[a-zA-Z0-9_\-]+\s*$",
        "severity": "medium",
        "remediation": "Pin package versions to prevent supply chain attacks via version updates."
    },
    {
        "name": "wildcard_tool_permission",
        "description": "Wildcard or overly broad tool permission",
        "pattern": r"\*|all|any",
        "severity": "medium",
        "remediation": "Restrict tool permissions to only the specific tools required.",
        "keys_only": True,
        "key_pattern": r"(?i)(permission|allow|grant|scope)"
    },
    {
        "name": "localhost_binding",
        "description": "Server bound to all interfaces (0.0.0.0)",
        "pattern": r"0\.0\.0\.0",
        "severity": "medium",
        "remediation": "Bind to localhost (127.0.0.1) unless external access is explicitly required."
    },
    {
        "name": "debug_mode_enabled",
        "description": "Debug mode enabled in configuration",
        "pattern": r"(?i)^true$",
        "severity": "low",
        "remediation": "Disable debug mode in production environments.",
        "keys_only": True,
        "key_pattern": r"(?i)(debug|verbose|trace)"
    },
    {
        "name": "http_not_https",
        "description": "Insecure HTTP URL used instead of HTTPS",
        "pattern": r"http://(?!localhost|127\.0\.0\.1)",
        "severity": "medium",
        "remediation": "Use HTTPS for all external URLs to prevent man-in-the-middle attacks."
    },
    {
        "name": "private_key_material",
        "description": "Private key or certificate material detected",
        "pattern": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "severity": "high",
        "remediation": "Remove private key material from config files; reference key file paths instead."
    },
    {
        "name": "shell_injection_risk",
        "description": "Potential shell injection via unescaped command string",
        "pattern": r";\s*(rm|curl|wget|bash|sh|python|exec)\s",
        "severity": "high",
        "remediation": "Avoid constructing shell commands from config values; use parameterized execution."
    },
]


def load_rules(custom_rules_path=None):
    rules = list(BUILTIN_RULES)
    if not custom_rules_path:
        return rules
    try:
        with open(custom_rules_path, "r") as f:
            custom = json.load(f)
        if not isinstance(custom, list):
            print(f"[WARNING] Custom rules file must contain a JSON array; ignoring.", file=sys.stderr)
            return rules
        for rule in custom:
            required = {"name", "pattern", "severity", "remediation"}
            if not required.issubset(rule.keys()):
                print(f"[WARNING] Skipping malformed custom rule (missing fields): {rule.get('name', '<unnamed>')}", file=sys.stderr)
                continue
            if rule["severity"] not in ("low", "medium", "high"):
                print(f"[WARNING] Skipping rule '{rule['name']}' with invalid severity '{rule['severity']}'", file=sys.stderr)
                continue
            try:
                re.compile(rule["pattern"])
            except re.error as e:
                print(f"[WARNING] Skipping rule '{rule['name']}' with invalid regex pattern: {e}", file=sys.stderr)
                continue
            rules.append(rule)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[WARNING] Could not load custom rules from '{custom_rules_path}': {e}", file=sys.stderr)
    return rules


def scan_config(config, rules, path="root", key_context=None):
    findings = []
    if isinstance(config, dict):
        for key, value in config.items():
            current_path = f"{path}.{key}"
            for rule in rules:
                key_pattern = rule.get("key_pattern")
                if key_pattern and not re.search(key_pattern, key):
                    continue
                if isinstance(value, str):
                    try:
                        if re.search(rule["pattern"], value):
                            findings.append({
                                "rule": rule["name"],
                                "description": rule.get("description", rule["name"]),
                                "severity": rule["severity"],
                                "path": current_path,
                                "matched_value": value[:120] + ("..." if len(value) > 120 else ""),
                                "remediation": rule["remediation"],
                            })
                    except re.error:
                        pass
            # Only recurse into compound types; strings are fully handled in the loop above
            # to avoid matching the same string twice (once with key context, once without).
            # Pass key as key_context so keys_only rules can fire on strings inside lists.
            if not isinstance(value, str):
                findings.extend(scan_config(value, rules, current_path, key_context=key))
    elif isinstance(config, list):
        for i, item in enumerate(config):
            findings.extend(scan_config(item, rules, f"{path}[{i}]", key_context=key_context))
    elif isinstance(config, str):
        for rule in rules:
            if rule.get("keys_only"):
                # keys_only rules require a parent key context to be meaningful
                if key_context is None:
                    continue
                key_pattern = rule.get("key_pattern")
                if key_pattern and not re.search(key_pattern, key_context):
                    continue
            try:
                if re.search(rule["pattern"], config):
                    findings.append({
                        "rule": rule["name"],
                        "description": rule.get("description", rule["name"]),
                        "severity": rule["severity"],
                        "path": path,
                        "matched_value": config[:120] + ("..." if len(config) > 120 else ""),
                        "remediation": rule["remediation"],
                    })
            except re.error:
                pass
    return findings


def collect_config_files(config_path):
    if os.path.isfile(config_path):
        return [config_path]
    if os.path.isdir(config_path):
        return [
            os.path.join(root, fname)
            for root, _, files in os.walk(config_path)
            for fname in files
            if fname.endswith(".json")
        ]
    return []


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def main():
    parser = argparse.ArgumentParser(description="Scan MCP server config files for misconfigurations and supply-chain risks.")
    parser.add_argument("config_path", help="Path to MCP config file or directory")
    parser.add_argument("--rules", dest="rules_path", default=None, help="Path to custom rules JSON file")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low", help="Minimum severity to report (default: low)")
    args = parser.parse_args()

    rules = load_rules(args.rules_path)
    config_files = collect_config_files(args.config_path)

    if not config_files:
        print(f"[ERROR] No JSON config files found at '{args.config_path}'", file=sys.stderr)
        sys.exit(1)

    all_findings = []
    for config_file in config_files:
        try:
            with open(config_file, "r") as fh:
                config = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            print(f"[WARNING] Could not parse '{config_file}': {e}", file=sys.stderr)
            continue
        findings = scan_config(config, rules)
        for finding in findings:
            finding["file"] = config_file
        all_findings.extend(findings)

    min_severity = SEVERITY_ORDER[args.severity]
    filtered = [f for f in all_findings if SEVERITY_ORDER[f["severity"]] >= min_severity]
    filtered.sort(key=lambda x: -SEVERITY_ORDER[x["severity"]])

    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"MCP Config Scanner — {timestamp}")
    print(f"Files scanned: {len(config_files)} | Rules loaded: {len(rules)} | Findings: {len(filtered)}")
    print("=" * 72)

    if not filtered:
        print("No findings at or above the specified severity threshold.")
    else:
        for finding in filtered:
            print(f"[{finding['severity'].upper()}] {finding['rule']}")
            print(f"  File    : {finding['file']}")
            print(f"  Path    : {finding['path']}")
            print(f"  Matched : {finding['matched_value']}")
            print(f"  Fix     : {finding['remediation']}")
            print()

    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in filtered:
        counts[finding["severity"]] += 1
    print(f"Summary — High: {counts['high']}  Medium: {counts['medium']}  Low: {counts['low']}")


if __name__ == "__main__":
    main()