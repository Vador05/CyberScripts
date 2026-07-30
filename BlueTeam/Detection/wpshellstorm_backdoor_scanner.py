"""
WP-SHELLSTORM Backdoor Scanner

Scans WordPress PHP source files for backdoor indicators derived from IOCs
exposed in the WP-SHELLSTORM operation's own leaked server.

Usage:
    python wpshellstorm_backdoor_scanner.py /var/www/html/wordpress
    python wpshellstorm_backdoor_scanner.py /var/www/html/wordpress --min-severity high
    python wpshellstorm_backdoor_scanner.py /tmp/suspicious.php --rules extra_iocs.json
    python wpshellstorm_backdoor_scanner.py /var/www/html --rules iocs.json --min-severity medium

Exit code 1 if any high-severity finding is emitted.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Generator

SAFE_PATH_PREFIXES = [
    "wp-includes/class-smtp.php",
    "wp-includes/class-phpmailer.php",
    "wp-includes/ID3/",
    "wp-includes/Text/",
    "wp-includes/sodium_compat/",
    "wp-admin/includes/class-pclzip.php",
]

BUNDLED_RULES: list[dict] = [
    {"name": "eval_base64_decode_chain", "severity": "high",
     "pattern": r"eval\s*\(\s*base64_decode\s*\("},
    {"name": "preg_replace_e_modifier", "severity": "high",
     "pattern": r"preg_replace\s*\(\s*['\"].*?/e.*?['\"]"},
    {"name": "assert_request_input", "severity": "high",
     "pattern": r"assert\s*\(\s*\$_(REQUEST|POST|GET|COOKIE)"},
    {"name": "system_http_input", "severity": "high",
     "pattern": r"(system|exec|passthru|shell_exec|popen)\s*\(\s*\$_(REQUEST|POST|GET|COOKIE)"},
    {"name": "filesMan_fingerprint", "severity": "high",
     "pattern": r"FilesMan|\"FilesMan\"|b374k|Safe0ver"},
    {"name": "wso_webshell_fingerprint", "severity": "high",
     "pattern": r"WSO\s+\d+\.\d+|wso_authorization|\"WSO \""},
    {"name": "c99_webshell_fingerprint", "severity": "high",
     "pattern": r"c99shell|\"c99\"|c99_buff_prepare"},
    {"name": "hex_encoded_payload", "severity": "medium",
     "pattern": r"(\\x[0-9a-fA-F]{2}){8,}"},
    {"name": "gzinflate_base64_stack", "severity": "high",
     "pattern": r"gzinflate\s*\(\s*base64_decode\s*\("},
    {"name": "str_rot13_eval", "severity": "medium",
     "pattern": r"eval\s*\(\s*str_rot13\s*\("},
    {"name": "create_function_exec", "severity": "high",
     "pattern": r"create_function\s*\(\s*['\"][^'\"]*['\"],\s*\$_(REQUEST|POST|GET|COOKIE)"},
    {"name": "base64_gzinflate_stack", "severity": "high",
     "pattern": r"base64_decode\s*\(\s*gzinflate\s*\("},
    {"name": "variable_variable_exec", "severity": "medium",
     "pattern": r"\$\{\s*\$_(REQUEST|POST|GET|COOKIE)\s*\["},
    {"name": "php_uname_disclosure", "severity": "low",
     "pattern": r"php_uname\s*\(\s*['\"]a['\"]\s*\)"},
    {"name": "posix_getpwuid_recon", "severity": "low",
     "pattern": r"posix_getpwuid\s*\(\s*posix_geteuid"},
    {"name": "disable_functions_override", "severity": "medium",
     "pattern": r"ini_set\s*\(\s*['\"]disable_functions['\"]"},
    {"name": "chmod_world_writable", "severity": "medium",
     "pattern": r"chmod\s*\(\s*[^,]+,\s*0?777\s*\)"},
    {"name": "mail_header_injection", "severity": "medium",
     "pattern": r"mail\s*\([^)]*\$_(REQUEST|POST|GET)\s*\["},
    {"name": "wp_config_exfil_attempt", "severity": "high",
     "pattern": r"wp-config\.php.*?(fread|file_get_contents|readfile)"},
    {"name": "reverse_shell_indicator", "severity": "high",
     "pattern": r"(fsockopen|socket_create)\s*\([^)]*\$_(REQUEST|POST|GET)"},
]

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


def load_supplemental_rules(rules_path: str) -> list[dict]:
    try:
        with open(rules_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        rules = []
        for name, entry in data.items():
            if isinstance(entry, str):
                rules.append({"name": name, "severity": "medium", "pattern": entry})
            elif isinstance(entry, dict):
                severity = entry.get("severity", "medium")
                if severity not in SEVERITY_RANK:
                    print(f"[WARN] Invalid severity '{severity}' for rule '{name}', defaulting to 'medium'", file=sys.stderr)
                    severity = "medium"
                rules.append({"name": name, "severity": severity,
                               "pattern": entry["pattern"]})
        return rules
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"[ERROR] Failed to load supplemental rules from {rules_path}: {exc}", file=sys.stderr)
        sys.exit(2)


def is_safe_path(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/").lstrip("/")
    return any(normalized.startswith(prefix) for prefix in SAFE_PATH_PREFIXES)


def collect_php_files(target: str) -> Generator[tuple[str, str], None, None]:
    path = Path(target)
    if path.is_file():
        yield str(path.parent), str(path)
        return
    if not path.is_dir():
        print(f"[ERROR] Target not found: {target}", file=sys.stderr)
        sys.exit(2)
    root = str(path)
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            if filename.endswith(".php"):
                yield root, os.path.join(dirpath, filename)


def compile_rules(rules: list[dict]) -> list[dict]:
    compiled = []
    for rule in rules:
        try:
            compiled.append({**rule, "regex": re.compile(rule["pattern"], re.IGNORECASE)})
        except re.error as exc:
            print(f"[WARN] Skipping rule '{rule['name']}' — invalid regex: {exc}", file=sys.stderr)
    return compiled


def scan_file(root: str, filepath: str, compiled_rules: list[dict],
              min_severity: str) -> Generator[dict, None, None]:
    rel = os.path.relpath(filepath, root)
    if is_safe_path(rel):
        return
    min_rank = SEVERITY_RANK[min_severity]
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                for rule in compiled_rules:
                    if SEVERITY_RANK[rule["severity"]] < min_rank:
                        continue
                    if rule["regex"].search(line):
                        yield {
                            "rule": rule["name"],
                            "severity": rule["severity"],
                            "file": rel,
                            "lineno": lineno,
                            "snippet": line.rstrip()[:120],
                        }
    except OSError as exc:
        print(f"[WARN] Cannot read {filepath}: {exc}", file=sys.stderr)


def report_findings(findings: Generator[dict, None, None]) -> bool:
    counts = {"low": 0, "medium": 0, "high": 0}
    flagged_files: set[str] = set()
    has_high = False

    for f in findings:
        sev = f["severity"]
        counts[sev] += 1
        flagged_files.add(f["file"])
        if sev == "high":
            has_high = True
        label = f"[{sev.upper():6s}]"
        print(f"{label} {f['rule']:40s} {f['file']}:{f['lineno']}")
        print(f"         {f['snippet']}")

    print("\n--- Summary ---")
    for sev in ("high", "medium", "low"):
        print(f"  {sev.upper():6s}: {counts[sev]}")
    total = sum(counts.values())
    print(f"  TOTAL : {total}")
    if flagged_files:
        print("\nFlagged files:")
        for fp in sorted(flagged_files):
            print(f"  {fp}")
    else:
        print("\nNo findings.")
    return has_high


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-SHELLSTORM Backdoor Scanner — detects webshell IOCs in WordPress PHP files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("wp_root", help="WordPress root directory or single PHP file to scan")
    parser.add_argument("--rules", metavar="FILE",
                        help="JSON file mapping rule_name to regex pattern or {pattern, severity}")
    parser.add_argument("--min-severity", choices=["low", "medium", "high"], default="low",
                        help="Lowest alert level to emit (default: low)")
    args = parser.parse_args()

    all_rules = list(BUNDLED_RULES)
    if args.rules:
        all_rules.extend(load_supplemental_rules(args.rules))

    compiled = compile_rules(all_rules)

    def findings_gen() -> Generator[dict, None, None]:
        for root, filepath in collect_php_files(args.wp_root):
            yield from scan_file(root, filepath, compiled, args.min_severity)

    has_high = report_findings(findings_gen())
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()