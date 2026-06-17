"""
ClickFix Loader Detector - Scans plain text logs for BabaDeda, Lorem Ipsum, and Potemkin loader patterns.

Usage:
    python clickfix_loader_detector.py /var/log/app.log
    python clickfix_loader_detector.py /var/log/app.log --severity medium
    python clickfix_loader_detector.py /var/log/app.log --rules babadeda_msiexec,lorem_ipsum_wscript
"""

import argparse
import re
import sys
from datetime import datetime


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def build_ruleset():
    return {
        "babadeda_msiexec": {
            "pattern": re.compile(r"msiexec(?:\.exe)?\s+/[iq]\s+[\"']?([^\s\"']+\.msi)[\"']?", re.IGNORECASE),
            "severity": "high",
            "family": "BabaDeda",
            "description": "MSI silent install via msiexec matching BabaDeda delivery",
            "ioc_group": 1,
        },
        "babadeda_regsvr": {
            "pattern": re.compile(r"regsvr32(?:\.exe)?\s+(?:/s\s+)?[\"']?([^\s\"']+\.(?:dll|ocx))[\"']?", re.IGNORECASE),
            "severity": "high",
            "family": "BabaDeda",
            "description": "regsvr32 silent DLL/OCX registration used by BabaDeda",
            "ioc_group": 1,
        },
        "babadeda_wmic_process": {
            "pattern": re.compile(r"wmic\s+process\s+call\s+create\s+[\"']?([^\"'\n]{5,100})[\"']?", re.IGNORECASE),
            "severity": "medium",
            "family": "BabaDeda",
            "description": "WMIC process creation lateral movement indicator",
            "ioc_group": 1,
        },
        "lorem_ipsum_wscript": {
            "pattern": re.compile(r"wscript(?:\.exe)?\s+(?://[a-z]+\s+)?[\"']?([^\s\"']+\.(?:js|vbs|wsf))[\"']?", re.IGNORECASE),
            "severity": "high",
            "family": "Lorem Ipsum",
            "description": "WScript executing JS/VBS matching Lorem Ipsum loader stage",
            "ioc_group": 1,
        },
        "lorem_ipsum_certutil": {
            "pattern": re.compile(r"certutil(?:\.exe)?\s+(?:-decode|-urlcache\s+-(?:f|split))\s+[\"']?([^\s\"']+)[\"']?", re.IGNORECASE),
            "severity": "high",
            "family": "Lorem Ipsum",
            "description": "certutil decode/download used in Lorem Ipsum payload staging",
            "ioc_group": 1,
        },
        "lorem_ipsum_powershell_enc": {
            "pattern": re.compile(r"powershell(?:\.exe)?\s+.*-[Ee](?:nc(?:odedCommand)?)?\s+([A-Za-z0-9+/=]{20,})", re.IGNORECASE),
            "severity": "high",
            "family": "Lorem Ipsum",
            "description": "PowerShell encoded command execution typical of Lorem Ipsum dropper",
            "ioc_group": 1,
        },
        "lorem_ipsum_temp_exec": {
            "pattern": re.compile(r"(?:%temp%|\\Temp\\|/tmp/)([^\s\"'\\/:*?<>|]{1,64}\.(?:exe|bat|cmd|ps1))", re.IGNORECASE),
            "severity": "medium",
            "family": "Lorem Ipsum",
            "description": "Executable dropped to temp directory consistent with Lorem Ipsum staging",
            "ioc_group": 1,
        },
        "potemkin_mshta": {
            "pattern": re.compile(r"mshta(?:\.exe)?\s+[\"']?((?:https?://|vbscript:|javascript:)[^\s\"']{5,200})[\"']?", re.IGNORECASE),
            "severity": "high",
            "family": "Potemkin",
            "description": "mshta remote/script execution matching Potemkin loader delivery",
            "ioc_group": 1,
        },
        "potemkin_rundll32": {
            "pattern": re.compile(r"rundll32(?:\.exe)?\s+[\"']?([^\s\"',]+\.dll)[\"']?,\s*([^\s\"']+)", re.IGNORECASE),
            "severity": "high",
            "family": "Potemkin",
            "description": "rundll32 DLL export invocation used by Potemkin loader",
            "ioc_group": 1,
        },
        "potemkin_clipboard_cmd": {
            # Bounded [^\n]{0,N} replaces nested .* alternation to prevent ReDoS on adversarial lines.
            "pattern": re.compile(r"(?:cmd(?:\.exe)?|powershell(?:\.exe)?)\s+[^\n]{0,200}(?:/c|/k|-c|-Command)\s+[\"']?([^\n]{0,100}(?:clip|paste)[^\n]{0,100})", re.IGNORECASE),
            "severity": "medium",
            "family": "Potemkin",
            "description": "Clipboard-sourced command execution typical of ClickFix/Potemkin social engineering",
            "ioc_group": 1,
        },
        "clickfix_win_r_pattern": {
            "pattern": re.compile(r"(?:Win\+R|winrun|run dialog).*?(powershell|cmd|mshta|wscript|rundll32)", re.IGNORECASE),
            "severity": "medium",
            "family": "ClickFix",
            "description": "Win+R dialog abuse pattern common across all ClickFix loader families",
            "ioc_group": 1,
        },
        "suspicious_lolbin_chain": {
            "pattern": re.compile(r"(cmd|powershell|wscript|mshta|rundll32|regsvr32|certutil|msiexec).*?(cmd|powershell|wscript|mshta|rundll32|regsvr32|certutil|msiexec)", re.IGNORECASE),
            "severity": "low",
            "family": "Generic",
            "description": "Chained LOLBin execution pattern consistent with ClickFix campaigns",
            "ioc_group": 0,
        },
    }


def scan_log(log_path, rules, min_severity):
    findings = []
    min_level = SEVERITY_ORDER[min_severity]
    seen = set()
    try:
        with open(log_path, "r", errors="replace") as fh:
            for lineno, raw in enumerate(fh, start=1):
                line = raw.rstrip("\n")
                for rule_name, rule in rules.items():
                    if SEVERITY_ORDER[rule["severity"]] < min_level:
                        continue
                    m = rule["pattern"].search(line)
                    if not m:
                        continue
                    ioc = m.group(rule["ioc_group"]) if rule["ioc_group"] and rule["ioc_group"] <= len(m.groups()) else m.group(0)
                    key = (rule_name, lineno)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "lineno": lineno,
                        "rule": rule_name,
                        "severity": rule["severity"],
                        "family": rule["family"],
                        "description": rule["description"],
                        "ioc": ioc.strip()[:500],
                        "line": line.strip()[:200],
                    })
    except OSError as e:
        print(f"ERROR: Cannot read log file: {e}", file=sys.stderr)
        sys.exit(1)
    return findings


def report_findings(findings, log_path):
    if not findings:
        print(f"[{datetime.utcnow().isoformat()}Z] No matches found in {log_path}")
        return
    sorted_findings = sorted(findings, key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["lineno"]))
    print(f"[{datetime.utcnow().isoformat()}Z] ClickFix Loader Detector — {len(findings)} finding(s) in {log_path}\n")
    for f in sorted_findings:
        print(f"MATCH  rule:{f['rule']}  severity:{f['severity'].upper()}  family:{f['family']}")
        print(f"  line:{f['lineno']}  ioc:{f['ioc']}")
        print(f"  desc:{f['description']}")
        print(f"  raw: {f['line']}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Scan plain text logs for ClickFix loader indicators (BabaDeda, Lorem Ipsum, Potemkin).",
        epilog="Example: python clickfix_loader_detector.py app.log --severity medium --rules babadeda_msiexec,potemkin_mshta",
    )
    parser.add_argument("log_file", help="Path to plain text log file to scan")
    parser.add_argument("--rules", help="Comma-separated rule names to enable (default: all)")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low", help="Minimum severity threshold (default: low)")
    args = parser.parse_args()

    ruleset = build_ruleset()

    if args.rules:
        requested = set(r.strip() for r in args.rules.split(","))
        unknown = requested - ruleset.keys()
        if unknown:
            print(f"ERROR: Unknown rule(s): {', '.join(sorted(unknown))}. Available: {', '.join(sorted(ruleset.keys()))}", file=sys.stderr)
            sys.exit(1)
        ruleset = {k: v for k, v in ruleset.items() if k in requested}

    findings = scan_log(args.log_file, ruleset, args.severity)
    report_findings(findings, args.log_file)


if __name__ == "__main__":
    main()