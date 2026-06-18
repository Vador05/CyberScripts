"""
xeno_rat_hunter.py - Xeno RAT Log Hunter

Scans plain-text log files for Xeno RAT indicators including C2 registration
patterns, persistence registry keys, and network beaconing signatures.

Usage:
    python xeno_rat_hunter.py /var/log/auth.log
    python xeno_rat_hunter.py /var/log/syslog --severity high
    python xeno_rat_hunter.py /var/log/windows_event.log --json
    python xeno_rat_hunter.py access.log --severity medium --json
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone


def load_rules():
    return {
        "XENO_C2_REGISTRATION": {
            "description": "Xeno RAT C2 registration beacon pattern",
            "pattern": re.compile(
                r"(?:xeno|xenorat|xrat)[_\-]?(?:register|checkin|connect|init|beacon)"
                r"|(?:POST|GET)\s+/(?:reg|register|gate|gate\.php|connect)\b",
                re.IGNORECASE,
            ),
            "severity": "high",
            "mitre": "T1071.001",
            "tactic": "Command and Control",
        },
        "XENO_PERSISTENCE_REGISTRY": {
            "description": "Xeno RAT persistence via registry run keys",
            "pattern": re.compile(
                r"(?:HKCU|HKLM)\\[^\s]*\\(?:Run|RunOnce|RunServices)[^\n]*"
                r"(?:xeno|xenorat|xrat|update(?:r|checker|service))"
                r"|reg(?:\.exe)?\s+add\s+[^\s]*\\Run[^\n]*(?:xeno|xenorat|xrat|update(?:r|checker|service))",
                re.IGNORECASE,
            ),
            "severity": "high",
            "mitre": "T1547.001",
            "tactic": "Persistence",
        },
        "XENO_SCHEDULED_TASK": {
            "description": "Xeno RAT scheduled task creation for persistence",
            "pattern": re.compile(
                r"schtasks(?:\.exe)?\s+/create[^\n]*(?:xeno|xenorat|xrat)"
                r"|TaskName[^\n]*(?:xeno|xenorat|xrat)",
                re.IGNORECASE,
            ),
            "severity": "high",
            "mitre": "T1053.005",
            "tactic": "Persistence",
        },
        "XENO_BEACONING_INTERVAL": {
            "description": "Regular interval HTTP beaconing consistent with Xeno RAT",
            "pattern": re.compile(
                r"(?:sleep|interval|beacon_interval|heartbeat)[=:\s]+(?:3[0-9]{4}|[4-9][0-9]{4}|[1-9][0-9]{5})"
                r"|Thread\.Sleep\(\s*(?:3[0-9]{4}|[4-9][0-9]{4}|[1-9][0-9]{5})",
                re.IGNORECASE,
            ),
            "severity": "medium",
            "mitre": "T1071.001",
            "tactic": "Command and Control",
        },
        "XENO_PROCESS_INJECTION": {
            "description": "Process injection technique associated with Xeno RAT",
            "pattern": re.compile(
                r"VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx"
                r"|QueueUserAPC",
                re.IGNORECASE,
            ),
            "severity": "medium",
            "mitre": "T1055",
            "tactic": "Defense Evasion",
        },
        "XENO_KEYLOGGER": {
            "description": "Keylogging activity associated with Xeno RAT",
            "pattern": re.compile(
                r"GetAsyncKeyState|SetWindowsHookEx.*WH_KEYBOARD"
                r"|keylog(?:ger|ging)|keystroke[_\s]?capture",
                re.IGNORECASE,
            ),
            "severity": "high",
            "mitre": "T1056.001",
            "tactic": "Collection",
        },
        "XENO_SCREENSHOT": {
            "description": "Screenshot capture consistent with Xeno RAT collection",
            "pattern": re.compile(
                r"(?:BitBlt|GetDC|CreateCompatibleBitmap)[^\n]*screen"
                r"|screen(?:shot|capture|grab)[^\n]*(?:save|write|upload|send)",
                re.IGNORECASE,
            ),
            "severity": "medium",
            "mitre": "T1113",
            "tactic": "Collection",
        },
        "XENO_FINANCE_RECON": {
            "description": "Finance sector reconnaissance pattern linked to Xeno RAT campaigns",
            "pattern": re.compile(
                r"(?:swift|iban|bic|routing[\s._-]?number|account[\s._-]?number|wire[\s._-]?transfer)"
                r"[^\n]*(?:enum|list|dump|export|exfil|collect)",
                re.IGNORECASE,
            ),
            "severity": "high",
            "mitre": "T1005",
            "tactic": "Collection",
        },
        "XENO_ANTIDEBUG": {
            "description": "Anti-analysis techniques observed in Xeno RAT samples",
            "pattern": re.compile(
                r"IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess"
                r"|GetTickCount.*anti|timing.*evasion",
                re.IGNORECASE,
            ),
            "severity": "low",
            "mitre": "T1622",
            "tactic": "Defense Evasion",
        },
        "XENO_C2_PROTOCOL_MARKER": {
            "description": "Xeno RAT custom C2 protocol header or marker",
            "pattern": re.compile(
                r"X-(?:Session|Bot|ID|Token|Auth):\s*[A-Fa-f0-9]{16,}"
                r"|User-Agent:\s*(?:Mozilla/[45]\.[01]\s+\(compatible\)|XenoClient)",
                re.IGNORECASE,
            ),
            "severity": "medium",
            "mitre": "T1071.001",
            "tactic": "Command and Control",
        },
    }


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def scan_log(path, rules, min_severity):
    min_level = SEVERITY_ORDER[min_severity]
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, start=1):
                stripped = line.rstrip("\r\n")
                for rule_id, rule in rules.items():
                    if SEVERITY_ORDER[rule["severity"]] < min_level:
                        continue
                    match = rule["pattern"].search(stripped)
                    if match:
                        yield {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "rule": rule_id,
                            "description": rule["description"],
                            "severity": rule["severity"],
                            "mitre": rule["mitre"],
                            "tactic": rule["tactic"],
                            "line_number": lineno,
                            "matched_text": match.group(0),
                            "log_file": path,
                        }
    except OSError as exc:
        print(f"[ERROR] Cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(
        description="Xeno RAT Log Hunter — SIGMA-aligned indicator scanner",
        epilog="Example: python xeno_rat_hunter.py /var/log/syslog --severity high --json",
    )
    parser.add_argument("log_file", help="Path to plain-text log file to scan")
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum severity level to report (default: low)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="emit_json",
        help="Emit findings as JSON lines",
    )
    args = parser.parse_args()

    rules = load_rules()
    high_severity_hit = False

    for finding in scan_log(args.log_file, rules, args.severity):
        if finding["severity"] == "high":
            high_severity_hit = True
        if args.emit_json:
            print(json.dumps(finding))
        else:
            print(
                f"[{finding['timestamp']}] [{finding['severity'].upper()}] "
                f"{finding['rule']} | Line {finding['line_number']} | "
                f"MITRE {finding['mitre']} ({finding['tactic']}) | "
                f"Match: {finding['matched_text']!r}"
            )

    sys.exit(1 if high_severity_hit else 0)


if __name__ == "__main__":
    main()