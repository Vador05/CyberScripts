"""
woodgnat_native_msg_detector.py - Woodgnat/Mistic Native Messaging Kill Chain Detector

Scans plain-text process/event logs for Native Messaging host invocations spawned
by browser extension processes, a staging technique observed in the Woodgnat/Mistic
ransomware kill chain.

Usage:
    python woodgnat_native_msg_detector.py sysmon.log
    python woodgnat_native_msg_detector.py audit.log --browser chrome,firefox --verbose
    python woodgnat_native_msg_detector.py events.log --verbose; echo "Exit: $?"
"""

import argparse
import re
import sys
from datetime import datetime, timezone


def load_rules():
    return [
        {
            "id": "WG-001",
            "severity": "HIGH",
            "description": "Suspicious Native Messaging host path matching Woodgnat staging",
            "pattern": re.compile(
                r"(?i)(nm_host|nativehost|native_messaging_host|woodgnat|mistic)"
                r"[\\/].*\.(exe|bat|cmd|ps1|vbs|js)",
                re.IGNORECASE,
            ),
        },
        {
            "id": "WG-002",
            "severity": "HIGH",
            "description": "Suspicious COM/manifest registry key for Native Messaging",
            "pattern": re.compile(
                r"(?i)HKCU\\Software\\(Google|Mozilla|Microsoft)\\NativeMessagingHosts"
                r"\\[a-z0-9._-]{3,}",
                re.IGNORECASE,
            ),
        },
        {
            "id": "WG-003",
            "severity": "CRITICAL",
            "description": "Browser spawning cmd/powershell via Native Messaging host",
            "pattern": re.compile(
                r"(?i)(chrome|firefox|msedge|chromium).*\s+"
                r"(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe)",
                re.IGNORECASE,
            ),
        },
        {
            "id": "WG-004",
            "severity": "MEDIUM",
            "description": "Native Messaging manifest in suspicious temp/user path",
            "pattern": re.compile(
                r"(?i)(AppData\\Local\\Temp|/tmp/|%TEMP%)[/\\].*"
                r"(manifest\.json|nm_manifest|native-messaging)",
                re.IGNORECASE,
            ),
        },
        {
            "id": "WG-005",
            "severity": "HIGH",
            "description": "Browser extension process spawning network/recon tool",
            "pattern": re.compile(
                r"(?i)(chrome|firefox|msedge|chromium).*\s+"
                r"(net\.exe|whoami|ipconfig|nltest|certutil|bitsadmin)",
                re.IGNORECASE,
            ),
        },
        {
            "id": "WG-006",
            "severity": "CRITICAL",
            "description": "Known Woodgnat/Mistic dropper filename or mutex pattern",
            "pattern": re.compile(
                r"(?i)(woodgnat|mistic|wg_stage|ms_drop|ext_loader)"
                r"[\s\\/._-]*(v?\d+|loader|drop|stage|payload)",
                re.IGNORECASE,
            ),
        },
        {
            "id": "WG-007",
            "severity": "MEDIUM",
            "description": "Native Messaging host spawned outside standard install paths",
            "pattern": re.compile(
                r"(?i)(--parent=|ParentProcessName|ppid\s*[:=])\s*"
                r"(chrome|firefox|msedge|chromium)[^\n]*\n?"
                r"[^\n]*(AppData\\Roaming|/home/[^/]+/\.config)",
                re.IGNORECASE,
            ),
        },
    ]


_TIMESTAMP_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
_SEVERITY_ORDER = {"MEDIUM": 0, "HIGH": 1, "CRITICAL": 2}


def extract_timestamp(line):
    m = _TIMESTAMP_RE.search(line)
    return m.group(1) if m else datetime.now(timezone.utc).isoformat()


def browser_in_line(line, browsers):
    low = line.lower()
    return any(b.lower() in low for b in browsers)


def scan_log(path, rules, browsers, verbose=False):
    findings = []
    window = []
    window_size = 5

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.rstrip("\n")
                window.append((lineno, line))
                if len(window) > window_size:
                    window.pop(0)

                context = " ".join(l for _, l in window)

                for rule in rules:
                    if rule["pattern"].search(context):
                        if browsers and not browser_in_line(context, browsers):
                            if rule["id"] not in ("WG-001", "WG-004", "WG-006"):
                                continue
                        ts = extract_timestamp(line)
                        excerpt = line[:200] if verbose else ""
                        findings.append(
                            {
                                "timestamp": ts,
                                "severity": rule["severity"],
                                "rule_id": rule["id"],
                                "description": rule["description"],
                                "line_no": lineno,
                                "excerpt": excerpt,
                            }
                        )
                        break
    except OSError as exc:
        print(f"ERROR: cannot read log file: {exc}", file=sys.stderr)
        sys.exit(2)

    return findings


def format_finding(f, verbose=False):
    parts = [
        f["timestamp"],
        f"[{f['severity']}]",
        f"rule={f['rule_id']}",
        f"line={f['line_no']}",
        f['description'],
    ]
    if verbose and f.get("excerpt"):
        parts.append(f"| {f['excerpt']}")
    return " | ".join(parts)


def main():
    parser = argparse.ArgumentParser(
        description="Detect Woodgnat/Mistic Native Messaging kill chain indicators in plain-text logs."
    )
    parser.add_argument("log_file", help="Path to plain-text log file (Sysmon, auditd, or custom export)")
    parser.add_argument(
        "--browser",
        default="chrome,firefox,msedge",
        help="Comma-separated browser process names to target (default: chrome,firefox,msedge)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Emit full matched line alongside alert",
    )
    args = parser.parse_args()

    browsers = [b.strip() for b in args.browser.split(",") if b.strip()]
    rules = load_rules()

    findings = scan_log(args.log_file, rules, browsers, verbose=args.verbose)

    if not findings:
        print("No Woodgnat/Mistic indicators found.")
        sys.exit(0)

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 0), f["line_no"]))

    for f in findings:
        print(format_finding(f, verbose=args.verbose))

    high_plus = any(f["severity"] in ("HIGH", "CRITICAL") for f in findings)
    sys.exit(1 if high_plus else 0)


if __name__ == "__main__":
    main()