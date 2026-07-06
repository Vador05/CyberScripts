"""
Gamaredon TTP Log Scanner - Detect Shuckworm/Armageddon malware-loading and C2 activity.

Usage:
    python gamaredon_hunt.py /var/log/syslog
    python gamaredon_hunt.py /var/log/syslog --severity high
    python gamaredon_hunt.py /var/log/syslog --json
    cat auth.log | python gamaredon_hunt.py /dev/stdin --severity medium
"""

import argparse
import json
import re
import sys

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def build_ruleset():
    return [
        {
            "name": "EXEC_POWERSHELL_ENC",
            "ttp_id": "T1059.001",
            "severity": "high",
            "pattern": re.compile(
                r"powershell(?:\.exe)?.{0,40}-[Ee]n(?:c|co|cod|code|coded).{1,8}[A-Za-z0-9+/]{40,}",
                re.IGNORECASE,
            ),
        },
        {
            "name": "EXEC_POWERSHELL_HIDDEN",
            "ttp_id": "T1059.001",
            "severity": "medium",
            "pattern": re.compile(
                r"powershell(?:\.exe)?.{0,80}-[Ww](?:indow[Ss]tyle)?.{0,4}[Hh]idden",
                re.IGNORECASE,
            ),
        },
        {
            "name": "EXEC_POWERSHELL_BYPASS",
            "ttp_id": "T1059.001",
            "severity": "medium",
            "pattern": re.compile(
                r"powershell(?:\.exe)?.{0,80}-[Ee]xecution[Pp]olicy.{0,8}[Bb]ypass",
                re.IGNORECASE,
            ),
        },
        {
            "name": "EXEC_MSHTA_REMOTE",
            "ttp_id": "T1218.005",
            "severity": "high",
            "pattern": re.compile(
                r"mshta(?:\.exe)?.{0,30}https?://[^\s]{10,}",
                re.IGNORECASE,
            ),
        },
        {
            "name": "EXEC_WSCRIPT_REMOTE",
            "ttp_id": "T1059.005",
            "severity": "high",
            "pattern": re.compile(
                r"w(?:script|cscript)(?:\.exe)?.{0,60}https?://[^\s]{10,}",
                re.IGNORECASE,
            ),
        },
        {
            "name": "EXEC_REGSVR32_REMOTE",
            "ttp_id": "T1218.010",
            "severity": "high",
            "pattern": re.compile(
                r"regsvr32(?:\.exe)?.{0,30}/[Ss].{0,20}https?://[^\s]{10,}",
                re.IGNORECASE,
            ),
        },
        {
            "name": "EXEC_RUNDLL32_REMOTE",
            "ttp_id": "T1218.011",
            "severity": "high",
            "pattern": re.compile(
                r"rundll32(?:\.exe)?.{0,30}https?://[^\s]{10,}",
                re.IGNORECASE,
            ),
        },
        {
            "name": "EXEC_LNK_FROM_TEMP",
            "ttp_id": "T1204.002",
            "severity": "medium",
            "pattern": re.compile(
                r"(?:%temp%|\\temp\\|\\appdata\\local\\temp\\)[^\s]{0,60}\.lnk",
                re.IGNORECASE,
            ),
        },
        {
            "name": "EXEC_HTA_FROM_TEMP",
            "ttp_id": "T1218.005",
            "severity": "high",
            "pattern": re.compile(
                r"(?:%temp%|\\temp\\|\\appdata\\local\\temp\\)[^\s]{0,60}\.hta",
                re.IGNORECASE,
            ),
        },
        {
            "name": "C2_DDNS_NSLOOKUP",
            "ttp_id": "T1568.002",
            "severity": "medium",
            "pattern": re.compile(
                r"(?:no-ip\.(?:com|org|biz|info)|ddns\.net|duckdns\.org|hopto\.org|zapto\.org|sytes\.net|myftp\.org|redirectme\.net)",
                re.IGNORECASE,
            ),
        },
        {
            "name": "C2_TELEGRAM_BOT",
            "ttp_id": "T1102.002",
            "severity": "high",
            "pattern": re.compile(
                r"api\.telegram\.org/bot[0-9]{6,12}:[A-Za-z0-9_-]{30,}",
                re.IGNORECASE,
            ),
        },
        {
            "name": "C2_TELEGRAM_DOMAIN",
            "ttp_id": "T1102.002",
            "severity": "medium",
            "pattern": re.compile(
                r"api\.telegram\.org",
                re.IGNORECASE,
            ),
        },
        {
            "name": "OFFICE_SPAWN_CMD",
            "ttp_id": "T1566.001",
            "severity": "high",
            "pattern": re.compile(
                r"(?:winword|excel|powerpnt|outlook)(?:\.exe)?.{0,80}(?:cmd|powershell|wscript|cscript|mshta)(?:\.exe)?",
                re.IGNORECASE,
            ),
        },
        {
            "name": "EXEC_CERTUTIL_DECODE",
            "ttp_id": "T1140",
            "severity": "high",
            "pattern": re.compile(
                r"certutil(?:\.exe)?.{0,30}-(?:de|en)code",
                re.IGNORECASE,
            ),
        },
        {
            "name": "EXEC_BITS_DOWNLOAD",
            "ttp_id": "T1197",
            "severity": "medium",
            "pattern": re.compile(
                r"bitsadmin(?:\.exe)?.{0,30}/transfer.{0,80}https?://[^\s]{10,}",
                re.IGNORECASE,
            ),
        },
        {
            "name": "PERSIST_REG_RUN",
            "ttp_id": "T1547.001",
            "severity": "medium",
            "pattern": re.compile(
                r"(?:HKCU|HKLM)\\[^\s]{0,60}\\(?:Run|RunOnce)\b",
                re.IGNORECASE,
            ),
        },
        {
            "name": "EXEC_POWERSHELL_DOWNLOAD",
            "ttp_id": "T1059.001",
            "severity": "high",
            "pattern": re.compile(
                r"(?:Net\.WebClient|WebRequest|DownloadString|DownloadFile|IEX|Invoke-Expression).{0,120}https?://[^\s]{10,}",
                re.IGNORECASE,
            ),
        },
    ]


def scan_lines(lines, rules, min_sev):
    min_val = SEVERITY_ORDER[min_sev]
    for lineno, line in enumerate(lines, 1):
        stripped = line.rstrip("\n")
        for rule in rules:
            if SEVERITY_ORDER[rule["severity"]] < min_val:
                continue
            if rule["pattern"].search(stripped):
                yield {
                    "line": lineno,
                    "name": rule["name"],
                    "ttp_id": rule["ttp_id"],
                    "severity": rule["severity"],
                    "raw": stripped,
                }


def main():
    parser = argparse.ArgumentParser(
        description="Scan plain-text logs for Gamaredon (Shuckworm) TTPs."
    )
    parser.add_argument("logfile", help="Path to the plain-text log file to scan.")
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum severity to report (default: low).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_out",
        help="Emit findings as newline-delimited JSON.",
    )
    args = parser.parse_args()

    try:
        fh = open(args.logfile, "r", encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"ERROR: Cannot open '{args.logfile}': {exc}", file=sys.stderr)
        sys.exit(1)

    rules = build_ruleset()
    count = 0

    with fh:
        for finding in scan_lines(fh, rules, args.severity):
            count += 1
            if args.json_out:
                print(json.dumps(finding))
            else:
                print(
                    f"[{finding['severity'].upper()}] line {finding['line']} | "
                    f"{finding['name']} ({finding['ttp_id']}) | {finding['raw']}"
                )

    print(f"Scan complete: {count} finding(s).", file=sys.stderr)


if __name__ == "__main__":
    main()