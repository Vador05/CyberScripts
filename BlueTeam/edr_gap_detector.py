"""
EDR Telemetry Gap Detector - Parses EDR/syslog output to identify coverage gaps.

Usage:
    python edr_gap_detector.py /var/log/edr.log
    python edr_gap_detector.py /var/log/edr.log --threshold 5 --output detail
    python edr_gap_detector.py /var/log/edr.log --output detail

Example log lines detected:
    2024-01-15T10:23:01 exec /bin/bash pid=1234
    2024-01-15T10:23:02 ldap_query host=dc01
    2024-01-15T10:23:03 setuid uid=0 pid=5678
"""

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

SIGNAL_PATTERNS = {
    "proc_create": {
        "patterns": [
            r"\b(exec|execve|process_create|proc_start|spawn|fork)\b",
            r"\b(pid=\d+|process[_ ]id[=:]\s*\d+)\b",
            r"(/bin/|/usr/bin/|cmd\.exe|\bpowershell\b)",
        ],
        "description": "Process creation events",
        "evasion_context": "Missing proc_create telemetry enables AI-assisted process injection and living-off-the-land binaries to go undetected",
    },
    "net_enum": {
        "patterns": [
            r"\b(net_connect|tcp_connect|udp_send|dns_query|network_event)\b",
            r"\b(ldap[_:]|smb[_:]|wmi[_:]|rpc[_:])\b",
            r"\b(port_scan|arp_scan|nmap|masscan)\b",
        ],
        "description": "Network enumeration and lateral movement events",
        "evasion_context": "Absent network telemetry hides lateral movement, C2 beaconing, and AD subnet discovery",
    },
    "priv_esc": {
        "patterns": [
            r"\b(setuid|setgid|privilege[_ ]esc|priv_esc|sudo|runas)\b",
            r"\b(token[_ ]impersonat|impersonation|elevation)\b",
            r"\b(uid=0|gid=0|SYSTEM|NT AUTHORITY)\b",
        ],
        "description": "Privilege escalation and token manipulation events",
        "evasion_context": "Missing priv_esc signals allow token theft and sudo abuse to bypass detection",
    },
    "container_ns": {
        "patterns": [
            r"\b(namespace|unshare|clone[_ ]flag|pivot_root|chroot)\b",
            r"\b(container[_ ]escape|docker[_ ]break|cgroup[_ ]escape)\b",
            r"\b(cap_sys_admin|CAP_SYS_ADMIN|seccomp[_ ]bypass)\b",
        ],
        "description": "Container namespace and escape events",
        "evasion_context": "No container telemetry leaves namespace escapes and cgroup breakouts invisible to EDR",
    },
    "ad_ldap": {
        "patterns": [
            r"\b(ldap_query|ldap_bind|ldap_search|ad_query)\b",
            r"\b(dc=[a-zA-Z0-9]+|domain[_ ]controller|kerberos|krb5)\b",
            r"\b(BloodHound|SharpHound|ldapdomaindump|adidnsdump)\b",
        ],
        "description": "Active Directory and LDAP discovery events",
        "evasion_context": "Absent AD telemetry enables stealthy domain enumeration and Kerberoasting reconnaissance",
    },
}

TIMESTAMP_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
)

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _sanitize(text: str) -> str:
    return _CTRL_RE.sub("?", text)


def parse_log_events(path: str) -> tuple[dict, dict]:
    """Returns (counts_per_category, samples_per_category) with samples capped at 3."""
    counts: dict[str, int] = defaultdict(int)
    samples: dict[str, list] = defaultdict(list)
    compiled = {
        cat: [re.compile(p, re.IGNORECASE) for p in data["patterns"]]
        for cat, data in SIGNAL_PATTERNS.items()
    }

    try:
        with open(path, "r", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.rstrip()
                ts_match = TIMESTAMP_RE.match(line)
                timestamp = ts_match.group(1) if ts_match else f"line:{lineno}"
                for category, patterns in compiled.items():
                    if any(p.search(line) for p in patterns):
                        counts[category] += 1
                        if len(samples[category]) < 3:
                            samples[category].append((timestamp, line[:120]))
    except PermissionError:
        sys.exit(f"[error] Permission denied reading: {path}")
    except OSError as exc:
        sys.exit(f"[error] Cannot open log file: {exc}")

    return dict(counts), dict(samples)


def detect_gaps(counts: dict, samples: dict, threshold: int) -> list:
    gaps = []
    for category, meta in SIGNAL_PATTERNS.items():
        count = counts.get(category, 0)
        covered = count >= threshold
        gaps.append({
            "category": category,
            "description": meta["description"],
            "evasion_context": meta["evasion_context"],
            "count": count,
            "covered": covered,
            "samples": samples.get(category, []),
        })
    return gaps


def report(gaps: list, mode: str) -> None:
    col_w = [16, 52, 10, 8]
    header = f"{'CATEGORY':<{col_w[0]}} {'DESCRIPTION':<{col_w[1]}} {'STATUS':<{col_w[2]}} {'COUNT':<{col_w[3]}}"
    divider = "-" * (sum(col_w) + 3)

    print(divider)
    print(header)
    print(divider)

    for g in gaps:
        status = "COVERED" if g["covered"] else "GAP"
        flag = "" if g["covered"] else " <--"
        desc = g["description"][:col_w[1]]
        print(f"{g['category']:<{col_w[0]}} {desc:<{col_w[1]}} {status:<{col_w[2]}} {g['count']:<{col_w[3]}}{flag}")

    print(divider)

    gap_items = [g for g in gaps if not g["covered"]]
    print(f"\nResult: {len(gap_items)} gap(s) detected out of {len(gaps)} required signal categories.\n")

    if mode == "detail":
        for g in gap_items:
            print(f"[GAP] {g['category'].upper()}")
            print(f"  Description : {g['description']}")
            print(f"  Risk        : {g['evasion_context']}")
            print(f"  Events found: {g['count']}")
            if g["samples"]:
                print("  Samples:")
                for ts, line in g["samples"]:
                    print(f"    [{_sanitize(ts)}] {_sanitize(line)}")
            print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EDR Telemetry Gap Detector — identifies missing log signals exploitable by evasion and AD discovery.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python edr_gap_detector.py /var/log/edr.log --threshold 5 --output detail",
    )
    parser.add_argument("log_file", help="Path to plain-text EDR or syslog file")
    parser.add_argument("--threshold", type=int, default=1, metavar="N", help="Minimum expected events per category (default: 1)")
    parser.add_argument("--output", choices=["summary", "detail"], default="summary", help="Output verbosity (default: summary)")
    args = parser.parse_args()

    if not Path(args.log_file).is_file():
        sys.exit(f"[error] File not found: {args.log_file}")
    if args.threshold < 1:
        sys.exit("[error] --threshold must be >= 1")

    print(f"\nEDR Telemetry Gap Detector")
    print(f"Log file : {_sanitize(str(args.log_file))}")
    print(f"Threshold: {args.threshold} event(s) per category\n")

    counts, samples = parse_log_events(args.log_file)
    gaps = detect_gaps(counts, samples, args.threshold)
    report(gaps, args.output)

    if any(not g["covered"] for g in gaps):
        sys.exit(1)


if __name__ == "__main__":
    main()
