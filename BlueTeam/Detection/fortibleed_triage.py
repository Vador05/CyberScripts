"""
FortiBleed Triage Scanner - Detect CVE-2022-42475 / CVE-2024-21762 implant artifacts in FortiGate logs.

Usage:
    python fortibleed_triage.py /var/log/fortigate.log
    python fortibleed_triage.py /var/log/fortigate.log --severity high
    python fortibleed_triage.py /var/log/fortigate.log --json
    python fortibleed_triage.py /var/log/fortigate.log --severity critical --json
"""

import argparse
import json
import re
import sys
from datetime import datetime


SEVERITIES = ["low", "medium", "high", "critical"]


def load_signatures():
    return {
        "fortibleed_implant_sslvpnd": {
            "pattern": r"/data/lib/\.sslvpnd",
            "severity": "critical",
            "attack": "T1543.003",
            "tactic": "Persistence",
            "action": "Immediately isolate device; binary at path is the FortiBleed sniffer implant.",
        },
        "fortibleed_implant_smartctl": {
            "pattern": r"/bin/smartctl\b.*(?:modified|replaced|patched|injected)",
            "severity": "critical",
            "attack": "T1574.006",
            "tactic": "Defense Evasion",
            "action": "Verify smartctl binary hash against vendor baseline; trojanized binary indicates compromise.",
        },
        "fortibleed_implant_wnm": {
            "pattern": r"/bin/wnm\b.*(?:modified|replaced|patched|injected)",
            "severity": "critical",
            "attack": "T1574.006",
            "tactic": "Defense Evasion",
            "action": "Verify wnm binary hash against vendor baseline; modification is a known FortiBleed IOC.",
        },
        "fortibleed_implant_ips_helper": {
            "pattern": r"/bin/ips_helper\b.*(?:modified|replaced|patched|injected)",
            "severity": "critical",
            "attack": "T1574.006",
            "tactic": "Defense Evasion",
            "action": "Verify ips_helper binary hash; replacement is a FortiBleed persistence mechanism.",
        },
        "fortibleed_data_lib_write": {
            "pattern": r"/data/lib/",
            "severity": "high",
            "attack": "T1543.003",
            "tactic": "Persistence",
            "action": "Audit all files under /data/lib/; hidden files or unexpected binaries indicate implant staging.",
        },
        "fortibleed_sniffer_pcap": {
            "pattern": r"(?:libpcap|pcap_open|pcap_loop|BPF filter)\b",
            "severity": "high",
            "attack": "T1040",
            "tactic": "Credential Access",
            "action": "Packet capture library activity on FortiGate outside maintenance window is suspicious; review process context.",
        },
        "fortibleed_credential_exfil_beacon": {
            "pattern": r"(?:POST|GET)\s+https?://[^\s]+(?:beacon|c2|collect|exfil|upload)[^\s]*",
            "severity": "critical",
            "attack": "T1041",
            "tactic": "Exfiltration",
            "action": "Block destination IP/domain immediately; potential credential exfiltration beacon detected.",
        },
        "fortibleed_ssl_vpn_exploit": {
            "pattern": r"(?:sslvpn|ssl-vpn).*(?:heap.?overflow|buffer.?overflow|out.?of.?bound|CVE-2022-42475|CVE-2024-21762)",
            "severity": "critical",
            "attack": "T1190",
            "tactic": "Initial Access",
            "action": "Confirm FortiOS patch level; exploit attempt or crash log entry suggests active exploitation.",
        },
        "fortibleed_suspicious_child_proc": {
            "pattern": r"(?:httpsd|sslvpnd|ips_helper)\s+(?:exec|spawn|fork|system|popen)\s+\S+",
            "severity": "high",
            "attack": "T1059",
            "tactic": "Execution",
            "action": "Investigate child process spawned from VPN/IPS daemon; indicative of post-exploit code execution.",
        },
        "fortibleed_tmp_exec": {
            "pattern": r"exec(?:ve|vp)?\s+(?:/tmp/|/var/tmp/)[^\s]+",
            "severity": "high",
            "attack": "T1059",
            "tactic": "Execution",
            "action": "Execution from /tmp is a red flag; collect the binary for forensic analysis before it is deleted.",
        },
        "fortibleed_crontab_modification": {
            "pattern": r"(?:crontab|/etc/cron)\b.*(?:write|modify|append|insert)",
            "severity": "high",
            "attack": "T1053.003",
            "tactic": "Persistence",
            "action": "Review crontab entries for unknown jobs; attackers may schedule implant re-install via cron.",
        },
        "fortibleed_passwd_shadow_read": {
            "pattern": r"(?:open|read)\s+/etc/(?:passwd|shadow)",
            "severity": "medium",
            "attack": "T1003.008",
            "tactic": "Credential Access",
            "action": "Verify which process read credential files; FortiBleed implant harvests local credentials.",
        },
        "fortibleed_ldap_credential_dump": {
            "pattern": r"ldap(?:s)?://[^\s]+.*(?:bind|password|userPassword)",
            "severity": "medium",
            "attack": "T1556",
            "tactic": "Credential Access",
            "action": "Inspect LDAP bind credentials in log; implant may be harvesting directory service passwords.",
        },
        "fortibleed_abnormal_mgmt_traffic": {
            "pattern": r"(?:dst=(?:4\.2\.2\.|8\.8\.8\.|1\.1\.1\.)|dstport=(?:4444|1337|31337|12345))\b",
            "severity": "medium",
            "attack": "T1071.001",
            "tactic": "Command and Control",
            "action": "Management-plane traffic to non-standard or public DNS IPs may indicate C2 tunneling; investigate.",
        },
        "fortibleed_kernel_module_load": {
            "pattern": r"(?:insmod|modprobe|init_module)\s+\S+",
            "severity": "high",
            "attack": "T1547.006",
            "tactic": "Persistence",
            "action": "Unauthorized kernel module load may represent rootkit installation; collect module for analysis.",
        },
        "fortibleed_log_clear": {
            "pattern": r"(?:clear\s+log|log\s+delete|truncate.*log|unlink.*\.log)",
            "severity": "medium",
            "attack": "T1070.002",
            "tactic": "Defense Evasion",
            "action": "Log clearing activity detected; attacker may be removing exploitation evidence.",
        },
    }


def scan_log(log_file, signatures):
    compiled = {name: (re.compile(sig["pattern"], re.IGNORECASE), sig) for name, sig in signatures.items()}
    findings = []
    seen = set()
    try:
        with open(log_file, "r", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.rstrip()
                for name, (regex, sig) in compiled.items():
                    if regex.search(line):
                        key = (name, lineno)
                        if key in seen:
                            continue
                        seen.add(key)
                        ts_match = re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", line)
                        findings.append({
                            "signature": name,
                            "severity": sig["severity"],
                            "attack_id": sig["attack"],
                            "tactic": sig["tactic"],
                            "action": sig["action"],
                            "lineno": lineno,
                            "timestamp": ts_match.group(0) if ts_match else None,
                            "raw_line": line[:300],
                        })
    except OSError as exc:
        print(f"ERROR: Cannot read log file: {exc}", file=sys.stderr)
        sys.exit(2)
    findings.sort(key=lambda f: SEVERITIES.index(f["severity"]), reverse=True)
    return findings


def render_report(findings, args):
    min_idx = SEVERITIES.index(args.severity)
    filtered = [f for f in findings if SEVERITIES.index(f["severity"]) >= min_idx]

    if args.json:
        print(json.dumps(filtered, indent=2))
    else:
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"=== FortiBleed Triage Report  generated={now}  file={args.log_file} ===")
        print(f"    Total findings: {len(findings)}  Displayed (>={args.severity}): {len(filtered)}")
        print()
        if not filtered:
            print("[ PASS ] No findings at or above the requested severity threshold.")
        for f in filtered:
            badge = "[ CRITICAL ]" if f["severity"] == "critical" else f"[  {f['severity'].upper():<8}]"
            ts = f["timestamp"] or "unknown-time"
            print(f"{badge}  Line {f['lineno']:>6}  {ts}")
            print(f"           Signature : {f['signature']}")
            print(f"           ATT&CK    : {f['attack_id']} ({f['tactic']})")
            print(f"           Action    : {f['action']}")
            print(f"           Evidence  : {f['raw_line'][:120]}")
            print()

    has_critical = any(f["severity"] == "critical" for f in filtered)
    if has_critical:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="FortiBleed Triage Scanner: detect CVE-2022-42475/CVE-2024-21762 implant artifacts in FortiGate logs."
    )
    parser.add_argument("log_file", help="Path to plain-text FortiGate log file.")
    parser.add_argument(
        "--severity",
        choices=SEVERITIES,
        default="low",
        help="Minimum finding severity to emit (default: low).",
    )
    parser.add_argument("--json", action="store_true", help="Output findings as JSON array.")
    args = parser.parse_args()

    signatures = load_signatures()
    findings = scan_log(args.log_file, signatures)
    render_report(findings, args)


if __name__ == "__main__":
    main()