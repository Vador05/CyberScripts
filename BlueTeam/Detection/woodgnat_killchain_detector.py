"""
Woodgnat/Mistic Kill Chain Detector

Scans plain-text security logs for indicators spanning the Mistic/Woodgnat
IAB-to-ransomware kill chain, matching stage-specific embedded Sigma-style rules
against Qilin, Akira, Black Basta, and affiliated families.

Usage:
    python woodgnat_killchain_detector.py /var/log/security.log
    python woodgnat_killchain_detector.py auth.log --family akira --stage lateral_movement
    python woodgnat_killchain_detector.py events.log --family all --stage exfil
"""

import argparse
import re
import sys
from typing import Generator

_MAX_LINE_LEN = 4096


def load_rules() -> dict:
    raw = [
        ("all",        "initial_access",   "WG-IA-001", r"(?i)(mistic|woodgnat|qbot|pikabot|darkgate)\s+(loader|dropper|stub)"),
        ("all",        "initial_access",   "WG-IA-002", r"(?i)(phish|malspam|html\s*smuggl|iso\s*mount|lnk\s*execut)"),
        ("all",        "initial_access",   "WG-IA-003", r"(?i)iab\s*(handoff|access|sale|auction)"),
        ("qilin",      "initial_access",   "QL-IA-001", r"(?i)(qilin|agenda)\s*(ransomware|payload|sample)"),
        ("akira",      "initial_access",   "AK-IA-001", r"(?i)akira\s*(ransomware|affiliate|access)"),
        ("black_basta","initial_access",   "BB-IA-001", r"(?i)(black.?basta|blackbasta)\s*(access|entry|iab)"),
        ("all",        "execution",        "WG-EX-001", r"(?i)(wscript|cscript|mshta|regsvr32|rundll32|certutil)\.exe.{0,80}(http|\\\\|cmd|powershell)"),
        ("all",        "execution",        "WG-EX-002", r"(?i)powershell.{0,60}(-enc|-nop|-w\s*hidden|-exec\s*bypass)"),
        ("all",        "execution",        "WG-EX-003", r"(?i)(cmd\.exe|command\.com).{0,60}(/c|/k).{0,60}(echo|set\s*/a|for\s*/f)"),
        ("all",        "execution",        "WG-EX-004", r"(?i)(msiexec|installutil|regasm|regsvcs)\.exe.{0,60}(http|\\\\[a-z0-9])"),
        ("all",        "execution",        "WG-EX-005", r"(?i)wmic.{0,60}(process\s*call\s*create|shadowcopy\s*delete)"),
        ("all",        "persistence",      "WG-PE-001", r"(?i)(schtasks|at\.exe).{0,80}(/create|/add).{0,80}(/tr|/sc)"),
        ("all",        "persistence",      "WG-PE-002", r"(?i)(HKLM|HKCU)\\[^\s]{0,120}(run|runonce|services)[^\s]{0,60}(cmd|powershell|wscript|regsvr)"),
        ("all",        "persistence",      "WG-PE-003", r"(?i)(new-service|sc\s*create|sc\s*config).{0,80}(binpath|start=\s*auto)"),
        ("all",        "persistence",      "WG-PE-004", r"(?i)(startup|appdata\\roaming\\microsoft\\windows\\start\s*menu\\programs\\startup)"),
        ("all",        "lateral_movement", "WG-LM-001", r"(?i)(psexec|psexesvc|wmiexec|smbexec|dcomexec)"),
        ("all",        "lateral_movement", "WG-LM-002", r"(?i)net\s+(use|view|share).{0,60}(\\\\[a-z0-9\-\.]+\\[a-z$])"),
        ("all",        "lateral_movement", "WG-LM-003", r"(?i)(impacket|secretsdump|mimikatz|lsass\s*dump|procdump.{0,30}lsass)"),
        ("all",        "lateral_movement", "WG-LM-004", r"(?i)(pass.?the.?hash|pth|overpass.?the.?hash|kerberoast|asreproast)"),
        ("all",        "lateral_movement", "WG-LM-005", r"(?i)(cobalt.?strike|beacon\.dll|cs\s*listener|named\s*pipe.*msagent)"),
        ("all",        "exfil",            "WG-EF-001", r"(?i)(rclone|megasync|mega\.nz).{0,80}(copy|sync|upload|remote)"),
        ("all",        "exfil",            "WG-EF-002", r"(?i)rclone.{0,80}(--config|--transfers|--checkers|--no-check-certificate)"),
        ("all",        "exfil",            "WG-EF-003", r"(?i)(curl|wget|certutil).{0,80}(-T|--upload|--post).{0,60}(http|ftp)"),
        ("all",        "exfil",            "WG-EF-004", r"(?i)(7z|winrar|winzip).{0,80}(a\s|add).{0,80}(-p|-hp).{0,40}(\.zip|\.7z|\.rar)"),
        ("qilin",      "exfil",            "QL-EF-001", r"(?i)(qilin|agenda).{0,60}(exfil|steal|upload|mega|rclone)"),
        ("akira",      "exfil",            "AK-EF-001", r"(?i)akira.{0,60}(exfil|steal|upload|mega|rclone)"),
        ("black_basta","exfil",            "BB-EF-001", r"(?i)black.?basta.{0,60}(exfil|steal|upload|rclone|mega)"),
        ("all",        "ransomware",       "WG-RW-001", r"(?i)(vssadmin|wmic\s+shadowcopy).{0,60}(delete|resize\s+shadowstorage)"),
        ("all",        "ransomware",       "WG-RW-002", r"(?i)(bcdedit|bootcfg).{0,80}(recoveryenabled\s+no|safeboot|ignoreallfailures)"),
        ("all",        "ransomware",       "WG-RW-003", r"(?i)(ransom.?note|readme\.txt|decrypt.?instruction|how.?to.?decrypt|restore.?file)"),
        ("all",        "ransomware",       "WG-RW-004", r"(?i)\.(qilin|akira|basta|encrypted|locked|crypt)\b"),
        ("qilin",      "ransomware",       "QL-RW-001", r"(?i)(qilin|agenda).{0,60}(encrypt|ransom|\.qilin|\.agenda)"),
        ("akira",      "ransomware",       "AK-RW-001", r"(?i)akira.{0,60}(encrypt|ransom|\.akira)"),
        ("black_basta","ransomware",       "BB-RW-001", r"(?i)black.?basta.{0,60}(encrypt|ransom|\.basta|readme\.txt)"),
    ]
    rules = {}
    for family, stage, rule_id, pattern in raw:
        rules[(family, stage, rule_id)] = re.compile(pattern)
    return rules


def scan_log(
    logfile: str,
    rules: dict,
    family_filter: str,
    stage_filter: str,
) -> Generator[tuple, None, None]:
    families = ["all", family_filter] if family_filter != "all" else ["all", "qilin", "akira", "black_basta"]
    with open(logfile, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            stripped = line.rstrip("\n")[:_MAX_LINE_LEN]
            for (family, stage, rule_id), pattern in rules.items():
                if family not in families:
                    continue
                if stage_filter != "all" and stage != stage_filter:
                    continue
                if pattern.search(stripped):
                    tag = family if family != "all" else "multi"
                    yield (stage, tag, rule_id, lineno, stripped[:200])


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Woodgnat/Mistic Kill Chain Detector — stage-labels log hits across Qilin, Akira, Black Basta"
    )
    parser.add_argument("logfile", help="Path to plain-text log file")
    parser.add_argument(
        "--family",
        choices=["qilin", "akira", "black_basta", "all"],
        default="all",
        help="Filter by ransomware family (default: all)",
    )
    parser.add_argument(
        "--stage",
        choices=["initial_access", "execution", "persistence", "lateral_movement", "exfil", "ransomware", "all"],
        default="all",
        help="Filter by kill chain stage (default: all)",
    )
    args = parser.parse_args()

    try:
        rules = load_rules()
    except re.error as exc:
        print(f"[ERROR] Rule compilation failed: {exc}", file=sys.stderr)
        sys.exit(2)

    stage_counts: dict[str, int] = {}
    hit_found = False

    try:
        for stage, family, rule_id, lineno, excerpt in scan_log(args.logfile, rules, args.family, args.stage):
            hit_found = True
            stage_counts[stage] = stage_counts.get(stage, 0) + 1
            print(f"{stage:<20} | {family:<12} | {rule_id:<12} | L{lineno:<7} | {excerpt}")
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {args.logfile}", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print(f"[ERROR] Permission denied reading: {args.logfile}", file=sys.stderr)
        sys.exit(2)
    except OSError as exc:
        print(f"[ERROR] Cannot read log file: {exc}", file=sys.stderr)
        sys.exit(2)

    if stage_counts:
        print("\n--- Hit Summary ---")
        for stage, count in sorted(stage_counts.items()):
            print(f"  {stage:<20}: {count}")
        print(f"  {'TOTAL':<20}: {sum(stage_counts.values())}")

    sys.exit(1 if hit_found else 0)


if __name__ == "__main__":
    main()