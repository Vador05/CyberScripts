"""
npm Supply Chain Attack Lab

Parses a plain-text npm verbose install log to detect postinstall scripts,
simulates pre-npm12 execution, applies npm12 opt-in blocking, and generates
allowlist migration artifacts.

Usage:
    python npm_supply_chain_lab.py --log install.log --mode attack
    python npm_supply_chain_lab.py --log install.log --mode block
    python npm_supply_chain_lab.py --log install.log --mode migrate --allow lodash,chalk
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass
from typing import List, Set


@dataclass
class ScriptEntry:
    package: str
    command: str
    status: str = ""
    risk: str = ""


EXFIL_PATTERNS = re.compile(
    r"curl|wget|fetch|http[s]?://|dns|nslookup|ping|nc\s|netcat|base64.*decode",
    re.IGNORECASE,
)
NET_CALL_PATTERNS = re.compile(
    r"require\(['\"]https?['\"]|axios|got\.|request\(|XMLHttpRequest|socket\.connect",
    re.IGNORECASE,
)
FS_WRITE_PATTERNS = re.compile(
    r"fs\.write|fs\.append|writeFile|mkdir|chmod|chown|rm\s+-rf|>\s*/|tee\s+/",
    re.IGNORECASE,
)
EXEC_PATTERNS = re.compile(
    r"exec\(|spawn\(|child_process|eval\(|Function\(|__import__|subprocess|shell=True",
    re.IGNORECASE,
)

LOG_PATTERN = re.compile(
    r"npm\s+(?:verb|verbose)\s+.*?run-script\s+postinstall.*?>\s*(?P<pkg>[^\s@]+)@[^\s]*\s+postinstall\s*\n.*?(?P<cmd>[^\n]+)",
    re.MULTILINE | re.IGNORECASE,
)
ALT_LOG_PATTERN = re.compile(
    r"(?:npm\s+)?(?:verb|verbose|info)\s+lifecycle\s+(?P<pkg>[^\s@]+)@[^\s~]*~postinstall:\s*(?P<cmd>.+)",
    re.IGNORECASE,
)
SCRIPT_BLOCK_PATTERN = re.compile(
    r">\s+(?P<pkg>[^\s@]+)@[\d.]+\s+postinstall\s*\n\s*>\s*(?P<cmd>.+)",
    re.MULTILINE,
)


def parse_log(path: str) -> List[ScriptEntry]:
    try:
        with open(path, "r", errors="replace") as f:
            content = f.read()
    except OSError as e:
        print(f"Error reading log file: {e}", file=sys.stderr)
        sys.exit(1)

    entries = []
    seen = set()

    for pattern in (LOG_PATTERN, ALT_LOG_PATTERN, SCRIPT_BLOCK_PATTERN):
        for m in pattern.finditer(content):
            pkg = m.group("pkg").strip()
            cmd = m.group("cmd").strip()
            key = (pkg, cmd)
            if key not in seen:
                seen.add(key)
                entries.append(ScriptEntry(package=pkg, command=cmd))

    if not entries:
        lines = content.splitlines()
        current_pkg = None
        for line in lines:
            pkg_match = re.search(r">\s+([^\s@]+)@[\d.]+\s+postinstall", line)
            if pkg_match:
                current_pkg = pkg_match.group(1)
            elif current_pkg and re.match(r">\s+\S", line):
                cmd = line.lstrip("> ").strip()
                key = (current_pkg, cmd)
                if key not in seen:
                    seen.add(key)
                    entries.append(ScriptEntry(package=current_pkg, command=cmd))
                current_pkg = None

    return entries


def classify_risk(command: str) -> str:
    if EXFIL_PATTERNS.search(command):
        return "EXFIL-PATTERN"
    if NET_CALL_PATTERNS.search(command):
        return "NET-CALL"
    if FS_WRITE_PATTERNS.search(command) or EXEC_PATTERNS.search(command):
        return "FS-WRITE"
    return "OK"


def evaluate_scripts(
    entries: List[ScriptEntry], mode: str, allow_set: Set[str]
) -> List[ScriptEntry]:
    results = []
    for entry in entries:
        risk = classify_risk(entry.command)
        if mode == "attack":
            status = "RAN"
        else:
            status = "RAN" if entry.package in allow_set else "BLOCKED"
        results.append(ScriptEntry(package=entry.package, command=entry.command, status=status, risk=risk))
    return results


def render_output(results: List[ScriptEntry], mode: str, allow_set: Set[str]) -> None:
    if not results:
        print("No postinstall scripts detected in log.")
        return

    col_widths = (30, 60, 7, 13)
    headers = ("PACKAGE", "POSTINSTALL COMMAND", "STATUS", "RISK TAG")
    sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    row_fmt = "| {:<30} | {:<60} | {:<7} | {:<13} |"

    print(sep)
    print("| {:<30} | {:<60} | {:<7} | {:<13} |".format(*headers))
    print(sep)

    for r in results:
        cmd_display = r.command[:59] + "…" if len(r.command) > 60 else r.command
        print(row_fmt.format(r.package[:30], cmd_display, r.status, r.risk))

    print(sep)
    ran = sum(1 for r in results if r.status == "RAN")
    blocked = sum(1 for r in results if r.status == "BLOCKED")
    print(f"\nTotal: {len(results)} scripts | RAN: {ran} | BLOCKED: {blocked}")

    if mode == "migrate":
        detected_pkgs = {r.package for r in results}
        missing = allow_set - detected_pkgs
        if missing:
            print(
                f"\nWARNING: The following --allow packages were not found in the log "
                f"and are excluded from the allowlist: {', '.join(sorted(missing))}",
                file=sys.stderr,
            )
        approved = [r.package for r in results if r.package in allow_set]
        allowlist = {"npmLifecycleScriptAllowList": sorted(set(approved))}
        print("\n--- Allowlist JSON (paste into package.json) ---")
        print(json.dumps(allowlist, indent=2))
        print("--- End Allowlist ---")
        print("\nWARNING: Human review required before committing this allowlist.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="npm Supply Chain Attack Lab — detect and classify postinstall scripts",
        epilog="Example: python npm_supply_chain_lab.py --log install.log --mode block",
    )
    parser.add_argument("--log", required=True, metavar="<path>", help="npm verbose install log file")
    parser.add_argument(
        "--mode",
        choices=["attack", "block", "migrate"],
        default="attack",
        help="attack=show all as pre-npm12 RAN, block=apply npm12 opt-in, migrate=output allowlist",
    )
    parser.add_argument(
        "--allow",
        default="",
        metavar="<pkg,...>",
        help="comma-separated pre-approved packages (used in block/migrate modes)",
    )
    args = parser.parse_args()

    allow_set: Set[str] = {p.strip() for p in args.allow.split(",") if p.strip()}
    entries = parse_log(args.log)
    results = evaluate_scripts(entries, args.mode, allow_set)
    render_output(results, args.mode, allow_set)


if __name__ == "__main__":
    main()