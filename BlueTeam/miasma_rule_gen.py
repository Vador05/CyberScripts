"""
miasma_rule_gen.py - Scans plain-text logs for Miasma malware IOCs and emits YARA or Sigma rules.

Usage:
    python miasma_rule_gen.py /var/log/endpoint.log --format yara --threshold 2
    python miasma_rule_gen.py /var/log/endpoint.log --format sigma --threshold 3
"""

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

IOC_PATTERNS = {
    "dpapi_access": re.compile(r"CryptUnprotectData|dpapi\.dll|DPAPI", re.IGNORECASE),
    "lsass_access": re.compile(r"lsass\.exe|OpenProcess.*lsass|MiniDumpWriteDump", re.IGNORECASE),
    "browser_vault": re.compile(r"Login Data|Cookies|Web Data|\.sqlite.*password|chrome.*vault|firefox.*key4\.db", re.IGNORECASE),
    "npm_hook": re.compile(r"preinstall|postinstall|scripts.*install.*node_modules|\.npmrc.*hook", re.IGNORECASE),
    "pip_hook": re.compile(r"setup\.py.*cmdclass|egg-link.*post|pip.*install.*hook|\.pth.*import", re.IGNORECASE),
    "dll_sideload": re.compile(r"AppData.*Roaming.*\.dll|HKCU.*Image File Execution|hijack.*dll|side.?load", re.IGNORECASE),
    "registry_persist": re.compile(r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|HKLM.*CurrentVersion.*Run", re.IGNORECASE),
    "cred_store": re.compile(r"Windows Credential Manager|CredEnumerate|vault\.vcrd|\.crd file", re.IGNORECASE),
    "supply_chain_pkg": re.compile(r"typosquat|dependency.?confusion|package.*miasma|malicious.*package", re.IGNORECASE),
    "exfil_beacon": re.compile(r"POST.*/(exfil|harvest|collect|upload).*credential|multipart.*creds", re.IGNORECASE),
}

SIGNATURE_TABLE = {
    "credential_harvesting": ["dpapi_access", "lsass_access", "browser_vault", "cred_store"],
    "supply_chain_delivery": ["npm_hook", "pip_hook", "supply_chain_pkg"],
    "persistence_mechanism": ["registry_persist", "dll_sideload"],
    "data_exfiltration": ["exfil_beacon"],
}


def parse_log(path: str) -> dict:
    candidates = {k: [] for k in IOC_PATTERNS}
    try:
        with open(path, "r", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                for name, pattern in IOC_PATTERNS.items():
                    if pattern.search(line):
                        candidates[name].append(lineno)
    except OSError as exc:
        print(f"Error reading log file: {exc}", file=sys.stderr)
        sys.exit(1)
    return candidates


def match_signatures(candidates: dict) -> dict:
    scored = {}
    for sig_name, ioc_keys in SIGNATURE_TABLE.items():
        hits = {k: candidates[k] for k in ioc_keys if candidates.get(k)}
        total = sum(len(v) for v in hits.values())
        if total > 0:
            scored[sig_name] = {"total_hits": total, "ioc_hits": hits}
    return scored


def _yara_rule(sig_name: str, data: dict, timestamp: str) -> str:
    rule_id = f"Miasma_{sig_name.title().replace('_', '')}"
    ioc_lines = []
    for ioc, lines in data["ioc_hits"].items():
        ioc_lines.append(f'        $ioc_{ioc} = "{ioc.replace("_", " ")}" nocase wide ascii')
    strings_block = "\n".join(ioc_lines)
    condition_vars = " or ".join(f"$ioc_{k}" for k in data["ioc_hits"])
    evidence = ", ".join(f"{k}({len(v)} hits)" for k, v in data["ioc_hits"].items())
    return (
        f"// Generated: {timestamp} | Evidence: {evidence} | Total hits: {data['total_hits']}\n"
        f"rule {rule_id} {{\n"
        f"    meta:\n"
        f"        description = \"Miasma {sig_name.replace('_', ' ')} detection\"\n"
        f"        author = \"miasma_rule_gen\"\n"
        f"        date = \"{timestamp[:10]}\"\n"
        f"        reference = \"Miasma public IOC disclosure\"\n"
        f"    strings:\n"
        f"{strings_block}\n"
        f"    condition:\n"
        f"        {condition_vars}\n"
        f"}}\n"
    )


def _sigma_rule(sig_name: str, data: dict, timestamp: str) -> str:
    evidence = ", ".join(f"{k}({len(v)} hits)" for k, v in data["ioc_hits"].items())
    keywords = [k.replace("_", " ") for k in data["ioc_hits"]]
    kw_block = "\n".join(f"        - '{kw}'" for kw in keywords)
    return (
        f"# Generated: {timestamp} | Evidence: {evidence} | Total hits: {data['total_hits']}\n"
        f"title: Miasma {sig_name.replace('_', ' ').title()}\n"
        f"id: miasma-{sig_name.replace('_', '-')}\n"
        f"status: experimental\n"
        f"description: Detects Miasma malware {sig_name.replace('_', ' ')} activity\n"
        f"references:\n"
        f"    - Miasma public IOC disclosure\n"
        f"author: miasma_rule_gen\n"
        f"date: {timestamp[:10]}\n"
        f"logsource:\n"
        f"    category: process_creation\n"
        f"    product: windows\n"
        f"detection:\n"
        f"    keywords:\n"
        f"{kw_block}\n"
        f"    condition: keywords\n"
        f"falsepositives:\n"
        f"    - Legitimate security tooling\n"
        f"level: high\n"
        f"---\n"
    )


def emit_rules(scored_hits: dict, fmt: str, threshold: int) -> None:
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    emitted = 0
    for sig_name, data in scored_hits.items():
        if data["total_hits"] < threshold:
            continue
        if fmt == "sigma":
            print(_sigma_rule(sig_name, data, timestamp))
        else:
            print(_yara_rule(sig_name, data, timestamp))
        emitted += 1
    if emitted == 0:
        print(f"# No signatures met threshold of {threshold} hits.", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan logs for Miasma IOCs and emit YARA or Sigma detection rules."
    )
    parser.add_argument("log_file", help="Path to plain-text log file to analyze")
    parser.add_argument("--format", choices=["yara", "sigma"], default="yara", help="Output rule format (default: yara)")
    parser.add_argument("--threshold", type=int, default=2, help="Minimum signature hits required to emit a rule (default: 2)")
    args = parser.parse_args()

    if not Path(args.log_file).is_file():
        print(f"Error: log file not found: {args.log_file}", file=sys.stderr)
        sys.exit(1)

    if args.threshold < 1:
        print("Error: threshold must be >= 1", file=sys.stderr)
        sys.exit(1)

    candidates = parse_log(args.log_file)
    scored = match_signatures(candidates)
    emit_rules(scored, args.format, args.threshold)


if __name__ == "__main__":
    main()