"""
AI IDE Path-Hijacking Binary Guard

Scans a project directory for unexpected executable files that could be used
in path-hijacking attacks against AI IDEs such as Cursor, Copilot, or Windsurf.

Usage:
    python ai_ide_path_hijack_guard.py /path/to/project
    python ai_ide_path_hijack_guard.py . --allowlist safe_bins.json --severity high
    python ai_ide_path_hijack_guard.py /repo --severity medium

Example allowlist JSON:
    ["scripts/build.sh", "entrypoint", "run.sh"]
"""

import argparse
import json
import os
import stat
import sys

SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__"}

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def detect_binary_type(filepath):
    try:
        with open(filepath, "rb") as f:
            header = f.read(4)
    except (OSError, PermissionError):
        return None, None

    if header[:4] == ELF_MAGIC:
        return "ELF", "high"
    if header[:2] == PE_MAGIC:
        return "PE", "high"
    if header[:4] in MACHO_MAGICS:
        return "MachO", "high"

    try:
        file_stat = os.stat(filepath)
        mode = file_stat.st_mode
        if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            return "Script", "low"
    except OSError:
        return None, None

    return None, None


def get_permission_octet(filepath):
    try:
        mode = os.stat(filepath).st_mode
        return oct(stat.S_IMODE(mode))
    except OSError:
        return "unknown"


def scan_for_executables(directory):
    findings = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            filepath = os.path.join(root, filename)
            if os.path.islink(filepath):
                continue
            binary_type, severity = detect_binary_type(filepath)
            if binary_type is None:
                continue
            perm_octet = get_permission_octet(filepath)
            findings.append({
                "path": filepath,
                "rel_path": os.path.relpath(filepath, directory),
                "binary_type": binary_type,
                "severity": severity,
                "permissions": perm_octet,
            })
    return findings


def load_allowlist(allowlist_path, base_dir):
    if not allowlist_path:
        return set(), set()
    try:
        with open(allowlist_path, "r") as f:
            entries = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[ERROR] Failed to load allowlist '{allowlist_path}': {e}", file=sys.stderr)
        sys.exit(2)

    if not isinstance(entries, list):
        print("[ERROR] Allowlist JSON must be a list of strings.", file=sys.stderr)
        sys.exit(2)

    abs_paths = set()
    basenames = set()
    for entry in entries:
        if not isinstance(entry, str):
            continue
        abs_paths.add(os.path.abspath(os.path.join(base_dir, entry)))
        basenames.add(os.path.basename(entry))
    return abs_paths, basenames


def match_allowlist(findings, allowlist_abs, allowlist_basenames):
    filtered = []
    for finding in findings:
        abs_path = os.path.abspath(finding["path"])
        basename = os.path.basename(finding["path"])
        if abs_path in allowlist_abs or basename in allowlist_basenames:
            continue
        filtered.append(finding)
    return filtered


RISK_DESCRIPTIONS = {
    "ELF": "Native ELF binary may shadow a trusted executable via PATH manipulation",
    "PE": "Native PE binary may shadow a trusted executable via PATH manipulation",
    "MachO": "Native Mach-O binary may shadow a trusted executable via PATH manipulation",
    "Script": "Executable script may shadow a trusted command via PATH manipulation",
}


def report_findings(findings, min_severity):
    min_level = SEVERITY_ORDER[min_severity]
    type_counts = {}
    peak_level = -1
    exit_nonzero = False

    for finding in findings:
        sev = finding["severity"]
        sev_level = SEVERITY_ORDER[sev]

        if sev_level >= min_level:
            type_counts[finding["binary_type"]] = type_counts.get(finding["binary_type"], 0) + 1
            if sev_level > peak_level:
                peak_level = sev_level
            exit_nonzero = True
            risk = RISK_DESCRIPTIONS.get(finding["binary_type"], "Unexpected executable detected")
            print(
                f"[{sev.upper()}] {finding['binary_type']} | {finding['permissions']} | "
                f"{finding['rel_path']} | {risk}"
            )

    peak_severity = [k for k, v in SEVERITY_ORDER.items() if v == peak_level][0] if peak_level >= 0 else "none"
    total = sum(type_counts.values())
    type_summary = ", ".join(f"{k}={v}" for k, v in sorted(type_counts.items()))
    print(f"\nSummary: {total} unexpected executable(s) found | peak severity: {peak_severity} | {type_summary or 'none'}")

    if exit_nonzero:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Detect unexpected executable binaries that could enable path-hijacking attacks against AI IDEs."
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="Project root directory to scan (default: current working directory)",
    )
    parser.add_argument(
        "--allowlist",
        metavar="FILE",
        help="Path to JSON file listing expected executable filenames or relative paths",
    )
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum severity level to report (default: low)",
    )
    args = parser.parse_args()

    directory = os.path.abspath(args.directory)
    if not os.path.isdir(directory):
        print(f"[ERROR] '{directory}' is not a valid directory.", file=sys.stderr)
        sys.exit(2)

    findings = scan_for_executables(directory)
    allowlist_abs, allowlist_basenames = load_allowlist(args.allowlist, directory)
    filtered = match_allowlist(findings, allowlist_abs, allowlist_basenames)
    report_findings(filtered, args.severity)


if __name__ == "__main__":
    main()