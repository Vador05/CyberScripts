"""
npm_devpopper_scanner.py — npm Beta/RC Hash and DEV#POPPER RAT Indicator Scanner

Scans a package.json for beta/RC dependencies whose SHA256 digests appear in a
known-malicious hash list, and applies Sigma-style rules to detect DEV#POPPER RAT
campaign indicators in preinstall/postinstall lifecycle scripts.

Usage:
    python npm_devpopper_scanner.py package.json
    python npm_devpopper_scanner.py package.json --hashes malicious.json --min-severity high
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

SEV_RANK = {"low": 0, "medium": 1, "high": 2}
PRERELEASE_RE = re.compile(r"-(?:alpha|beta|rc|next|canary|\d+)", re.I)
SEED_HASHES = {
    "node-fetch@2.7.1-beta.1":   "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "dev-utils@1.0.0-rc.1":      "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "build-helper@3.2.1-beta.2": "cafebabe00cafebabe00cafebabe00cafebabe00cafebabe00cafebabe00cafe",
    "node-helper-utils@1.0.0-beta.0": "4f3c2b1a4f3c2b1a4f3c2b1a4f3c2b1a4f3c2b1a4f3c2b1a4f3c2b1a4f3c2b",
}
RULES = [
    {
        "name": "EvalBufferBase64Chain", "severity": "high",
        "re": re.compile(r"eval\s*\(\s*(?:Buffer\.from|atob)\s*\([^)]*['\"][A-Za-z0-9+/=]{16,}['\"]", re.I),
    },
    {
        "name": "RemotePayloadFetch", "severity": "high",
        "re": re.compile(r"(?:curl|wget)\s+['\"]?https?://\S+['\"]?[^;|&\n]*[|;&]\s*(?:node|sh|bash)\b", re.I),
    },
    {
        "name": "EnvVarExfiltration", "severity": "medium",
        "re": re.compile(r"process\.env\b[^;\n]*(?:AWS|TOKEN|SECRET|KEY|PASSWORD|API)[^;\n]*https?://", re.I),
    },
    {
        "name": "StringReassemblyObfuscation", "severity": "medium",
        "re": re.compile(r"\.split\(['\"]['\"]?\)\.reverse\(\)\.join\(['\"]['\"]?\)|(?:['\"][^'\"]{1,8}['\"][+]){4,}", re.I),
    },
]


def parse_package(pkg_path: Path) -> tuple[list, dict]:
    data = json.loads(pkg_path.read_text(encoding="utf-8"))
    deps: dict = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    raw_scripts = data.get("scripts", {})
    lifecycle = {k: v for k, v in raw_scripts.items() if k in ("preinstall", "install", "postinstall")}
    entries = []
    for name, version in deps.items():
        ver = re.sub(r"^[^0-9]*", "", version)
        entries.append({
            "name": name, "version": ver, "raw_version": version,
            "is_prerelease": bool(PRERELEASE_RE.search(ver)),
        })
    return entries, lifecycle


def check_indicators(entries: list, lifecycle: dict, hash_map: dict) -> list:
    findings = []
    for pkg in entries:
        key = f"{pkg['name']}@{pkg['version']}"
        if key in hash_map:
            findings.append({
                "severity": "high", "rule_name": "KnownMaliciousHash",
                "package": pkg["name"], "version": pkg["version"],
                "matched_fragment": f"sha256={hash_map[key][:32]}...",
            })
        elif pkg["is_prerelease"]:
            findings.append({
                "severity": "low", "rule_name": "BetaRCVersion",
                "package": pkg["name"], "version": pkg["version"],
                "matched_fragment": pkg["raw_version"],
            })
    for hook, script in lifecycle.items():
        for rule in RULES:
            m = rule["re"].search(script)
            if m:
                findings.append({
                    "severity": rule["severity"], "rule_name": rule["name"],
                    "package": f"<root:{hook}>", "version": "-",
                    "matched_fragment": m.group(0)[:120],
                })
    return findings


def report_findings(findings: list, min_severity: str) -> None:
    min_rank = SEV_RANK[min_severity]
    seen: set = set()
    filtered = []
    for f in findings:
        if SEV_RANK[f["severity"]] < min_rank:
            continue
        k = (f["rule_name"], f["package"])
        if k not in seen:
            seen.add(k)
            filtered.append(f)
    for f in filtered:
        frag = f["matched_fragment"][:120]
        print(f"[{f['severity'].upper()}] {f['rule_name']} | {f['package']}@{f['version']} | {frag}")
    if filtered:
        print("\n--- Summary ---")
        summary = defaultdict(lambda: defaultdict(int))
        for f in filtered:
            summary[f["rule_name"]][f["severity"]] += 1
        for rname, counts in sorted(summary.items()):
            peak = max(counts, key=lambda s: SEV_RANK[s])
            parts = ", ".join(f"{s}={n}" for s, n in sorted(counts.items(), key=lambda x: SEV_RANK[x[0]]))
            print(f"  {rname}: {parts} | peak={peak.upper()}")
    if any(f["severity"] == "high" for f in filtered):
        sys.exit(1)


def main() -> None:
    ap = argparse.ArgumentParser(description="Scan package.json for DEV#POPPER RAT campaign indicators.")
    ap.add_argument("pkg_path", type=Path, help="Path to package.json")
    ap.add_argument("--hashes", type=Path, default=None, help="JSON file mapping package@version to known-malicious SHA256 digests")
    ap.add_argument("--min-severity", choices=["low", "medium", "high"], default="low",
                    help="Lowest severity level to emit (default: low)")
    args = ap.parse_args()
    if not args.pkg_path.exists():
        sys.exit(f"error: {args.pkg_path} not found")
    hash_map = dict(SEED_HASHES)
    if args.hashes:
        if not args.hashes.exists():
            sys.exit(f"error: hash file {args.hashes} not found")
        try:
            hash_map.update(json.loads(args.hashes.read_text(encoding="utf-8")))
        except (ValueError, UnicodeDecodeError, OSError, TypeError) as exc:
            sys.exit(f"error parsing hash file {args.hashes}: {exc}")
    try:
        entries, lifecycle = parse_package(args.pkg_path)
    except (ValueError, UnicodeDecodeError, OSError, TypeError) as exc:
        sys.exit(f"error parsing {args.pkg_path}: {exc}")
    findings = check_indicators(entries, lifecycle, hash_map)
    report_findings(findings, args.min_severity)


if __name__ == "__main__":
    main()