"""
npm_binary_drop_scanner.py - Scans npm lifecycle scripts for native binary drop patterns.

Usage:
    python npm_binary_drop_scanner.py package.json
    python npm_binary_drop_scanner.py package-lock.json --min-severity medium
    python npm_binary_drop_scanner.py package.json --recursive
    python npm_binary_drop_scanner.py /repo/package.json --min-severity high --recursive

Exit code 1 if any high-severity finding is detected.
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

HOOKS = ("preinstall", "install", "postinstall")

RULES = [
    {"name": "curl_pipe_shell", "severity": "high",
     "pattern": r"(?i)(curl|wget)\s+\S*https?://\S+\s*\|\s*(sh|bash|node|python3?)"},
    {"name": "download_chmod_exec", "severity": "high",
     "pattern": r"(?i)(curl|wget|fetch)\s+.*https?://.*(\bchmod\s*\+x\b|\bexec\s+\S)"},
    {"name": "base64_decode_exec", "severity": "high",
     "pattern": r"(?i)(echo\s+[A-Za-z0-9+/=]{20,}\s*\|.*base64.*-d|base64\s+--?decode).*(\|\s*(sh|bash|node|python)|exec\s)"},
    {"name": "rust_toolchain_build", "severity": "medium",
     "pattern": r"(?i)(cargo\s+build\s+--release|rustc\s+--edition|cross\s+build\s+--target\s+\S+-unknown-\S+)"},
    {"name": "neon_bindgen_build", "severity": "medium",
     "pattern": r"(?i)(neon\s+build|node-bindgen\s+build|napi\s+build)"},
    {"name": "node_pre_gyp_install", "severity": "medium",
     "pattern": r"(?i)(node-pre-gyp|@mapbox/node-pre-gyp|prebuild-install|node-gyp\s+rebuild)(\s+(install|download|rebuild))?"},
    {"name": "native_artifact_write", "severity": "low",
     "pattern": r"(?i)\b(cp|mv|install|copy)\b\s+\S+\.(node|so|dylib|exe|dll)\b"},
    {"name": "download_binary_url", "severity": "medium",
     "pattern": r"(?i)(curl|wget)\s+\S*https?://\S+\.(exe|bin|so|dylib|node|elf)\b"},
]

DOWNLOAD_OR_EXEC_RE = re.compile(
    r"(?i)(curl|wget|fetch|http\.get|https\.get|\|\s*(sh|bash|node|python)|exec\s|chmod\s*\+x)", re.I
)
SEV_RANK = {"low": 0, "medium": 1, "high": 2}
_compiled = [(r, re.compile(r["pattern"])) for r in RULES]


def parse_packages(pkg_path: Path, recursive: bool) -> list:
    paths = list(pkg_path.parent.rglob("package.json")) if recursive else [pkg_path]
    if not recursive and pkg_path.name == "package-lock.json":
        paths = [pkg_path]
    packages = []
    for p in paths:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"[WARN] Skipping {p}: {exc}", file=sys.stderr)
            continue
        if p.name == "package-lock.json":
            for pkg_name, pkg_data in data.get("packages", {}).items():
                hooks = {h: pkg_data["scripts"][h] for h in HOOKS if h in pkg_data.get("scripts", {})}
                if hooks:
                    packages.append({"name": pkg_name or data.get("name", "unknown"),
                                     "version": pkg_data.get("version", "?"),
                                     "scripts": hooks, "source": str(p)})
        else:
            scripts = data.get("scripts", {})
            hooks = {h: scripts[h] for h in HOOKS if h in scripts}
            if hooks:
                packages.append({"name": data.get("name", p.parent.name),
                                 "version": data.get("version", "?"),
                                 "scripts": hooks, "source": str(p)})
    return packages


def detect_binary_drops(packages: list) -> list:
    findings = []
    for pkg in packages:
        seen: set = set()
        for hook, script in pkg["scripts"].items():
            has_download_exec = bool(DOWNLOAD_OR_EXEC_RE.search(script))
            for rule, rx in _compiled:
                if not rx.search(script):
                    continue
                key = (pkg["name"], hook, rule["name"])
                if key in seen:
                    continue
                seen.add(key)
                sev = "high" if rule["severity"] == "medium" and has_download_exec else rule["severity"]
                findings.append({"package": pkg["name"], "version": pkg["version"],
                                 "hook": hook, "rule": rule["name"], "severity": sev,
                                 "fragment": script[:100], "source": pkg["source"]})
    return findings


def report_findings(findings: list, min_severity: str) -> int:
    visible = [f for f in findings if SEV_RANK[f["severity"]] >= SEV_RANK[min_severity]]
    rule_counts: dict = defaultdict(lambda: defaultdict(int))
    peak = "low"
    for f in visible:
        tag = f"[{f['severity'].upper():6}]"
        print(f"{tag} {f['package']}@{f['version']} [{f['hook']}] rule={f['rule']} | {f['fragment']!r}")
        rule_counts[f["rule"]][f["severity"]] += 1
        if SEV_RANK[f["severity"]] > SEV_RANK[peak]:
            peak = f["severity"]
    print(f"\n--- Summary: {len(visible)} finding(s), peak_severity={peak.upper()} ---")
    for rule_name, sevs in sorted(rule_counts.items()):
        detail = ", ".join(f"{s}={c}" for s, c in sorted(sevs.items(), key=lambda x: SEV_RANK[x[0]]))
        print(f"  {rule_name}: {detail}")
    return 1 if any(SEV_RANK[f["severity"]] >= SEV_RANK["high"] for f in visible) else 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan npm package.json lifecycle scripts for native binary drop patterns."
    )
    parser.add_argument("pkg_path", type=Path, help="Path to package.json or package-lock.json")
    parser.add_argument("--min-severity", choices=["low", "medium", "high"], default="low",
                        dest="min_severity", help="Minimum severity to emit (default: low)")
    parser.add_argument("--recursive", action="store_true",
                        help="Also scan every package.json under node_modules at pkg_path's parent")
    args = parser.parse_args()
    if not args.pkg_path.exists():
        print(f"[ERROR] Not found: {args.pkg_path}", file=sys.stderr)
        sys.exit(2)
    packages = parse_packages(args.pkg_path, args.recursive)
    if not packages:
        print("No packages with install lifecycle scripts found.")
        sys.exit(0)
    sys.exit(report_findings(detect_binary_drops(packages), args.min_severity))


if __name__ == "__main__":
    main()