"""
PolinRider Dependency Backdoor Scanner

Parses a project dependency manifest and cross-references each pinned package
against a PolinRider compromised-package threat database.

Usage:
    python polinrider_dep_scanner.py requirements.txt
    python polinrider_dep_scanner.py package.json --min-severity high
    python polinrider_dep_scanner.py go.mod --threat-db /path/to/custom.db
    python polinrider_dep_scanner.py composer.json --min-severity medium

Exit code 0 = clean, exit code 1 = compromised packages found.
"""

import argparse
import json
import re
import sys
from pathlib import Path

BUNDLED_THREAT_DB = """
pypi:polinrider-utils:1.0.0:1.0.1:high:PolinRider-2024-A
pypi:setup-tools-ext:2.3.1:2.3.2:high:PolinRider-2024-B
pypi:requests-async-ext:0.6.0:0.7.0:medium:PolinRider-2024-C
pypi:colorama-plus:0.4.5:0.4.6:low:PolinRider-2024-D
npm:polinrider-core:3.1.0:3.1.1:high:PolinRider-2024-E
npm:lodash-utils-ext:4.17.20:4.17.21:medium:PolinRider-2024-F
npm:express-middleware-pro:1.2.3:1.2.4:high:PolinRider-2024-G
npm:axios-interceptor:0.21.0:0.21.1:low:PolinRider-2024-H
go:github.com/polinrider/utils:v1.0.0:v1.0.1:high:PolinRider-2024-I
go:github.com/example/logger-ext:v2.1.0:v2.1.1:medium:PolinRider-2024-J
packagist:polinrider/core:1.5.0:1.5.1:high:PolinRider-2024-K
packagist:vendor/helper-ext:2.0.0:2.0.1:medium:PolinRider-2024-L
""".strip()

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

# npm and go preserve original case; pypi and packagist are case-insensitive
CASE_INSENSITIVE_ECOSYSTEMS = {"pypi", "packagist"}


def _normalize_package_name(ecosystem, package):
    if ecosystem in CASE_INSENSITIVE_ECOSYSTEMS:
        return package.lower()
    return package


def _version_tuple(ver_str):
    v = ver_str.lstrip("v").strip()
    parts = re.split(r"[.\-]", v)
    result = []
    for p in parts:
        result.append(int(p) if p.isdigit() else p)
    return tuple(result)


def _version_matches(pinned, comp_ver_spec):
    """Exact match, or range check when comp_ver_spec starts with a comparison operator."""
    for op in (">=", "<=", "!=", ">", "<", "=="):
        if comp_ver_spec.startswith(op):
            spec_ver = comp_ver_spec[len(op):].strip()
            try:
                p = _version_tuple(pinned)
                s = _version_tuple(spec_ver)
                if op == ">=":
                    return p >= s
                if op == "<=":
                    return p <= s
                if op == "!=":
                    return p != s
                if op == ">":
                    return p > s
                if op == "<":
                    return p < s
                if op == "==":
                    return p == s
            except Exception:
                return False
    return pinned == comp_ver_spec


def load_threat_db(db_path=None):
    if db_path:
        try:
            content = Path(db_path).read_text(encoding="utf-8")
        except OSError as e:
            sys.exit(f"[ERROR] Cannot read threat DB '{db_path}': {e}")
    else:
        content = BUNDLED_THREAT_DB

    db = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 6:
            print(f"[WARN] Skipping malformed threat DB entry (too few fields): {line!r}", file=sys.stderr)
            continue
        ecosystem = parts[0].strip().lower()
        package = parts[1].strip()
        comp_ver = parts[2].strip()
        safe_ver = parts[3].strip()
        severity = parts[4].strip().lower()
        label = ":".join(parts[5:]).strip()
        if not ecosystem or not package or not comp_ver or not safe_ver:
            print(f"[WARN] Skipping malformed threat DB entry (empty required field): {line!r}", file=sys.stderr)
            continue
        if severity not in SEVERITY_ORDER:
            print(f"[WARN] Skipping entry with unknown severity '{severity}' for {ecosystem}:{package}", file=sys.stderr)
            continue
        norm_package = _normalize_package_name(ecosystem, package)
        key = (ecosystem, norm_package)
        db[key] = {"comp_ver": comp_ver, "safe_ver": safe_ver, "severity": severity, "label": label}
    return db


def parse_manifest(manifest_path):
    path = Path(manifest_path)
    if not path.exists():
        sys.exit(f"[ERROR] Manifest file not found: {manifest_path}")

    name = path.name.lower()
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as e:
        sys.exit(f"[ERROR] Cannot read manifest '{manifest_path}': {e}")

    deps = []

    if name == "requirements.txt":
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_\-\.]+)==([^\s;]+)", line)
            if m:
                deps.append(("pypi", _normalize_package_name("pypi", m.group(1)), m.group(2)))
            else:
                pkg_match = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
                if pkg_match:
                    deps.append(("pypi", _normalize_package_name("pypi", pkg_match.group(1)), None))

    elif name == "package.json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            sys.exit(f"[ERROR] Invalid JSON in package.json: {e}")
        for section in ("dependencies", "devDependencies"):
            for pkg, ver in data.get(section, {}).items():
                clean = ver.lstrip("^~=v").strip() if isinstance(ver, str) else None
                pinned = clean if clean and re.match(r"^\d+\.\d+", clean) else None
                deps.append(("npm", _normalize_package_name("npm", pkg), pinned))

    elif name == "go.mod":
        for line in content.splitlines():
            m = re.match(r"^\s+([^\s]+)\s+(v[^\s]+)", line)
            if m:
                deps.append(("go", _normalize_package_name("go", m.group(1)), m.group(2)))

    elif name == "composer.json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            sys.exit(f"[ERROR] Invalid JSON in composer.json: {e}")
        for pkg, ver in data.get("require", {}).items():
            if pkg == "php":
                continue
            clean = ver.lstrip("^~=v").strip() if isinstance(ver, str) else None
            pinned = clean if clean and re.match(r"^\d+\.\d+", clean) else None
            deps.append(("packagist", _normalize_package_name("packagist", pkg), pinned))

    else:
        sys.exit(f"[ERROR] Unsupported manifest type: {name}. Supported: requirements.txt, package.json, go.mod, composer.json")

    return deps


def scan_and_report(deps, threat_db, min_severity):
    min_level = SEVERITY_ORDER.get(min_severity, 0)
    hits = []
    unresolvable = []
    peak = -1

    for ecosystem, package, version in deps:
        key = (ecosystem, package)
        entry = threat_db.get(key)
        if not entry:
            continue
        if version is None:
            unresolvable.append((ecosystem, package))
            continue
        if not _version_matches(version, entry["comp_ver"]):
            continue
        sev_level = SEVERITY_ORDER[entry["severity"]]
        if sev_level < min_level:
            continue
        if sev_level > peak:
            peak = sev_level
        hits.append((ecosystem, package, version, entry))

    for h in hits:
        ecosystem, package, version, entry = h
        print(f"[ALERT] [{entry['severity'].upper()}] {ecosystem}:{package}@{version} | Campaign: {entry['label']} | Upgrade to: {entry['safe_ver']}")

    if unresolvable:
        for ecosystem, package in unresolvable:
            print(f"[WARN] {ecosystem}:{package} version unresolvable (not pinned) — lock to exact version for reliable scanning")

    total = len(deps)
    hit_count = len(hits)
    peak_label = [k for k, v in SEVERITY_ORDER.items() if v == peak][0].upper() if peak >= 0 else "NONE"
    print(f"\n[SUMMARY] Scanned: {total} | Compromised: {hit_count} | Peak severity: {peak_label}")

    return hit_count > 0


def main():
    parser = argparse.ArgumentParser(
        description="PolinRider Dependency Backdoor Scanner — pre-install supply chain gate",
        epilog="Example: python polinrider_dep_scanner.py requirements.txt --min-severity medium"
    )
    parser.add_argument("manifest_path", help="Path to requirements.txt, package.json, go.mod, or composer.json")
    parser.add_argument("--threat-db", dest="threat_db", default=None, help="Path to custom threat DB file (default: bundled list)")
    parser.add_argument("--min-severity", dest="min_severity", choices=["low", "medium", "high"], default="low", help="Minimum severity to report (default: low)")
    args = parser.parse_args()

    threat_db = load_threat_db(args.threat_db)
    deps = parse_manifest(args.manifest_path)
    found = scan_and_report(deps, threat_db, args.min_severity)
    sys.exit(1 if found else 0)


if __name__ == "__main__":
    main()