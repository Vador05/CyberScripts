"""
pkg_baseline_gate.py - Package checksum and maintainer-key baseline gate.

Compares current npm/PyPI integrity manifest against a known-good baseline
to surface checksum drift and unexpected key rotations before package install.

Usage:
    python pkg_baseline_gate.py manifest.json                              # bootstrap baseline
    python pkg_baseline_gate.py manifest.json --baseline baseline.json
    python pkg_baseline_gate.py manifest.json --baseline baseline.json --severity high

Exit code 1 if any high-severity finding is detected.
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

SEV_RANK = {"low": 0, "medium": 1, "high": 2}
DEFAULT_BASELINE = Path("pkg_baseline.json")


def normalize_digest(value: str) -> str:
    return re.sub(r"^(sha256-|sha512-|sha1-)", "", value, flags=re.I).lower()


def normalize_fingerprint(fp: str) -> str:
    return re.sub(r"\s+", "", fp).lower()


def parse_entries(data) -> list:
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "packages" in data:
        entries = []
        for path, pkg in data["packages"].items():
            if not path:
                continue
            name = pkg.get("name") or path.split("node_modules/")[-1]
            if pkg.get("version") and pkg.get("integrity"):
                entries.append({"name": name, "version": pkg["version"], "integrity": pkg["integrity"]})
        return entries
    if isinstance(data, dict):
        for key in ("dependencies", "results", "audited"):
            if key in data and isinstance(data[key], list):
                return data[key]
    return []


def load_manifest(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"[ERROR] Cannot read {path}: {e}")
    entries = parse_entries(raw)
    result = {}
    for entry in entries:
        name = entry.get("name") or entry.get("package")
        version = entry.get("version") or entry.get("installed_version")
        integrity = entry.get("integrity") or entry.get("digest") or entry.get("checksum")
        if not (name and version and integrity):
            continue
        key = f"{name}@{version}"
        raw_fps = entry.get("maintainer_keys") or entry.get("fingerprints") or []
        result[key] = {
            "digest": normalize_digest(str(integrity)),
            "fingerprints": [normalize_fingerprint(str(f)) for f in raw_fps if f is not None and str(f).strip()],
        }
    if not result:
        sys.exit(f"[ERROR] No valid entries in {path} — each entry needs name, version, and integrity fields")
    return result


def detect_drift(current: dict, baseline: dict) -> list:
    findings = []
    for key, cur in current.items():
        name, version = key.rsplit("@", 1)
        if key not in baseline:
            findings.append({"severity": "low", "drift_type": "NewPackage", "package": name,
                             "version": version, "baseline_value": "(absent)", "current_value": cur["digest"]})
            continue
        base = baseline[key]
        if cur["digest"] != base["digest"]:
            findings.append({"severity": "high", "drift_type": "ChecksumDrift", "package": name,
                             "version": version, "baseline_value": base["digest"], "current_value": cur["digest"]})
        base_fps = set(base["fingerprints"])
        for fp in cur["fingerprints"]:
            if fp and fp not in base_fps:
                findings.append({"severity": "medium", "drift_type": "KeyRotation", "package": name,
                                 "version": version,
                                 "baseline_value": ",".join(base["fingerprints"]) or "(none)",
                                 "current_value": fp})
    return findings


def report_findings(findings: list, min_severity: str) -> None:
    min_rank = SEV_RANK[min_severity]
    seen = set()
    counts: dict = defaultdict(lambda: defaultdict(int))
    peak = 0
    visible = []

    for f in findings:
        dedup = (f["drift_type"], f["package"], f["version"], f["current_value"])
        if dedup in seen:
            continue
        seen.add(dedup)
        counts[f["drift_type"]][f["severity"]] += 1
        rank = SEV_RANK[f["severity"]]
        if rank > peak:
            peak = rank
        if rank >= min_rank:
            visible.append(f)

    for f in visible:
        print(f"[{f['severity'].upper()}] {f['drift_type']} | {f['package']}@{f['version']} "
              f"| {f['baseline_value']} -> {f['current_value']}")

    if counts:
        print("\n--- Summary ---")
        for dtype, sevs in sorted(counts.items()):
            parts = ", ".join(f"{s}={c}" for s, c in sorted(sevs.items(), key=lambda x: -SEV_RANK[x[0]]))
            print(f"  {dtype}: {parts}")
        print(f"  Peak severity: {['low','medium','high'][peak].upper()}")
    else:
        print("[OK] No drift detected against baseline.")

    if peak == SEV_RANK["high"]:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Package checksum and maintainer-key baseline gate")
    parser.add_argument("manifest", type=Path, help="Path to current package integrity manifest JSON")
    parser.add_argument("--baseline", type=Path, default=None, help="Path to known-good baseline JSON")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum severity to emit (default: low)")
    args = parser.parse_args()

    if not args.manifest.exists():
        sys.exit(f"[ERROR] Manifest not found: {args.manifest}")

    if args.baseline is None:
        try:
            raw_manifest_text = args.manifest.read_text(encoding="utf-8")
            raw_manifest = json.loads(raw_manifest_text)
        except (OSError, json.JSONDecodeError) as e:
            sys.exit(f"[ERROR] Cannot read {args.manifest}: {e}")
        # Validate manifest before enrolling it as the baseline
        current = load_manifest(args.manifest)
        # Save the original manifest schema (not the normalized dict) so load_manifest
        # can re-parse the baseline on subsequent runs via parse_entries()
        DEFAULT_BASELINE.write_text(json.dumps(raw_manifest, indent=2), encoding="utf-8")
        print(f"[INFO] Baseline enrolled at {DEFAULT_BASELINE} ({len(current)} packages). "
              f"Re-run with --baseline {DEFAULT_BASELINE} to gate.")
        sys.exit(0)

    if not args.baseline.exists():
        sys.exit(f"[ERROR] Baseline not found: {args.baseline}")

    current = load_manifest(args.manifest)
    baseline = load_manifest(args.baseline)
    findings = detect_drift(current, baseline)
    report_findings(findings, args.severity)


if __name__ == "__main__":
    main()