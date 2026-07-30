"""
npm/PyPI Package Compromise Detector

Scans registry event logs and CI pipeline output for supply-chain compromise signals
across three kill-chain stages: ChecksumDrift, MaintainerChange, WalletExfil.

Usage:
    python pkg_compromise_detector.py registry.log
    python pkg_compromise_detector.py ci_output.log --severity high
    python pkg_compromise_detector.py audit.log --iocs extra_iocs.json --severity medium
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

KNOWN_GOOD_CHECKSUMS = {
    "lodash@4.17.21": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZR7Y5+8MjKo5VGYLtA==",
    "express@4.18.2": "sha512-ab2oPuPQ89MoTMXNZMOEAfOTNlq6+kPcKl2G7fXiGPKMJaP9gcVE4N8idS+RGcGGCmgPMZCqRYMkDPbDMoSA==",
    "requests@2.31.0": "sha256-942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1",
    "numpy@1.24.3": "sha256-ab344f1bf21f140adab8e47fdbc7c35a477dc01408791f8ba00d018dd0bc5155",
    "django@4.2.7": "sha256-bf8ff9ac9ca37bf22fb755f9657a1de2e7a87f439dde4cfe0498fc6a47cbde08",
    "react@18.2.0": "sha512-/3IjMdb2L9QbBdWiW5e3P2/npwMBaU9mHCSCUyNfu31lze/ZGYqTvjdkPesjkYcs9oBKSMmCyz5UkBYiPOoA==",
    "axios@1.4.0": "sha512-S4XCWMEmzvo64T9GfvQDOXgYRDJ/wsSZc7Jvdgx5u1sd0JwsuPLqb3SYmusag+edF6ziyMensPVqLTSc1PiSg==",
}

KNOWN_GOOD_MAINTAINERS = {
    "nicolo-ribaudo", "ljharb", "sindresorhus", "isaacs", "mikeal",
    "tj", "expressjs", "kennethreitz", "psf", "django", "facebook", "meta",
}

SUSPICIOUS_MAINTAINER_RE = re.compile(r"0day|inject|pwn|exfil|evil|malware|c2bot|supplychain", re.I)
FRESH_ACCOUNT_RE = re.compile(r"\d{6,}|tmp\d{3,}|user\d{5,}|bot\d{4,}", re.I)

WALLET_EXFIL_DOMAINS = {
    "cdn-bootstrap.net", "npmpackage.live", "pypi-cdn.info", "pkg-update.xyz",
    "registry-mirror.cc", "wallet-harvest.io", "crypto-exfil.ru", "btc-drain.top",
    "eth-stealer.pw", "npm-stats.cc", "pypi-analytics.xyz", "package-telemetry.ru",
}
WALLET_EXFIL_IPS = {
    "185.220.101.45", "45.142.212.100", "194.165.16.11",
    "91.108.4.0", "77.91.68.0", "5.188.206.0",
}

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

PKG_VER_RE = re.compile(r"([\w\-\.@/]+)@([\d][\d\.\w\-]*)")
HASH_RE = re.compile(r"integrity[:\s]+(sha(?:256|512)[:\-][A-Za-z0-9+/=]+)", re.I)
MAINTAINER_RE = re.compile(r"(?:added|owner add|maintainer added)[:\s]+([\w\.\-@+]+)", re.I)
HOST_RE = re.compile(
    r"(?:(?:GET|POST|connect(?:ing)?|fetch|curl|wget|socket\.connect)\s+(?:https?://)?|https?://)([^\s/\"':]+)",
    re.I,
)


def parse_log_entry(line):
    entry = {"pkg": None, "ver": None, "hash": None, "maintainer": None, "host": None}
    m = PKG_VER_RE.search(line)
    if m:
        entry["pkg"], entry["ver"] = m.group(1), m.group(2)
    m = HASH_RE.search(line)
    if m:
        entry["hash"] = m.group(1)
    m = MAINTAINER_RE.search(line)
    if m:
        entry["maintainer"] = m.group(1).strip()
    m = HOST_RE.search(line)
    if m:
        entry["host"] = m.group(1).lower().split(":")[0]
    return entry


def match_rules(entry, extra_checksums, extra_bad_maintainers, all_domains, all_ips):
    findings = []
    pkg, ver = entry["pkg"] or "unknown", entry["ver"] or "unknown"

    if entry["hash"] and entry["pkg"] and entry["ver"]:
        checksums = {**KNOWN_GOOD_CHECKSUMS, **extra_checksums}
        key = f"{entry['pkg']}@{entry['ver']}"
        if key in checksums and entry["hash"] != checksums[key]:
            findings.append(("ChecksumDrift", "integrity-hash-mismatch", "high", pkg, ver))

    if entry["maintainer"]:
        acct = entry["maintainer"]
        if SUSPICIOUS_MAINTAINER_RE.search(acct) or acct in extra_bad_maintainers:
            findings.append(("MaintainerChange", "suspicious-account-pattern", "high", pkg, ver))
        elif FRESH_ACCOUNT_RE.search(acct):
            findings.append(("MaintainerChange", "freshly-registered-account-pattern", "medium", pkg, ver))
        elif acct not in KNOWN_GOOD_MAINTAINERS:
            findings.append(("MaintainerChange", "unknown-contributor-added", "low", pkg, ver))

    if entry["host"]:
        h = entry["host"]
        if h in all_ips or any(h == d or h.endswith("." + d) for d in all_domains):
            findings.append(("WalletExfil", "outbound-exfil-endpoint", "high", pkg, ver))

    return findings


def run(log_path, min_severity, extra_iocs):
    extra_checksums = extra_iocs.get("checksums", {})
    extra_bad_maintainers = set(extra_iocs.get("bad_maintainers", []))
    all_domains = WALLET_EXFIL_DOMAINS | set(extra_iocs.get("domains", []))
    all_ips = WALLET_EXFIL_IPS | set(extra_iocs.get("ips", []))
    min_rank = SEVERITY_RANK[min_severity]

    try:
        lines = Path(log_path).read_text(errors="replace").splitlines()
    except OSError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    seen = set()
    stage_counts = {"ChecksumDrift": 0, "MaintainerChange": 0, "WalletExfil": 0}
    peak_sev = -1
    has_high = False
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for line in lines:
        entry = parse_log_entry(line)
        for stage, rule, sev, pkg, ver in match_rules(entry, extra_checksums, extra_bad_maintainers, all_domains, all_ips):
            if SEVERITY_RANK[sev] < min_rank:
                continue
            key = (stage, rule, pkg, ver)
            if key in seen:
                continue
            seen.add(key)
            stage_counts[stage] += 1
            peak_sev = max(peak_sev, SEVERITY_RANK[sev])
            has_high = has_high or sev == "high"
            print(f"[{ts}] [{stage}] [{sev.upper()}] rule={rule} pkg={pkg}@{ver} | {line.rstrip()}")

    peak_label = ["low", "medium", "high"][peak_sev] if peak_sev >= 0 else "none"
    print("\n--- Summary ---")
    for stage, count in stage_counts.items():
        print(f"  {stage}: {count} hit(s)")
    print(f"  PeakSeverity: {peak_label}")

    if has_high:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Detect npm/PyPI package compromise from registry event logs.")
    parser.add_argument("log_file", help="Path to registry event log or CI pipeline output")
    parser.add_argument("--iocs", metavar="FILE", help="JSON with supplemental domains, IPs, checksums, bad_maintainers")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low", help="Minimum alert severity (default: low)")
    args = parser.parse_args()

    extra_iocs = {}
    if args.iocs:
        try:
            extra_iocs = json.loads(Path(args.iocs).read_text())
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR loading IOC file: {e}", file=sys.stderr)
            sys.exit(2)

    run(args.log_file, args.severity, extra_iocs)


if __name__ == "__main__":
    main()