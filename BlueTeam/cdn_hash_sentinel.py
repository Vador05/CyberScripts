"""
CDN Hash Sentinel - Detects unexpected CDN asset hash changes indicating supply chain compromise.

Usage examples:
    python cdn_hash_sentinel.py --mode simulate --log-file /tmp/cdn_update.log
    python cdn_hash_sentinel.py --mode detect --log-file /tmp/cdn_update.log
    python cdn_hash_sentinel.py --mode detect --log-file /tmp/cdn_update.log --asset jquery.min.js
"""

import argparse
import re
import sys
import os
from datetime import datetime, timedelta

BASELINE_HASHES = {
    "jquery.min.js": "sha256-abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
    "bootstrap.min.js": "sha256-111aaa222bbb333ccc444ddd555eee666fff777888999000aaabbbcccdddeee",
    "react.production.min.js": "sha256-deadbeefcafe1234deadbeefcafe1234deadbeefcafe1234deadbeefcafe1234",
    "lodash.min.js": "sha256-feedface0000feedface0000feedface0000feedface0000feedface0000feed",
    "moment.min.js": "sha256-ca11ab1eca11ab1eca11ab1eca11ab1eca11ab1eca11ab1eca11ab1eca11ab",
}

LOG_LINE_FORMAT = "{timestamp} ASSET_UPDATE asset={asset} expected={expected} observed={observed} cdn=cdn-edge-{cdn_id}.example.com\n"

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|[\x00-\x1f\x7f]")
# Unicode bidi overrides and directional isolates that can spoof terminal output
_UNICODE_CTRL = re.compile(
    r"[\u200b-\u200f\u2028-\u202f\u2066-\u206f\ufff9-\ufffc]"
)
_MAX_FIELD_LEN = 256


def _sanitize(value: str) -> str:
    value = _ANSI_ESCAPE.sub("", value)
    value = _UNICODE_CTRL.sub("", value)
    if len(value) > _MAX_FIELD_LEN:
        value = value[:_MAX_FIELD_LEN] + "...[truncated]"
    return value


def simulate_update_log(log_file: str) -> None:
    if os.path.exists(log_file):
        print(f"[WARN] Log file already exists and will be overwritten: {log_file}", file=sys.stderr)

    base_time = datetime(2026, 6, 16, 8, 0, 0)
    entries = []

    for i, (asset, expected_hash) in enumerate(BASELINE_HASHES.items()):
        ts = (base_time + timedelta(minutes=i * 15)).strftime("%Y-%m-%dT%H:%M:%SZ")
        entries.append(LOG_LINE_FORMAT.format(
            timestamp=ts,
            asset=asset,
            expected=expected_hash,
            observed=expected_hash,
            cdn_id=str(100 + i),
        ))

    malicious_asset = "jquery.min.js"
    malicious_ts = (base_time + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    malicious_observed = "sha256-0000000000000000000000000000000000000000000000000000000000000000"
    entries.append(LOG_LINE_FORMAT.format(
        timestamp=malicious_ts,
        asset=malicious_asset,
        expected=BASELINE_HASHES[malicious_asset],
        observed=malicious_observed,
        cdn_id="999",
    ))

    try:
        with open(log_file, "w") as f:
            f.writelines(entries)
        print(f"[SIMULATE] Wrote {len(entries)} log entries to {log_file}")
        print(f"[SIMULATE] Injected malicious hash mismatch for '{malicious_asset}' at {malicious_ts}")
    except OSError as e:
        print(f"[ERROR] Failed to write log file: {e}", file=sys.stderr)
        sys.exit(1)


def detect_hash_changes(log_file: str, asset_filter: str = None) -> int:
    pattern = re.compile(
        r"(?P<timestamp>\S+)\s+ASSET_UPDATE\s+"
        r"asset=(?P<asset>\S+)\s+"
        r"expected=(?P<expected>\S+)\s+"
        r"observed=(?P<observed>\S+)\s+"
        r"cdn=(?P<cdn>\S+)"
    )

    alerts = []

    try:
        with open(log_file, "r") as f:
            for lineno, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                m = pattern.search(line)
                if not m:
                    continue

                asset = m.group("asset")
                expected = m.group("expected")
                observed = m.group("observed")
                timestamp = m.group("timestamp")
                cdn = m.group("cdn")

                if asset_filter and asset != asset_filter:
                    continue

                baseline = BASELINE_HASHES.get(asset)
                if baseline is None:
                    alerts.append({
                        "line": lineno,
                        "timestamp": timestamp,
                        "asset": asset,
                        "expected": expected,
                        "observed": observed,
                        "cdn": cdn,
                        "reason": "UNKNOWN_ASSET",
                    })
                    continue

                if observed != baseline:
                    alerts.append({
                        "line": lineno,
                        "timestamp": timestamp,
                        "asset": asset,
                        "expected": baseline,
                        "observed": observed,
                        "cdn": cdn,
                        "reason": "HASH_MISMATCH",
                    })
    except OSError as e:
        print(f"[ERROR] Cannot read log file: {e}", file=sys.stderr)
        sys.exit(1)

    if alerts:
        print("[ALERT] Supply chain anomalies detected:")
        print("-" * 80)
        for a in alerts:
            print(
                f"LINE      : {a['line']}\n"
                f"TIMESTAMP : {_sanitize(a['timestamp'])}\n"
                f"ASSET     : {_sanitize(a['asset'])}\n"
                f"REASON    : {a['reason']}\n"
                f"CDN       : {_sanitize(a['cdn'])}\n"
                f"EXPECTED  : {_sanitize(a['expected'])}\n"
                f"OBSERVED  : {_sanitize(a['observed'])}\n"
                f"SEVERITY  : HIGH\n"
            )
            print("-" * 80)
    else:
        print("[OK] No hash anomalies detected.")

    return len(alerts)


def main():
    parser = argparse.ArgumentParser(
        description="CDN Hash Sentinel: detect supply chain hash anomalies in CDN plugin update logs."
    )
    parser.add_argument("--mode", choices=["simulate", "detect"], required=True,
                        help="simulate: generate synthetic log; detect: scan log for anomalies")
    parser.add_argument("--log-file", required=True, help="Path to CDN update log file")
    parser.add_argument("--asset", default=None, help="Optional asset name filter for detection")
    args = parser.parse_args()

    if args.mode == "simulate":
        simulate_update_log(args.log_file)
    elif args.mode == "detect":
        if not os.path.isfile(args.log_file):
            print(f"[ERROR] Log file not found: {args.log_file}", file=sys.stderr)
            sys.exit(1)
        count = detect_hash_changes(args.log_file, asset_filter=args.asset)
        print(f"\n[SUMMARY] Total alerts: {count}")
        sys.exit(1 if count > 0 else 0)


if __name__ == "__main__":
    main()