"""
SRI Drift Monitor - Detects third-party script hash drift from SRI baselines.

Usage example:
    python sri_drift_monitor.py --baseline baseline.json --log access.log
    python sri_drift_monitor.py --baseline baseline.json --log access.log --strict

baseline.json format:
    {"https://cdn.example.com/lib.js": "sha384-abc123..."}

Log line format (space or tab separated, hash field prefixed with sha384=):
    2024-01-15T10:23:45Z GET https://cdn.example.com/lib.js sha384=abc123...
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone


def load_baseline(path: str) -> dict[str, str]:
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: Baseline file not found: {path}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in baseline file: {e}", file=sys.stderr)
        sys.exit(2)

    if not isinstance(data, dict):
        print("ERROR: Baseline JSON must be a top-level object mapping URLs to hashes.", file=sys.stderr)
        sys.exit(2)

    for url, h in data.items():
        if not isinstance(url, str) or not isinstance(h, str):
            print(f"ERROR: Baseline entries must be string:string pairs, got {url!r}: {h!r}", file=sys.stderr)
            sys.exit(2)
        if not h.startswith("sha384-"):
            print(f"WARNING: Expected hash for {url} does not start with 'sha384-': {h}", file=sys.stderr)

    return data


LOG_PATTERN = re.compile(
    r"(?P<timestamp>\S+)\s+\S+\s+(?P<url>https?://\S+)\s+.*sha384=(?P<hash>sha384-[A-Za-z0-9+/=]+)"
)

ALT_PATTERN = re.compile(
    r"(?P<timestamp>\S+)\s+(?P<url>https?://\S+)\s+sha384=(?P<hash>sha384-[A-Za-z0-9+/=]+)"
)


def parse_log(path: str) -> list[tuple[str, str, str]]:
    records = []
    try:
        with open(path, "r") as f:
            for lineno, line in enumerate(f, 1):
                line = line.rstrip("\n")
                m = LOG_PATTERN.search(line) or ALT_PATTERN.search(line)
                if m:
                    records.append((m.group("timestamp"), m.group("url"), m.group("hash")))
    except FileNotFoundError:
        print(f"ERROR: Log file not found: {path}", file=sys.stderr)
        sys.exit(2)
    except OSError as e:
        print(f"ERROR: Could not read log file: {e}", file=sys.stderr)
        sys.exit(2)

    return records


def check_drift(baseline: dict[str, str], records: list[tuple[str, str, str]]) -> bool:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    seen: dict[str, list[tuple[str, str]]] = {}

    for timestamp, url, observed_hash in records:
        if url in baseline:
            seen.setdefault(url, []).append((timestamp, observed_hash))

    drift_found = False

    for url, expected_hash in baseline.items():
        if url not in seen:
            print(f"[{now}] WARN url={url} expected={expected_hash} observed=<no log entries found>")
            continue

        entries = seen[url]
        for timestamp, observed_hash in entries:
            if observed_hash != expected_hash:
                print(
                    f"[{timestamp}] ALERT url={url} expected={expected_hash} observed={observed_hash}"
                )
                drift_found = True
            else:
                print(
                    f"[{timestamp}] OK url={url} expected={expected_hash} observed={observed_hash}"
                )

    return drift_found


def main():
    parser = argparse.ArgumentParser(
        description="Detect SRI hash drift in third-party scripts from access logs."
    )
    parser.add_argument("--baseline", required=True, metavar="<json_file>",
                        help="JSON file mapping script URLs to expected sha384 hashes")
    parser.add_argument("--log", required=True, metavar="<log_file>",
                        help="Plain-text access log with script fetch records")
    parser.add_argument("--strict", action="store_true",
                        help="Exit with code 1 if any drift is detected")
    args = parser.parse_args()

    baseline = load_baseline(args.baseline)
    records = parse_log(args.log)

    if not records:
        print("WARNING: No matching log entries found.", file=sys.stderr)

    drift = check_drift(baseline, records)

    if args.strict and drift:
        sys.exit(1)


if __name__ == "__main__":
    main()