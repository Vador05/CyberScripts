"""
Marketplace Plugin Risk Scanner

Scans a plain-text log of IDE plugin metadata to flag suspicious packages
using velocity anomalies and publisher freshness heuristics.

Usage example:
    python plugin_risk_scanner.py plugins.log --threshold 10 --max-publisher-age-days 30

Log file format (one JSON object per line):
    {"name": "my-plugin", "publisher": "acme", "publisher_age_days": 5,
     "download_delta": 50000, "baseline_downloads": 100}
"""

import argparse
import json
import sys


def _sanitize(s):
    """Strip tab and newline characters to prevent TSV output injection."""
    return s.replace("\t", " ").replace("\r", " ").replace("\n", " ")


def parse_plugin_log(path):
    with open(path, "r") as fh:
        for lineno, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                print(f"[WARN] line {lineno}: skipping malformed JSON: {exc}", file=sys.stderr)
                continue

            name = obj.get("name") or obj.get("plugin_name") or obj.get("id")
            if not name:
                print(f"[WARN] line {lineno}: missing plugin name field, skipping", file=sys.stderr)
                continue

            try:
                publisher_age_days = float(obj["publisher_age_days"])
                download_delta = float(obj["download_delta"])
                baseline = float(obj.get("baseline_downloads", 0))
            except (KeyError, TypeError, ValueError) as exc:
                print(f"[WARN] line {lineno}: missing/invalid numeric field: {exc}, skipping", file=sys.stderr)
                continue

            if publisher_age_days < 0:
                print(f"[WARN] line {lineno}: negative publisher_age_days ({publisher_age_days}), skipping", file=sys.stderr)
                continue
            if download_delta < 0:
                print(f"[WARN] line {lineno}: negative download_delta ({download_delta}), skipping", file=sys.stderr)
                continue
            if baseline < 0:
                print(f"[WARN] line {lineno}: negative baseline_downloads ({baseline}), skipping", file=sys.stderr)
                continue

            yield {
                "name": str(name),
                "publisher": str(obj.get("publisher", "unknown")),
                "publisher_age_days": publisher_age_days,
                "download_delta": download_delta,
                "baseline_downloads": baseline,
            }


def score_risk(plugin, threshold, max_age):
    age = plugin["publisher_age_days"]
    delta = plugin["download_delta"]
    baseline = plugin["baseline_downloads"]

    if baseline > 0:
        velocity_ratio = delta / baseline
    elif delta > 0:
        # No historical baseline: any positive delta is an infinite-ratio spike.
        velocity_ratio = float("inf")
    else:
        velocity_ratio = 0.0

    new_publisher = age <= max_age
    velocity_spike = velocity_ratio >= threshold

    if new_publisher and velocity_spike:
        return "HIGH", f"new publisher ({age:.0f}d) + velocity spike ({velocity_ratio:.1f}x)", velocity_ratio
    if new_publisher and not velocity_spike:
        return "MEDIUM", f"new publisher account ({age:.0f} days old)", velocity_ratio
    if velocity_spike and not new_publisher:
        return "MEDIUM", f"velocity spike ({velocity_ratio:.1f}x baseline)", velocity_ratio
    return "LOW", "no anomalies detected", velocity_ratio


def main():
    parser = argparse.ArgumentParser(
        description="Scan IDE plugin metadata log for supply-chain risk signals."
    )
    parser.add_argument("log_file", help="Path to plain-text plugin metadata log (one JSON per line)")
    parser.add_argument(
        "--threshold",
        type=int,
        default=10,
        help="Download velocity spike multiplier to flag (default: 10)",
    )
    parser.add_argument(
        "--max-publisher-age-days",
        type=int,
        default=30,
        dest="max_publisher_age_days",
        help="Publisher account age ceiling in days to flag as new (default: 30)",
    )
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be >= 1")
    if args.max_publisher_age_days < 0:
        parser.error("--max-publisher-age-days must be >= 0")

    try:
        plugins = list(parse_plugin_log(args.log_file))
    except FileNotFoundError:
        print(f"[ERROR] log file not found: {args.log_file}", file=sys.stderr)
        sys.exit(2)
    except OSError as exc:
        print(f"[ERROR] cannot read log file: {exc}", file=sys.stderr)
        sys.exit(2)

    if not plugins:
        print("[INFO] no valid plugin entries found in log.", file=sys.stderr)
        sys.exit(0)

    header = "\t".join(["RISK", "PLUGIN", "PUBLISHER", "PUBLISHER_AGE_DAYS", "VELOCITY_RATIO", "REASON"])
    print(header)

    found_high = False
    for plugin in plugins:
        risk, reason, velocity_ratio = score_risk(plugin, args.threshold, args.max_publisher_age_days)
        if risk == "HIGH":
            found_high = True
        ratio_str = "inf" if velocity_ratio == float("inf") else f"{velocity_ratio:.2f}"
        row = "\t".join([
            risk,
            _sanitize(plugin["name"]),
            _sanitize(plugin["publisher"]),
            f"{plugin['publisher_age_days']:.0f}",
            ratio_str,
            _sanitize(reason),
        ])
        print(row)

    if found_high:
        sys.exit(1)


if __name__ == "__main__":
    main()