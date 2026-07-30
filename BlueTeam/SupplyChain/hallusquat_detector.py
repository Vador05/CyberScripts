"""
HalluSquat Package Registry Threat Detector

Reads a plain-text list of AI-recommended package names, queries PyPI or npm
registry APIs, and flags packages that are absent, newly registered, or show
near-zero release activity -- the compound risk profile of HalluSquatting.

Usage:
    python hallusquat_detector.py packages.txt
    python hallusquat_detector.py packages.txt --ecosystem npm
    python hallusquat_detector.py packages.txt --ecosystem pypi --max-age-days 180
    python hallusquat_detector.py packages.txt --ecosystem npm --max-age-days 30

Exit code 0 = all packages pass, exit code 1 = NOT_FOUND or NEWLY_REGISTERED detected.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timezone


def load_packages(packages_file):
    seen = set()
    result = []
    with open(packages_file, "r", encoding="utf-8") as f:
        for line in f:
            name = line.strip()
            if not name or name.startswith("#"):
                continue
            if name not in seen:
                seen.add(name)
                result.append(name)
    return result


def query_registry(package, ecosystem):
    if ecosystem == "pypi":
        return _query_pypi(package)
    return _query_npm(package)


def _fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "hallusquat-detector/1.0"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _query_pypi(package):
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        data = _fetch_json(url)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"first_published": None, "release_count": 0, "download_last_month": None}
        raise

    releases = data.get("releases", {})
    release_count = len(releases)

    first_published = None
    earliest = None
    for version_files in releases.values():
        for f in version_files:
            upload_time = f.get("upload_time")
            if upload_time:
                dt = datetime.fromisoformat(upload_time)
                if earliest is None or dt < earliest:
                    earliest = dt

    if earliest:
        first_published = earliest.date().isoformat()

    return {"first_published": first_published, "release_count": release_count, "download_last_month": None}


def _query_npm(package):
    url = f"https://registry.npmjs.org/{package}"
    try:
        data = _fetch_json(url)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"first_published": None, "release_count": 0, "download_last_month": None}
        raise

    times = data.get("time", {})
    created_str = times.get("created")
    first_published = None
    if created_str:
        dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
        first_published = dt.date().isoformat()

    versions = data.get("versions", {})
    release_count = len(versions)

    download_last_month = None
    encoded = urllib.request.quote(package, safe="@/")
    dl_url = f"https://api.npmjs.org/downloads/point/last-month/{encoded}"
    try:
        dl_data = _fetch_json(dl_url)
        download_last_month = dl_data.get("downloads")
    except (urllib.error.HTTPError, urllib.error.URLError):
        pass

    return {"first_published": first_published, "release_count": release_count, "download_last_month": download_last_month}


def analyze_and_report(packages, ecosystem, max_age_days):
    today = date.today()
    counts = {"NOT_FOUND": 0, "NEWLY_REGISTERED": 0, "LOW_ACTIVITY": 0, "OK": 0}
    has_critical = False

    print(f"{'STATUS':<18} {'PACKAGE':<35} {'AGE(days)':<12} {'RELEASES':<10} RISK NOTE")
    print("-" * 100)

    for pkg in packages:
        try:
            info = query_registry(pkg, ecosystem)
        except Exception as e:
            print(f"{'ERROR':<18} {pkg:<35} {'N/A':<12} {'N/A':<10} Query failed: {e}", file=sys.stderr)
            continue

        first_pub = info["first_published"]
        release_count = info["release_count"]
        download_last_month = info["download_last_month"]

        if first_pub is None:
            status = "NOT_FOUND"
            age_str = "N/A"
            note = "Package absent from registry -- likely hallucinated name; prime HalluSquat target"
            has_critical = True
        else:
            pub_date = date.fromisoformat(first_pub)
            age_days = (today - pub_date).days
            age_str = str(age_days)

            if age_days <= max_age_days:
                status = "NEWLY_REGISTERED"
                note = f"Registered only {age_days}d ago (threshold {max_age_days}d) -- high HalluSquat risk"
                has_critical = True
            elif release_count < 3:
                status = "LOW_ACTIVITY"
                dl_note = f", {download_last_month} downloads/month" if download_last_month is not None else ""
                note = f"Only {release_count} release(s){dl_note} -- verify publisher identity before install"
            else:
                status = "OK"
                dl_note = f", {download_last_month} downloads/month" if download_last_month is not None else ""
                note = f"Established package{dl_note}"

        counts[status] += 1
        print(f"{status:<18} {pkg:<35} {age_str:<12} {str(release_count):<10} {note}")

    print()
    print("=" * 100)
    print(f"SUMMARY: {len(packages)} packages checked on {ecosystem.upper()}")
    for s, c in counts.items():
        print(f"  {s}: {c}")

    if has_critical:
        print("\nRECOMMENDATION: BLOCK installation -- NOT_FOUND or NEWLY_REGISTERED packages detected.")
        print("                Do not proceed until each flagged package is manually verified.")
    else:
        print("\nRECOMMENDATION: All packages passed critical checks. Review any LOW_ACTIVITY flags manually.")

    return has_critical


def main():
    parser = argparse.ArgumentParser(
        description="Detect likely HalluSquat threats in AI-recommended package lists."
    )
    parser.add_argument("packages_file", help="Path to plain-text file with one package name per line")
    parser.add_argument(
        "--ecosystem",
        choices=["pypi", "npm"],
        default="pypi",
        help="Target registry to query (default: pypi)",
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=90,
        dest="max_age_days",
        help="Flag packages first published within this many days as NEWLY_REGISTERED (default: 90)",
    )
    args = parser.parse_args()

    packages = load_packages(args.packages_file)
    if not packages:
        print("No packages found in input file.", file=sys.stderr)
        sys.exit(0)

    has_critical = analyze_and_report(packages, args.ecosystem, args.max_age_days)
    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()