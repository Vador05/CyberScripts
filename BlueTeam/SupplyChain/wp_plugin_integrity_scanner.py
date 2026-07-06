"""
WordPress Plugin Integrity Scanner

Computes SHA256 hashes of installed WordPress plugin files and diffs them
against the official WordPress.org SVN repository to detect unauthorized
modifications.

Usage example:
    python wp_plugin_integrity_scanner.py --plugins-dir /var/www/html/wp-content/plugins
    python wp_plugin_integrity_scanner.py --plugins-dir /var/www/html/wp-content/plugins --plugin akismet
    python wp_plugin_integrity_scanner.py --plugins-dir /var/www/html/wp-content/plugins --output-format full
"""

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def hash_plugin_files(plugin_dir: str) -> dict[str, str]:
    hashes = {}
    for root, _, files in os.walk(plugin_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, plugin_dir).replace(os.sep, "/")
            try:
                h = hashlib.sha256()
                with open(fpath, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                hashes[rel] = h.hexdigest()
            except OSError:
                pass
    return hashes


def get_plugin_version(plugins_dir: str, slug: str) -> str | None:
    main_file = os.path.join(plugins_dir, slug, f"{slug}.php")
    candidates = [main_file]
    try:
        for fname in os.listdir(os.path.join(plugins_dir, slug)):
            if fname.endswith(".php"):
                candidates.append(os.path.join(plugins_dir, slug, fname))
    except OSError:
        return None
    for fpath in candidates:
        try:
            with open(fpath, "r", errors="replace") as f:
                for line in f:
                    low = line.lower()
                    if "version:" in low:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            v = parts[1].strip().strip("'\"")
                            if v and v[0].isdigit():
                                return v
        except OSError:
            continue
    return None


def fetch_official_checksums(slug: str, version: str) -> dict[str, str] | None:
    # URL-encode both slug and version to prevent injection via tampered plugin metadata.
    safe_slug = urllib.parse.quote(slug, safe="")
    safe_version = urllib.parse.quote(version, safe="")
    url = f"https://downloads.wordpress.org/plugin-checksums/{safe_slug}/{safe_version}.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "wp-integrity-scanner/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        files = data.get("files", {})
        return {path: info["sha256"] for path, info in files.items() if "sha256" in info}
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError, KeyError):
        return None


def diff_and_report(slug: str, local: dict[str, str], official: dict[str, str], output_format: str) -> bool:
    added = sorted(k for k in local if k not in official)
    removed = sorted(k for k in official if k not in local)
    modified = sorted(k for k in local if k in official and local[k] != official[k])
    compromised = bool(added or removed or modified)
    status = "MODIFIED" if compromised else "CLEAN"
    print(f"\n[{status}] {slug}")
    if compromised and output_format == "full":
        for f in added:
            print(f"  + ADDED    {f}  ({local[f]})")
        for f in removed:
            print(f"  - REMOVED  {f}  ({official[f]})")
        for f in modified:
            print(f"  ~ TAMPERED {f}  local={local[f]} official={official[f]}")
    elif compromised:
        total = len(added) + len(removed) + len(modified)
        print(f"  {len(added)} added, {len(removed)} removed, {len(modified)} tampered ({total} total issues)")
    return compromised


def resolve_plugin_dir(plugins_dir: str, slug: str) -> str | None:
    """Return the plugin directory only if it resolves within plugins_dir."""
    base = os.path.realpath(plugins_dir)
    target = os.path.realpath(os.path.join(base, slug))
    if target != base and not target.startswith(base + os.sep):
        return None
    return target


def scan_plugin(plugins_dir: str, slug: str, output_format: str) -> str:
    plugin_dir = resolve_plugin_dir(plugins_dir, slug)
    if plugin_dir is None or not os.path.isdir(plugin_dir):
        print(f"\n[UNKNOWN] {slug}  (directory not found or invalid path)")
        return "unknown"
    version = get_plugin_version(plugins_dir, slug)
    if not version:
        print(f"\n[UNKNOWN] {slug}  (could not determine version)")
        return "unknown"
    official = fetch_official_checksums(slug, version)
    if official is None:
        print(f"\n[UNKNOWN] {slug} v{version}  (no checksum manifest available)")
        return "unknown"
    local = hash_plugin_files(plugin_dir)
    compromised = diff_and_report(slug, local, official, output_format)
    return "compromised" if compromised else "clean"


def main():
    parser = argparse.ArgumentParser(description="WordPress Plugin Integrity Scanner")
    parser.add_argument("--plugins-dir", required=True, help="Path to wp-content/plugins directory")
    parser.add_argument("--plugin", help="Single plugin slug to scan")
    parser.add_argument("--output-format", choices=["summary", "full"], default="summary")
    args = parser.parse_args()

    if not os.path.isdir(args.plugins_dir):
        print(f"Error: plugins directory not found: {args.plugins_dir}", file=sys.stderr)
        sys.exit(1)

    slugs = [args.plugin] if args.plugin else sorted(
        e.name for e in os.scandir(args.plugins_dir) if e.is_dir()
    )

    if not slugs:
        print("No plugins found.", file=sys.stderr)
        sys.exit(0)

    counts = {"clean": 0, "compromised": 0, "unknown": 0}
    for slug in slugs:
        result = scan_plugin(args.plugins_dir, slug, args.output_format)
        counts[result] += 1

    print(f"\n{'='*50}")
    print(f"SCAN COMPLETE: {len(slugs)} plugin(s) checked")
    print(f"  CLEAN:      {counts['clean']}")
    print(f"  MODIFIED:   {counts['compromised']}")
    print(f"  UNKNOWN:    {counts['unknown']}")
    if counts["compromised"]:
        sys.exit(2)


if __name__ == "__main__":
    main()