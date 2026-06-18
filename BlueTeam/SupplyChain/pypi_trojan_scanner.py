"""
PyPI Trojan Scanner - Detect credential-harvesting stubs in PyPI wheels.

Usage:
    python pypi_trojan_scanner.py requests
    python pypi_trojan_scanner.py requests --version 2.28.0
    python pypi_trojan_scanner.py requests --strict
"""

import argparse
import json
import re
import sys
import tempfile
import urllib.request
import zipfile

PATTERNS = {
    "env_var_exfil": re.compile(
        r'os\.environ\.get\s*\(\s*["\'](?:AWS|SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE)[^"\']*["\']',
        re.IGNORECASE,
    ),
    "http_post_secrets": re.compile(
        r'(?:requests|urllib).*\.post\s*\(.*(?:password|secret|token|credential)',
        re.IGNORECASE,
    ),
    "discord_webhook": re.compile(
        r'discord(?:app)?\.com/api/webhooks',
        re.IGNORECASE,
    ),
    "telegram_webhook": re.compile(
        r'api\.telegram\.org/bot',
        re.IGNORECASE,
    ),
    "base64_url_stub": re.compile(
        r'base64\.b64decode\s*\(\s*["\'][A-Za-z0-9+/]{20,}={0,2}["\']',
    ),
    "subprocess_curl_wget": re.compile(
        r'subprocess.*(?:curl|wget).*(?:http|ftp)',
        re.IGNORECASE,
    ),
    "encoded_exec": re.compile(
        r'exec\s*\(\s*(?:base64|codecs|zlib)',
        re.IGNORECASE,
    ),
    "socket_exfil": re.compile(
        r'socket\.connect\s*\(\s*\(.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    ),
    "pastebin_upload": re.compile(
        r'pastebin\.com|paste\.ee|hastebin\.com',
        re.IGNORECASE,
    ),
    "ngrok_tunnel": re.compile(
        r'ngrok\.io|\.ngrok-free\.app',
        re.IGNORECASE,
    ),
}


def fetch_wheel(pkg: str, ver: str | None) -> dict[str, str]:
    api_url = f"https://pypi.org/pypi/{pkg}/json"
    try:
        with urllib.request.urlopen(api_url, timeout=15) as resp:
            meta = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"PyPI API error for '{pkg}': {e.code} {e.reason}")
    except Exception as e:
        sys.exit(f"Failed to reach PyPI: {e}")

    if ver is None:
        ver = meta["info"]["version"]

    releases = meta.get("releases", {})
    if ver not in releases:
        sys.exit(f"Version '{ver}' not found for package '{pkg}'")

    wheel_asset = next(
        (a for a in releases[ver] if a["filename"].endswith(".whl")), None
    )
    if wheel_asset is None:
        sys.exit(f"No wheel (.whl) found for {pkg}=={ver}")

    url = wheel_asset["url"]
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = resp.read()
    except Exception as e:
        sys.exit(f"Failed to download wheel: {e}")

    sources: dict[str, str] = {}
    with tempfile.NamedTemporaryFile(suffix=".whl", delete=True) as tmp:
        tmp.write(data)
        tmp.flush()
        try:
            with zipfile.ZipFile(tmp.name) as zf:
                for name in zf.namelist():
                    if name.endswith(".py"):
                        try:
                            sources[name] = zf.read(name).decode("utf-8", errors="replace")
                        except Exception:
                            pass
        except zipfile.BadZipFile as e:
            sys.exit(f"Downloaded file is not a valid zip/wheel: {e}")

    return sources


def scan_sources(sources: dict[str, str]) -> list[tuple[str, int, str, str]]:
    findings: list[tuple[str, int, str, str]] = []
    for filename, content in sources.items():
        for lineno, line in enumerate(content.splitlines(), start=1):
            for label, pattern in PATTERNS.items():
                if pattern.search(line):
                    snippet = line.strip()[:120]
                    findings.append((filename, lineno, label, snippet))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan a PyPI wheel for credential-harvesting trojan patterns.",
        epilog="Example: pypi_trojan_scanner.py requests --version 2.28.0 --strict",
    )
    parser.add_argument("package_name", help="PyPI package name to inspect")
    parser.add_argument("--version", metavar="VER", help="Pinned version to fetch (default: latest)")
    parser.add_argument("--strict", action="store_true", help="Exit with code 1 if any findings reported")
    args = parser.parse_args()

    print(f"Fetching {args.package_name}" + (f"=={args.version}" if args.version else " (latest)") + " ...")
    sources = fetch_wheel(args.package_name, args.version)
    print(f"Extracted {len(sources)} Python source file(s). Scanning...\n")

    findings = scan_sources(sources)

    if not findings:
        print("Verdict: CLEAN — no suspicious patterns detected.")
        sys.exit(0)

    col_w = max(len(f[0]) for f in findings)
    lbl_w = max(len(f[2]) for f in findings)
    for filename, lineno, label, snippet in findings:
        print(f"  {filename:<{col_w}}  line {lineno:>5}  [{label:<{lbl_w}}]  {snippet}")

    print(f"\nVerdict: SUSPICIOUS — {len(findings)} finding(s) detected.")
    if args.strict:
        sys.exit(1)


if __name__ == "__main__":
    main()