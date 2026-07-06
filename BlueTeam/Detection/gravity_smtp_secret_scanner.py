"""
Gravity SMTP Secret Exposure Scanner

Probes WordPress installations for unauthenticated API key and OAuth token
exposure through known Gravity SMTP REST endpoints.

Usage:
    python gravity_smtp_secret_scanner.py https://example.com
    python gravity_smtp_secret_scanner.py https://example.com --timeout 10 --verbose
"""

import argparse
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone


GRAVITY_SMTP_ENDPOINTS = [
    "/wp-json/gf-smtp/v1/settings",
    "/wp-json/gf-smtp/v1/config",
    "/wp-json/gf-smtp/v1/oauth/token",
    "/wp-json/gf-smtp/v1/credentials",
    "/wp-json/gf-smtp/v1/providers",
    "/wp-json/gravitysmtp/v1/settings",
    "/wp-json/gravitysmtp/v1/config",
    "/wp-json/gravitysmtp/v1/oauth/token",
    "/wp-json/gravitysmtp/v1/credentials",
    "/wp-json/gravitysmtp/v1/providers",
    "/?rest_route=/gf-smtp/v1/settings",
    "/?rest_route=/gf-smtp/v1/config",
    "/?rest_route=/gf-smtp/v1/credentials",
    "/?rest_route=/gravitysmtp/v1/settings",
    "/?rest_route=/gravitysmtp/v1/credentials",
]

SECRET_PATTERNS = [
    ("SendGrid API Key", re.compile(r'SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}')),
    ("Mailgun API Key", re.compile(r'key-[a-f0-9]{32}')),
    ("OAuth Bearer Token", re.compile(r'"access_token"\s*:\s*"([A-Za-z0-9_\-\.]{20,})"')),
    ("OAuth Refresh Token", re.compile(r'"refresh_token"\s*:\s*"([A-Za-z0-9_\-\.]{20,})"')),
    ("Generic API Key", re.compile(r'"api_key"\s*:\s*"([A-Za-z0-9_\-]{16,})"')),
    ("Generic API Secret", re.compile(r'"api_secret"\s*:\s*"([A-Za-z0-9_\-]{16,})"')),
    ("SMTP Password", re.compile(r'"(?:smtp_pass|smtp_password|password)"\s*:\s*"([^"]{6,})"')),
    ("Client Secret", re.compile(r'"client_secret"\s*:\s*"([A-Za-z0-9_\-\.]{16,})"')),
    ("Private Key Fragment", re.compile(r'"private_key"\s*:\s*"([^"]{16,})"')),
]


def probe_endpoints(base_url, timeout):
    base_url = base_url.rstrip("/")
    results = []
    for path in GRAVITY_SMTP_ENDPOINTS:
        url = base_url + path
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (SecurityAudit)"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(65536).decode("utf-8", errors="replace")
                results.append((path, resp.status, body))
        except urllib.error.HTTPError as exc:
            results.append((path, exc.code, ""))
        except Exception as exc:
            results.append((path, None, str(exc)))
    return results


def extract_secrets(body):
    found = []
    for secret_type, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(body):
            raw = match.group(1) if match.lastindex else match.group(0)
            redacted = raw[:8] + "..." if len(raw) > 8 else raw + "..."
            found.append((secret_type, redacted))
    return found


def report(probe_results, verbose):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    vuln_count = 0

    for path, status, body in probe_results:
        if status is None:
            print(f"[{ts}] ERROR  {path} — {body}")
            continue

        if status != 200:
            print(f"[{ts}] SAFE   {path} — HTTP {status}")
            continue

        secrets = extract_secrets(body)
        if not secrets:
            print(f"[{ts}] SAFE   {path} — HTTP {status}, no secrets matched")
            if verbose:
                print(f"         BODY: {body[:200]}")
            continue

        for secret_type, redacted in secrets:
            print(f"[{ts}] VULN   {path} — {secret_type}: {redacted}")
            vuln_count += 1

        if verbose:
            print(f"         BODY: {body[:200]}")

    ts_final = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts_final}] SUMMARY — {vuln_count} exposed credential(s) detected")

    if vuln_count > 0:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Detect unauthenticated Gravity SMTP credential exposure on WordPress sites."
    )
    parser.add_argument("target_url", help="Base WordPress URL to scan (e.g. https://example.com)")
    parser.add_argument("--timeout", type=float, default=5.0, help="HTTP request timeout in seconds (default: 5)")
    parser.add_argument("--verbose", action="store_true", help="Print raw response bodies alongside findings")
    args = parser.parse_args()

    if not args.target_url.startswith(("http://", "https://")):
        parser.error("target_url must begin with http:// or https://")

    print(f"[{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}] Scanning {args.target_url} — {len(GRAVITY_SMTP_ENDPOINTS)} endpoints")

    results = probe_endpoints(args.target_url, args.timeout)
    report(results, args.verbose)


if __name__ == "__main__":
    main()