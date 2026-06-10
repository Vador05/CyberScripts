"""
VS Code URI Token Hunter - Detect GitHub OAuth token theft via malicious vscode:// deep links.

Usage:
    python vscode_uri_token_hunter.py auth.log
    python vscode_uri_token_hunter.py auth.log --since 2026-01-01
    python vscode_uri_token_hunter.py auth.log --harden
"""

import argparse
import re
import sys
from datetime import date, datetime
from pathlib import Path

PATTERNS = [
    (re.compile(r'vscode(?:-insiders)?://[^\s]*[?&]code=[A-Za-z0-9_\-]+', re.IGNORECASE), 'HIGH', 'OAuth code param in vscode:// URI'),
    (re.compile(r'vscode(?:-insiders)?://[^\s]*redirect_uri=[^\s&"\']+', re.IGNORECASE), 'HIGH', 'Redirect URI manipulation in vscode:// handler'),
    (re.compile(r'vscode(?:-insiders)?://[^\s]*[?&]state=[A-Za-z0-9_\-]{8,}', re.IGNORECASE), 'MEDIUM', 'State parameter tampering in vscode:// URI'),
    (re.compile(r'vscode(?:-insiders)?://vscode\.github-authentication/did-authenticate[^\s]*', re.IGNORECASE), 'HIGH', 'GitHub auth callback intercepted via vscode:// URI'),
    (re.compile(r'vscode(?:-insiders)?://[^\s]*(token|access_token|bearer)[^\s]*', re.IGNORECASE), 'HIGH', 'Token value exposed in vscode:// URI'),
    (re.compile(r'vscode(?:-insiders)?://[^\s]*github[^\s]*[?&](code|token)=', re.IGNORECASE), 'HIGH', 'GitHub OAuth param in vscode:// deep link'),
    (re.compile(r'vscode(?:-insiders)?://[A-Za-z0-9.\-]+/[^\s]{40,}', re.IGNORECASE), 'MEDIUM', 'Unusually long vscode:// URI path (possible encoded payload)'),
]

TIMESTAMP_RE = re.compile(r'(\d{4}-\d{2}-\d{2})')


def classify_finding(line: str) -> tuple[str, str]:
    for pattern, severity, label in PATTERNS:
        if pattern.search(line):
            return severity, label
    return 'MEDIUM', 'Suspicious vscode:// URI'


def extract_date(line: str) -> date | None:
    m = TIMESTAMP_RE.search(line)
    if m:
        try:
            return datetime.strptime(m.group(1), '%Y-%m-%d').date()
        except ValueError:
            return None
    return None


def scan_log(path: Path, since: date | None):
    try:
        with path.open('r', encoding='utf-8', errors='replace') as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.rstrip('\n')
                if not re.search(r'vscode(?:-insiders)?://', line, re.IGNORECASE):
                    continue
                if since:
                    line_date = extract_date(line)
                    if line_date and line_date < since:
                        continue
                severity, label = classify_finding(line)
                yield lineno, line, severity, label
    except PermissionError:
        sys.exit(f'[ERROR] Permission denied reading {path}')
    except OSError as exc:
        sys.exit(f'[ERROR] Cannot read log file: {exc}')


def print_hardening_guide():
    guide = """
=== VS Code URI Handler OAuth Hardening Guide ===

1. RESTRICT DEEP-LINK PROCESSING
   Register only specific vscode:// paths your extension requires.
   Validate the full URI against an allowlist before processing any
   query parameters. Reject unexpected paths immediately.

2. VALIDATE OAUTH STATE PARAMETERS
   Generate cryptographically random state values (>=128 bits) per
   OAuth flow. Verify state matches before accepting a code= param.
   Discard any callback where state is missing or mismatched.

3. NEVER PASS TOKENS THROUGH URI SCHEMES
   Complete the OAuth code exchange server-side. Store the access token
   in VS Code SecretStorage, not in a URI fragment or query string.
   Log only opaque identifiers, never raw tokens or codes.

4. ENFORCE REDIRECT URI PINNING
   Register a fixed redirect_uri with your OAuth provider. Reject
   any authorization response whose redirect_uri differs from the
   registered value. Do not derive redirect_uri from user input.

5. MONITOR AND ALERT ON ANOMALOUS vscode:// INVOCATIONS
   Deploy this tool in CI and on developer workstations via log
   shipping. Alert on HIGH-severity findings within seconds. Rotate
   any OAuth token that appears in a flagged log line immediately.
"""
    print(guide.strip())


def main():
    parser = argparse.ArgumentParser(
        description='Scan logs for suspicious VS Code URI OAuth token theft patterns.',
        epilog='Example: python vscode_uri_token_hunter.py auth.log --since 2026-01-01',
    )
    parser.add_argument('log_file', nargs='?', help='Path to plain text log file')
    parser.add_argument('--since', metavar='YYYY-MM-DD', help='Filter events on or after this date')
    parser.add_argument('--harden', action='store_true', help='Print developer hardening guide and exit')
    args = parser.parse_args()

    if args.harden:
        print_hardening_guide()
        return

    if not args.log_file:
        parser.error('log_file is required unless --harden is specified')

    since: date | None = None
    if args.since:
        try:
            since = datetime.strptime(args.since, '%Y-%m-%d').date()
        except ValueError:
            sys.exit('[ERROR] --since must be in YYYY-MM-DD format')

    log_path = Path(args.log_file)
    if not log_path.exists():
        sys.exit(f'[ERROR] Log file not found: {log_path}')

    print(f'[*] Scanning: {log_path}' + (f'  (since {since})' if since else ''))
    print()

    total = 0
    high = 0
    for lineno, line, severity, label in scan_log(log_path, since):
        total += 1
        if severity == 'HIGH':
            high += 1
        ts_match = TIMESTAMP_RE.search(line)
        ts = ts_match.group(1) if ts_match else 'unknown-date'
        preview = line[:120] + ('...' if len(line) > 120 else '')
        print(f'[{severity:6}] Line {lineno:>6} | {ts} | {label}')
        print(f'         {preview}')
        print()

    if total == 0:
        print('[OK] No suspicious vscode:// URI patterns detected.')
    else:
        print(f'[SUMMARY] {total} suspicious event(s) found — {high} HIGH severity.')
        print('[!] Review flagged lines before escalation. False positives possible.')
        print('[!] Rotate any OAuth token appearing in flagged output immediately.')


if __name__ == '__main__':
    main()