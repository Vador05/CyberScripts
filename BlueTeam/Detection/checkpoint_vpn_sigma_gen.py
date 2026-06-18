"""
checkpoint_vpn_sigma_gen.py - Check Point VPN Qilin Sigma Rule Generator

Generates Sigma detection rules targeting IKEv1 authentication anomalies
associated with Check Point VPN zero-day exploitation patterns used by
Qilin ransomware for initial access.

Usage:
    python checkpoint_vpn_sigma_gen.py --log-file vpn.log --output-mode rule
    python checkpoint_vpn_sigma_gen.py --log-file vpn.log --output-mode iocs --min-events 3
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime


LOG_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})'
    r'.*?src[=:\s]+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'.*?(?P<action>auth[_-]?fail(?:ure|ed)?|invalid[_-]?cookie|aggressive[_-]?mode|ike[_-]?auth|pre[_-]?auth)',
    re.IGNORECASE
)

REASON_PATTERN = re.compile(
    r'reason[=:\s]+"?(?P<reason>[^",\n]{3,80})"?',
    re.IGNORECASE
)


def parse_vpn_log(log_path):
    events = []
    try:
        with open(log_path, 'r', errors='replace') as fh:
            for lineno, line in enumerate(fh, 1):
                m = LOG_PATTERN.search(line)
                if not m:
                    continue
                reason_m = REASON_PATTERN.search(line)
                events.append({
                    'src_ip': m.group('src_ip'),
                    'action': m.group('action').lower().replace('-', '_'),
                    'reason': reason_m.group('reason').strip() if reason_m else '',
                    'timestamp': m.group('timestamp'),
                    'lineno': lineno,
                })
    except OSError as exc:
        print(f"[ERROR] Cannot read log file: {exc}", file=sys.stderr)
        sys.exit(1)
    return events


def detect_anomalies(events, min_events):
    by_ip = defaultdict(list)
    for ev in events:
        by_ip[ev['src_ip']].append(ev)

    flagged = {}
    for ip, evlist in by_ip.items():
        auth_failures = [e for e in evlist if 'auth' in e['action']]
        aggressive = [e for e in evlist if 'aggressive' in e['action']]
        bad_cookie = [e for e in evlist if 'cookie' in e['action']]

        patterns = []
        if len(auth_failures) >= min_events:
            patterns.append(('repeated_preauth_failure', len(auth_failures), auth_failures))
        if len(aggressive) >= min_events:
            patterns.append(('ikev1_aggressive_mode_probe', len(aggressive), aggressive))
        if len(bad_cookie) >= min_events:
            patterns.append(('invalid_cookie_sequence', len(bad_cookie), bad_cookie))

        if patterns:
            flagged[ip] = patterns

    return flagged


def _sigma_timestamp():
    return datetime.utcnow().strftime('%Y/%m/%d')


def emit_sigma(flagged):
    if not flagged:
        print("# No anomalous patterns detected above threshold.", file=sys.stdout)
        return

    pattern_keywords = {
        'repeated_preauth_failure': ['auth_failure', 'auth_failed', 'pre_auth'],
        'ikev1_aggressive_mode_probe': ['aggressive_mode', 'IKEv1', 'aggressive'],
        'invalid_cookie_sequence': ['invalid_cookie', 'bad_cookie', 'cookie_invalid'],
    }

    seen_patterns = set()
    for ip, patterns in flagged.items():
        for pname, count, evlist in patterns:
            seen_patterns.add(pname)

    for pname in seen_patterns:
        src_ips = sorted(
            ip for ip, pats in flagged.items()
            if any(p[0] == pname for p in pats)
        )
        keywords = pattern_keywords.get(pname, [pname])
        rule_id = f"chkp-vpn-qilin-{pname.replace('_', '-')}"
        title = f"Check Point VPN IKEv1 Anomaly - {pname.replace('_', ' ').title()}"

        ip_condition_lines = '\n'.join(f'            - \'{ip}\'' for ip in src_ips)

        rule = f"""---
title: '{title}'
id: {rule_id}
status: experimental
description: >
    Detects IKEv1 {pname.replace('_', ' ')} patterns on Check Point VPN gateways
    consistent with Qilin ransomware initial-access exploitation (CVE-2024-24919 class).
date: {_sigma_timestamp()}
author: checkpoint_vpn_sigma_gen
references:
    - https://www.checkpoint.com/blog/may-2024-zero-day-advisory/
tags:
    - attack.initial_access
    - attack.t1190
    - attack.t1078
logsource:
    product: checkpoint
    service: vpn
detection:
    keywords:
{chr(10).join(f"        - '{k}'" for k in keywords)}
    src_ip_filter:
        src_ip|contains:
{ip_condition_lines}
    condition: keywords and src_ip_filter
falsepositives:
    - Legacy IKEv1 clients using aggressive mode in mixed environments
    - VPN misconfiguration during migrations
    - Penetration testing activity
level: high
"""
        print(rule)


def emit_iocs(flagged):
    if not flagged:
        print("# No IOCs extracted above threshold.", file=sys.stdout)
        return
    for ip in sorted(flagged.keys()):
        print(ip)


def main():
    parser = argparse.ArgumentParser(
        description='Generate Sigma rules from Check Point VPN logs for Qilin ransomware patterns.'
    )
    parser.add_argument('--log-file', required=True, help='Path to plain-text VPN/gateway log file')
    parser.add_argument('--output-mode', choices=['rule', 'iocs'], default='rule',
                        help='Output mode: "rule" emits Sigma YAML, "iocs" emits indicator list')
    parser.add_argument('--min-events', type=int, default=1,
                        help='Minimum anomaly event count before including a pattern (default: 1)')
    args = parser.parse_args()

    if args.min_events < 1:
        print("[ERROR] --min-events must be >= 1", file=sys.stderr)
        sys.exit(1)

    events = parse_vpn_log(args.log_file)
    if not events:
        print("[WARN] No matching IKEv1 events found in log file.", file=sys.stderr)

    flagged = detect_anomalies(events, args.min_events)

    if args.output_mode == 'rule':
        emit_sigma(flagged)
    else:
        emit_iocs(flagged)


if __name__ == '__main__':
    main()