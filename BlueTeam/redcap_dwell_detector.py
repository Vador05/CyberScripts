#!/usr/bin/env python3
"""
RedCAP Long-Dwell Credential Theft Detector

Analyzes plain-text authentication logs for UNC6508-style credential theft
targeting research institutions: slow enumeration, off-hours spikes, credential reuse.

Usage:
    python redcap_dwell_detector.py --log /var/log/auth.log
    python redcap_dwell_detector.py --log auth.log --threshold 3 --hours 23
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta


LOG_PATTERNS = [
    re.compile(
        r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2}).*'
        r'from\s+(?P<ip>[\d.a-fA-F:]+).*(?:for(?: invalid user)?\s+(?P<user>\S+))?.*'
        r'(?P<result>Failed|Accepted|failure|success)',
        re.IGNORECASE
    ),
    re.compile(
        r'(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}).*?'
        r'(?P<ip>[\d.a-fA-F:]+).*?'
        r'(?:user[=:\s]+(?P<user>\S+))?.*?'
        r'(?P<result>failed|success|invalid|accepted)',
        re.IGNORECASE
    ),
    re.compile(
        r'(?P<ip>[\d.a-fA-F:]+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\].*?'
        r'(?:POST|GET)\s+\S*(?:login|auth|signin)\S*.*?\s(?P<code>\d{3})',
        re.IGNORECASE
    ),
]

CURRENT_YEAR = datetime.now().year


def parse_timestamp(m):
    if 'ts' in m.groupdict() and m.group('ts'):
        raw = m.group('ts').replace('T', ' ').strip()
        # Apache-style timestamps carry a trailing UTC offset (e.g. "-0700");
        # split it off instead of blindly truncating to 19 chars, which
        # previously cut into the seconds field for the 20-char Apache format.
        base = raw.split(' ')[0] if '/' in raw else raw[:19]
        for fmt in ('%Y-%m-%d %H:%M:%S', '%d/%b/%Y:%H:%M:%S'):
            try:
                return datetime.strptime(base, fmt)
            except ValueError:
                pass
    if 'month' in m.groupdict() and m.group('month'):
        try:
            ts_str = f"{m.group('month')} {m.group('day')} {CURRENT_YEAR} {m.group('time')}"
            return datetime.strptime(ts_str, '%b %d %Y %H:%M:%S')
        except ValueError:
            pass
    return None


def parse_log(path):
    events = []
    try:
        with open(path, 'r', errors='replace') as fh:
            for line in fh:
                for pat in LOG_PATTERNS:
                    m = pat.search(line)
                    if not m:
                        continue
                    ts = parse_timestamp(m)
                    if not ts:
                        continue
                    ip = m.group('ip') if 'ip' in m.groupdict() else None
                    user = (m.group('user') if 'user' in m.groupdict() and m.group('user') else 'unknown')
                    if 'result' in m.groupdict():
                        raw = (m.group('result') or '').lower()
                        success = raw in ('accepted', 'success')
                    elif 'code' in m.groupdict():
                        code = int(m.group('code') or 0)
                        success = 200 <= code < 300
                    else:
                        continue
                    if ip:
                        events.append({'ts': ts, 'ip': ip, 'user': user, 'success': success})
                    break
    except OSError as e:
        print(f"[ERROR] Cannot read log file: {e}", file=sys.stderr)
        sys.exit(1)
    return events


def is_off_hours(ts, off_start):
    h = ts.hour
    off_end = (off_start + 8) % 24
    if off_start > off_end:
        return h >= off_start or h < off_end
    return off_start <= h < off_end


def analyze_ips(events, threshold, off_hours_start):
    buckets = defaultdict(lambda: {'events': [], 'users': set(), 'failures': 0, 'successes': 0, 'off_hours': 0})
    for ev in events:
        b = buckets[ev['ip']]
        b['events'].append(ev['ts'])
        b['users'].add(ev['user'])
        if ev['success']:
            b['successes'] += 1
        else:
            b['failures'] += 1
        if is_off_hours(ev['ts'], off_hours_start):
            b['off_hours'] += 1

    findings = []
    for ip, data in buckets.items():
        if data['failures'] < threshold:
            continue
        timestamps = sorted(data['events'])
        dwell = timestamps[-1] - timestamps[0]
        total = data['failures'] + data['successes']
        off_ratio = data['off_hours'] / total if total else 0
        unique_users = len(data['users'])
        slow_burn = dwell > timedelta(hours=24) and data['failures'] >= threshold
        techniques = ['T1110.003']
        if data['successes'] > 0:
            techniques.append('T1078')
        if unique_users > 5:
            techniques.append('T1136.001')

        score = 0
        score += min(data['failures'] // threshold, 3)
        score += 2 if slow_burn else 0
        score += 2 if off_ratio > 0.6 else (1 if off_ratio > 0.3 else 0)
        score += 1 if data['successes'] > 0 else 0
        score += 1 if unique_users > 3 else 0

        severity = 'LOW' if score <= 2 else 'MED' if score <= 4 else 'HIGH' if score <= 6 else 'CRITICAL'

        findings.append({
            'ip': ip,
            'failures': data['failures'],
            'successes': data['successes'],
            'unique_users': unique_users,
            'dwell': dwell,
            'first_seen': timestamps[0],
            'last_seen': timestamps[-1],
            'off_hours_ratio': off_ratio,
            'slow_burn': slow_burn,
            'techniques': techniques,
            'severity': severity,
            'score': score,
        })

    findings.sort(key=lambda x: x['score'], reverse=True)
    return findings


def render_report(findings, threshold, off_hours_start):
    off_end = (off_hours_start + 8) % 24
    print("=" * 72)
    print("  RedCAP Long-Dwell Credential Theft Detector — Alert Report")
    print(f"  Off-hours window: {off_hours_start:02d}:00–{off_end:02d}:00 | Fail threshold: {threshold}")
    print("=" * 72)
    if not findings:
        print("  No suspicious IPs detected above threshold.")
        return

    sev_order = ['CRITICAL', 'HIGH', 'MED', 'LOW']
    for sev in sev_order:
        group = [f for f in findings if f['severity'] == sev]
        if not group:
            continue
        print(f"\n[{sev}] {'─' * 60}")
        for f in group:
            dwell_h = int(f['dwell'].total_seconds() // 3600)
            print(f"  IP:           {f['ip']}")
            print(f"  Dwell window: {f['first_seen'].strftime('%Y-%m-%d %H:%M')} → "
                  f"{f['last_seen'].strftime('%Y-%m-%d %H:%M')} ({dwell_h}h)")
            print(f"  Failures:     {f['failures']}   Successes: {f['successes']}   "
                  f"Unique users targeted: {f['unique_users']}")
            print(f"  Off-hours:    {f['off_hours_ratio']:.0%}   Slow-burn: {'YES' if f['slow_burn'] else 'no'}")
            print(f"  ATT&CK:       {', '.join(f['techniques'])}")
            actions = []
            if f['successes'] > 0:
                actions.append("Block IP; audit authenticated sessions for lateral movement")
            if f['slow_burn']:
                actions.append("Correlate with VPN/proxy logs for campaign infrastructure")
            if f['unique_users'] > 5:
                actions.append("Check credential-reuse across institutional SSO/REDCap portals")
            if not actions:
                actions.append("Monitor; increase log verbosity for this source")
            print(f"  Triage:       {'; '.join(actions)}")
            print()

    print(f"  Total flagged IPs: {len(findings)}")
    print("=" * 72)


def main():
    parser = argparse.ArgumentParser(
        description='Detect UNC6508-style long-dwell credential theft in auth logs.'
    )
    parser.add_argument('--log', required=True, help='Path to plain-text auth log file')
    parser.add_argument('--threshold', type=int, default=5, help='Min failed logins to flag an IP (default: 5)')
    parser.add_argument('--hours', type=int, default=22, help='Off-hours start in 24h format (default: 22)')
    args = parser.parse_args()

    if not 0 <= args.hours <= 23:
        print("[ERROR] --hours must be 0–23", file=sys.stderr)
        sys.exit(1)
    if args.threshold < 1:
        print("[ERROR] --threshold must be >= 1", file=sys.stderr)
        sys.exit(1)

    events = parse_log(args.log)
    if not events:
        print("[WARN] No parseable log entries found. Check log format.", file=sys.stderr)
    findings = analyze_ips(events, args.threshold, args.hours)
    render_report(findings, args.threshold, args.hours)


if __name__ == '__main__':
    main()
