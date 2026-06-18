"""
AI Recon Pattern Detector - Analyzes auth/syslog entries for LLM-driven lateral movement signatures.

Usage:
    python ai_recon_detector.py --log /var/log/auth.log --window 120 --threshold 0.5
    python ai_recon_detector.py --log /var/log/syslog --window 60 --threshold 0.7

Output:
    ALERT | 0.85 | 192.168.1.10 | sequential_sweep | 14
    ALERT | 0.72 | 10.0.0.5 | recon_to_exploit | 8
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone


TIMESTAMP_PATTERNS = [
    re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'),
    re.compile(r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})'),
]
IP_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
PORT_RE = re.compile(r'(?:port|dport|sport)\s+(\d+)', re.IGNORECASE)

RECON_KEYWORDS = re.compile(
    r'\b(scan|probe|enum|nmap|masscan|discover|ping|connect|ssh|ftp|telnet|banner|version)\b',
    re.IGNORECASE
)
EXPLOIT_KEYWORDS = re.compile(
    r'\b(exploit|shell|exec|payload|overflow|inject|brute|attack|pwn|root|privilege|escalat)\b',
    re.IGNORECASE
)
FAIL_KEYWORDS = re.compile(
    r'\b(fail|invalid|refused|denied|error|rejected|incorrect|no route)\b',
    re.IGNORECASE
)


def parse_timestamp(line):
    for pat in TIMESTAMP_PATTERNS:
        m = pat.search(line)
        if m:
            ts_str = m.group(1)
            for fmt in ('%Y-%m-%dT%H:%M:%S', '%b %d %H:%M:%S', '%b  %d %H:%M:%S'):
                try:
                    dt = datetime.strptime(ts_str, fmt)
                    if dt.year == 1900:
                        dt = dt.replace(year=datetime.now().year)
                    return dt.replace(tzinfo=timezone.utc).timestamp()
                except ValueError:
                    continue
    return None


def parse_events(log_path):
    events = []
    try:
        with open(log_path, 'r', errors='replace') as f:
            for line in f:
                line = line.rstrip()
                ts = parse_timestamp(line)
                if ts is None:
                    continue
                ips = IP_RE.findall(line)
                if not ips:
                    continue
                src_ip = ips[0]
                port_m = PORT_RE.search(line)
                port = int(port_m.group(1)) if port_m else None
                action = 'recon' if RECON_KEYWORDS.search(line) else \
                         'exploit' if EXPLOIT_KEYWORDS.search(line) else \
                         'fail' if FAIL_KEYWORDS.search(line) else 'other'
                dest_ips = ips[1:] if len(ips) > 1 else []
                events.append({'ts': ts, 'src_ip': src_ip, 'action': action,
                                'port': port, 'dest_ips': dest_ips, 'raw': line})
    except OSError as e:
        print(f"ERROR: Cannot read log file: {e}", file=sys.stderr)
        sys.exit(1)
    return sorted(events, key=lambda x: x['ts'])


def score_sequential_ordering(events):
    dest_ips_all = []
    ports_all = []
    for e in events:
        dest_ips_all.extend(e['dest_ips'])
        if e['port']:
            ports_all.append(e['port'])

    score = 0.0
    if len(dest_ips_all) >= 3:
        try:
            octets = [int(ip.split('.')[3]) for ip in dest_ips_all if ip.count('.') == 3]
            diffs = [octets[i+1] - octets[i] for i in range(len(octets)-1)]
            if diffs and all(d == 1 for d in diffs):
                score += 0.5
            elif diffs and len(set(diffs)) == 1:
                score += 0.3
        except (ValueError, IndexError):
            pass

    if len(ports_all) >= 4:
        diffs = [ports_all[i+1] - ports_all[i] for i in range(len(ports_all)-1)]
        if diffs and all(d > 0 for d in diffs):
            score += 0.2
        sorted_ports = sorted(ports_all)
        common_recon = {21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080}
        if len(common_recon & set(ports_all)) >= 4:
            score += 0.3

    return min(score, 1.0)


def score_recon_to_exploit(events):
    actions = [e['action'] for e in events]
    recon_count = actions.count('recon')
    exploit_count = actions.count('exploit')
    fail_count = actions.count('fail')

    if recon_count == 0 and exploit_count == 0:
        return 0.0

    score = 0.0
    recon_indices = [i for i, a in enumerate(actions) if a == 'recon']
    exploit_indices = [i for i, a in enumerate(actions) if a == 'exploit']

    if recon_indices and exploit_indices:
        if max(recon_indices) < max(exploit_indices):
            score += 0.5

    if recon_count >= 3:
        score += 0.2
    if fail_count >= 5:
        score += 0.2

    total = len(actions)
    if total >= 5 and (recon_count + exploit_count) / total > 0.6:
        score += 0.1

    return min(score, 1.0)


def detect_ai_patterns(events, window, threshold):
    alerts = []
    by_src = defaultdict(list)
    for e in events:
        by_src[e['src_ip']].append(e)

    for src_ip, src_events in by_src.items():
        src_events.sort(key=lambda x: x['ts'])
        i = 0
        while i < len(src_events):
            window_events = [src_events[i]]
            j = i + 1
            while j < len(src_events) and src_events[j]['ts'] - src_events[i]['ts'] <= window:
                window_events.append(src_events[j])
                j += 1

            if len(window_events) < 3:
                i += 1
                continue

            seq_score = score_sequential_ordering(window_events)
            rte_score = score_recon_to_exploit(window_events)

            if seq_score >= threshold:
                alerts.append({'ts': src_events[i]['ts'], 'src_ip': src_ip,
                                'score': round(seq_score, 2), 'pattern': 'sequential_sweep',
                                'count': len(window_events)})
            if rte_score >= threshold:
                alerts.append({'ts': src_events[i]['ts'], 'src_ip': src_ip,
                                'score': round(rte_score, 2), 'pattern': 'recon_to_exploit',
                                'count': len(window_events)})
            i = j if j > i + 1 else i + 1

    return alerts


def main():
    parser = argparse.ArgumentParser(description='Detect AI-driven recon patterns in auth/syslog files.')
    parser.add_argument('--log', required=True, help='Path to syslog or auth.log file')
    parser.add_argument('--window', type=int, default=60, help='Correlation time window in seconds (default: 60)')
    parser.add_argument('--threshold', type=float, default=0.6, help='Minimum score to emit alert (default: 0.6)')
    args = parser.parse_args()

    if not 0.0 <= args.threshold <= 1.0:
        print("ERROR: --threshold must be between 0.0 and 1.0", file=sys.stderr)
        sys.exit(1)
    if args.window < 1:
        print("ERROR: --window must be a positive integer", file=sys.stderr)
        sys.exit(1)

    events = parse_events(args.log)
    if not events:
        print("INFO: No parseable events found in log file.", file=sys.stderr)
        sys.exit(0)

    alerts = detect_ai_patterns(events, args.window, args.threshold)
    for alert in sorted(alerts, key=lambda x: x['ts']):
        ts_str = datetime.fromtimestamp(alert['ts'], tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        print(f"ALERT | {alert['score']:.2f} | {alert['src_ip']} | {alert['pattern']} | {alert['count']}")


if __name__ == '__main__':
    main()