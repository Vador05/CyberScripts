"""
DShield SIEM Threat Hunt Lab

Parses DShield honeypot log exports and walks practitioners through three
guided threat hunting scenarios with KQL queries for ELK 8.19.15 dashboards.

Usage:
    python dshield_threat_hunt_lab.py sensor.log
    python dshield_threat_hunt_lab.py sensor.log --scenario sweep --top 5
    python dshield_threat_hunt_lab.py sensor.log --scenario brute --top 10
    python dshield_threat_hunt_lab.py sensor.log --scenario exploit --top 10
"""
import argparse, re, sys
from collections import defaultdict
from datetime import datetime, timezone

LOG_RE = re.compile(
    r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\d{10,13})\s+'
    r'(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+(\d+)\s+(\S+)'
)
PAYLOAD_RE = re.compile(r'GET|POST|cmd=|exec|/etc/passwd|union\s+select|eval\(|\.php\?', re.IGNORECASE)
AUTH_PORTS = {22, 23, 3389, 5900}
EXPLOIT_PORTS = {80, 443, 8080, 5060, 1433, 3306}


def parse_dshield_log(path):
    entries = []
    try:
        fh = open(path, encoding='utf-8', errors='replace')
    except OSError as exc:
        sys.exit(f"[ERROR] {exc}")
    with fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#') or re.match(r'(?i)^(date|time|timestamp)', line):
                continue
            m = LOG_RE.search(line)
            if not m:
                continue
            ts_raw, srcip, srcport, dstport, proto = m.groups()
            try:
                ts = (datetime.fromtimestamp(int(ts_raw[:10]), tz=timezone.utc)
                      if ts_raw.isdigit()
                      else datetime.fromisoformat(ts_raw.replace(' ', 'T')))
            except ValueError:
                ts = None
            entries.append({'ts': ts, 'srcip': srcip, 'srcport': int(srcport),
                            'dstport': int(dstport), 'proto': proto, 'raw': line})
    return entries


def run_sweep(entries, top):
    spread = defaultdict(set)
    for e in entries:
        spread[e['srcip']].add(e['dstport'])
    flagged = {ip: p for ip, p in spread.items() if len(p) >= 5}
    ranked = [(ip, (len(p), p)) for ip, p in sorted(flagged.items(), key=lambda x: len(x[1]), reverse=True)[:top]]
    kql = ('index=dshield-* | stats dc(destination.port) as uniq_ports, count as hits by source.ip '
           '| where uniq_ports >= 5 | sort -uniq_ports | head 10')
    return ranked, kql


def run_brute(entries, top):
    hits, ports = defaultdict(int), defaultdict(set)
    for e in entries:
        if e['dstport'] in AUTH_PORTS:
            hits[e['srcip']] += 1
            ports[e['srcip']].add(e['dstport'])
    flagged = {ip: (hits[ip], ports[ip]) for ip in hits if hits[ip] >= 10}
    ranked = sorted(flagged.items(), key=lambda x: x[1][0], reverse=True)[:top]
    kql = ('index=dshield-* destination.port:(22 OR 23 OR 3389 OR 5900) '
           '| stats count as hits, dc(destination.port) as ports by source.ip '
           '| where hits >= 10 | sort -hits | head 10')
    return ranked, kql


def run_exploit(entries, top):
    hits, ports = defaultdict(int), defaultdict(set)
    for e in entries:
        if e['dstport'] in EXPLOIT_PORTS and PAYLOAD_RE.search(e['raw']):
            hits[e['srcip']] += 1
            ports[e['srcip']].add(e['dstport'])
    ranked = [(ip, (cnt, ports[ip])) for ip, cnt in sorted(hits.items(), key=lambda x: x[1], reverse=True)[:top]]
    kql = ('index=dshield-* destination.port:(80 OR 443 OR 8080 OR 5060 OR 1433 OR 3306) '
           'message:("GET" OR "POST" OR "cmd=" OR "eval(" OR "union select") '
           '| stats count as hits, dc(destination.port) as ports by source.ip '
           '| sort -hits | head 10')
    return ranked, kql


SCENARIO_META = {
    'sweep':   ('Port-Sweep Reconnaissance',
                'Source IPs contacting >= 5 unique destination ports signal automated pre-attack surface mapping.',
                'Adversaries probing multiple destination ports from a single source are conducting network reconnaissance.',
                'Top Talkers by Port Spread'),
    'brute':   ('Brute-Force Clustering',
                'Source IPs with >= 10 hits on auth ports 22/23/3389/5900 indicate credential-stuffing campaigns.',
                'Repeated auth-port connections from a single source indicate credential-stuffing or brute-force activity.',
                'Auth Brute Force Summary'),
    'exploit': ('Exploit-Probe Triage',
                'Web/DB/VoIP port connections carrying payload keywords reveal active exploitation attempts.',
                'Connections to exploit-associated ports with inline payload fragments signal active exploitation.',
                'Exploit Probe Triage'),
}


def print_lab_guide(scenario_data, top):
    all_ips, dst_counter, exceeded = set(), defaultdict(int), False
    for step, (name, (ranked, kql)) in enumerate(scenario_data, 1):
        label, logic, hyp, panel = SCENARIO_META[name]
        print(f"\n{'='*70}\n  LAB STEP {step}: {label}\n{'='*70}")
        print(f"\nHypothesis: {hyp}\nDetection:  {logic}\n")
        print(f"{'Rank':<6}{'Source IP':<18}{'Hits':<10}Unique Dst Ports")
        print('-' * 56)
        for rank, (ip, (hit_count, dports)) in enumerate(ranked, 1):
            all_ips.add(ip)
            for p in dports:
                dst_counter[p] += 1
            print(f"{rank:<6}{ip:<18}{hit_count:<10}{len(dports)}")
        if len(ranked) >= top:
            exceeded = True
        print(f"\nKQL (paste into DShield ELK 8.19.15 dashboard):\n