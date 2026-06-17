"""
CVE Triage Scanner - Parse CVE feed logs, score exploitability, emit Sigma rules.

Usage:
    python cve_triage_scanner.py feed.txt
    python cve_triage_scanner.py feed.txt --threshold 8 --format json
    echo "CVE-2024-1234 CVSS:9.8 RCE via buffer overflow, PoC available" | python cve_triage_scanner.py -

Feed format (one entry per line):
    CVE-2024-1234 CVSS:9.8 Remote code execution via crafted packet, actively exploited
    CVE-2024-5678 CVSS:6.5 SQL injection in login form, auth bypass possible
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone


KEYWORD_WEIGHTS = {
    "rce": 2.0, "remote code execution": 2.0, "code execution": 1.8,
    "auth bypass": 1.5, "authentication bypass": 1.5, "unauthenticated": 1.2,
    "poc": 1.3, "proof of concept": 1.3, "exploit available": 1.4,
    "actively exploited": 2.0, "in the wild": 1.8, "zero-day": 1.9, "0-day": 1.9,
    "privilege escalation": 1.2, "privesc": 1.2, "buffer overflow": 1.1,
    "heap overflow": 1.1, "use after free": 1.1, "sql injection": 0.9,
    "xss": 0.6, "csrf": 0.5, "denial of service": 0.4, "dos": 0.4,
}

CVE_RE = re.compile(r'(CVE-\d{4}-\d+)', re.IGNORECASE)
CVSS_RE = re.compile(r'CVSS[v:/_]?\s*(\d+(?:\.\d+)?)', re.IGNORECASE)
COMPONENT_RE = re.compile(r'\bin\s+([\w\s./]+?)(?:\s+via|\s+allows|\s+could|\s*,|\s*\.|\s*$)', re.IGNORECASE)


def parse_feed(path):
    entries = []
    source = sys.stdin if path == '-' else None
    try:
        fh = source or open(path, 'r', encoding='utf-8', errors='replace')
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            cve_match = CVE_RE.search(line)
            if not cve_match:
                continue
            cvss_match = CVSS_RE.search(line)
            comp_match = COMPONENT_RE.search(line)
            entries.append({
                'cve_id': cve_match.group(1).upper(),
                'cvss': float(cvss_match.group(1)) if cvss_match else 0.0,
                'description': line,
                'component': comp_match.group(1).strip() if comp_match else 'unknown',
                'line': lineno,
            })
        if fh is not source:
            fh.close()
    except OSError as e:
        print(f"ERROR: Cannot read feed '{path}': {e}", file=sys.stderr)
        sys.exit(1)
    return entries


def score_exploitability(entry):
    base = min(entry['cvss'], 10.0)
    desc_lower = entry['description'].lower()
    keyword_bonus = 0.0
    for kw, weight in KEYWORD_WEIGHTS.items():
        if kw in desc_lower:
            keyword_bonus += weight
    raw = base * 0.6 + min(keyword_bonus, 6.0) * 0.4 * (10.0 / 6.0)
    return round(min(raw, 10.0), 1)


def _infer_category(description):
    d = description.lower()
    if any(k in d for k in ('network', 'remote', 'http', 'tcp', 'udp', 'packet', 'request')):
        return 'network'
    if any(k in d for k in ('file', 'path', 'directory', 'upload', 'write')):
        return 'file'
    return 'process'


def emit_sigma(entry, score):
    cve = entry['cve_id']
    component = re.sub(r'[^\w\s.-]', '', entry['component'])[:64]
    category = _infer_category(entry['description'])
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    detection_map = {
        'network': "    selection:\n        dst_port|exists: true\n        event_type: 'network_connection'\n    condition: selection",
        'file': "    selection:\n        TargetFilename|contains: '{comp}'\n    condition: selection".format(comp=component[:32]),
        'process': "    selection:\n        Image|endswith: '.exe'\n        CommandLine|contains: '{comp}'\n    condition: selection".format(comp=component[:32]),
    }
    return (
        f"# Sigma Rule — {cve} (score {score}/10)\n"
        f"title: Potential {cve} Exploitation — {component}\n"
        f"id: {cve.lower().replace('-', '_')}_exploit\n"
        f"status: experimental\n"
        f"description: >\n"
        f"    Heuristic detection for {cve}. Review before SIEM deployment.\n"
        f"references:\n"
        f"    - https://nvd.nist.gov/vuln/detail/{cve}\n"
        f"date: {ts}\n"
        f"tags:\n"
        f"    - attack.initial_access\n"
        f"    - cve.{cve.lower().replace('-', '_')}\n"
        f"logsource:\n"
        f"    category: {category}\n"
        f"detection:\n"
        f"{detection_map[category]}\n"
        f"falsepositives:\n"
        f"    - Legitimate use of affected component\n"
        f"level: {'critical' if score >= 9 else 'high'}\n"
    )


def main():
    parser = argparse.ArgumentParser(description='CVE Triage Scanner — score exploitability and emit Sigma rules.')
    parser.add_argument('feed_file', help='Path to plain-text CVE feed log, or - for stdin')
    parser.add_argument('--threshold', type=float, default=7.0, help='Min score to emit Sigma rule (default 7)')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain', dest='fmt')
    args = parser.parse_args()

    entries = parse_feed(args.feed_file)
    if not entries:
        print("No CVE entries found in feed.", file=sys.stderr)
        sys.exit(0)

    results, sigma_blocks = [], []
    for e in entries:
        score = score_exploitability(e)
        results.append({'cve_id': e['cve_id'], 'score': score, 'cvss': e['cvss'], 'component': e['component'], 'description': e['description']})
        if score >= args.threshold:
            sigma_blocks.append(emit_sigma(e, score))

    high_count = sum(1 for r in results if r['score'] >= args.threshold)

    if args.fmt == 'json':
        print(json.dumps({'triage': results, 'sigma_rules': sigma_blocks,
                          'summary': {'total': len(results), 'high_severity': high_count, 'rules_emitted': len(sigma_blocks)}}, indent=2))
        return

    print(f"{'CVE ID':<20} {'Score':>6} {'CVSS':>6}  Component")
    print('-' * 70)
    for r in sorted(results, key=lambda x: x['score'], reverse=True):
        flag = ' !' if r['score'] >= args.threshold else ''
        print(f"{r['cve_id']:<20} {r['score']:>6.1f} {r['cvss']:>6.1f}  {r['component'][:36]}{flag}")

    if sigma_blocks:
        print('\n' + '=' * 70)
        print('SIGMA DETECTION RULES (draft — human review required before deployment)')
        print('=' * 70)
        for block in sigma_blocks:
            print('\n' + block)

    print(f"\nSummary: {len(results)} CVEs parsed | {high_count} high-severity | {len(sigma_blocks)} Sigma rules emitted")


if __name__ == '__main__':
    main()