"""
PamStealer macOS PAM Abuse & AppleScript Detector

Scans macOS unified log exports for PamStealer campaign indicators across three
kill-chain stages: PAM module staging, privileged credential interception, and
AppleScript-based execution or exfiltration.

Usage:
    python pamstealer_macos_detector.py /var/log/unified_export.log
    python pamstealer_macos_detector.py /var/log/unified_export.log --severity high
    python pamstealer_macos_detector.py /var/log/unified_export.log --iocs extra_iocs.json --severity medium

Example log export command:
    log show --style syslog --predicate 'subsystem == "com.apple.pam"' > unified_export.log
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

LOG_RE = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>[^\[]+)\[(?P<pid>\d+)\]:\s+'
    r'(?P<message>.+)$'
)

SYSTEM_PAM_PATH = '/usr/lib/pam/'
SYSTEM_PAM_D = '/etc/pam.d/'
KNOWN_AUTH_BINARIES = {'loginwindow', 'screensaverlauncher', 'securityd', 'opendirectoryd', 'authorizationhost'}
SYSTEM_BINARY_NAMES = {'loginwindow', 'securityd', 'launchd', 'opendirectoryd', 'authorizationhost', 'sshd', 'sudo'}
WRITABLE_PATHS = ['/tmp/', '/var/tmp/', '/Library/Application Support/', '/Users/']
SEVERITY_ORDER = {'low': 0, 'medium': 1, 'high': 2}

BUNDLED_IOCS = {
    'suspicious_pam_modules': ['pam_stealer', 'pam_evil', 'pam_harvest', 'pam_exfil', 'pam_keylog'],
    'unsigned_binary_fragments': ['/tmp/', '/var/tmp/', '/.hidden/', '/Library/Application Support/'],
    'bad_osascript_parents': ['curl', 'python', 'python3', 'ruby', 'perl', 'bash', 'sh', 'zsh', 'nc', 'ncat'],
}

RULES = [
    {
        'stage': 'PamStaging',
        'technique': 'T1556.002',
        'severity': 'high',
        'name': 'PamModuleOutsideSystemPath',
        'fn': lambda e, iocs: (
            ('pam_' in e['message'] or '/etc/pam.d/' in e['message']) and
            SYSTEM_PAM_PATH not in e['message'] and
            not any(m in e['message'] for m in ['/usr/lib/pam/pam_', '/System/Library/'])
        ),
    },
    {
        'stage': 'PamStaging',
        'technique': 'T1556.002',
        'severity': 'high',
        'name': 'SuspiciousPamModuleName',
        'fn': lambda e, iocs: any(m in e['message'] for m in iocs['suspicious_pam_modules']),
    },
    {
        'stage': 'PamStaging',
        'technique': 'T1556.002',
        'severity': 'high',
        'name': 'PamServiceFileModification',
        'fn': lambda e, iocs: (
            SYSTEM_PAM_D in e['message'] and
            ('write' in e['message'].lower() or 'open' in e['message'].lower() or 'modify' in e['message'].lower()) and
            any(frag in e['message'] for frag in iocs['unsigned_binary_fragments'])
        ),
    },
    {
        'stage': 'CredentialInterception',
        'technique': 'T1556.002',
        'severity': 'high',
        'name': 'AuthFromNonSystemProcess',
        'fn': lambda e, iocs: (
            'pam_sm_authenticate' in e['message'] and
            e['process'].strip() not in KNOWN_AUTH_BINARIES
        ),
    },
    {
        'stage': 'CredentialInterception',
        'technique': 'T1556.002',
        'severity': 'high',
        'name': 'NonSystemModuleInAuthStack',
        'fn': lambda e, iocs: (
            ('pam_sm_authenticate' in e['message'] or 'pam_authenticate' in e['message']) and
            SYSTEM_PAM_PATH not in e['message'] and
            'pam_' in e['message']
        ),
    },
    {
        'stage': 'AppleScriptExec',
        'technique': 'T1059.002',
        'severity': 'medium',
        'name': 'CompiledScptFromWritablePath',
        'fn': lambda e, iocs: (
            e['process'].strip() in ('osascript', 'osacompile') and
            '.scpt' in e['message'] and
            any(p in e['message'] for p in WRITABLE_PATHS)
        ),
    },
    {
        'stage': 'AppleScriptExec',
        'technique': 'T1036.005',
        'severity': 'high',
        'name': 'OsascriptFromSuspiciousParent',
        'fn': lambda e, iocs: (
            e['process'].strip() in ('osascript', 'osacompile') and
            any(b in e['message'] for b in iocs['bad_osascript_parents'])
        ),
    },
    {
        'stage': 'AppleScriptExec',
        'technique': 'T1036.005',
        'severity': 'high',
        'name': 'SystemBinaryNameImpersonation',
        'fn': lambda e, iocs: (
            e['process'].strip() in SYSTEM_BINARY_NAMES and
            any(frag in e['message'] for frag in iocs['unsigned_binary_fragments'])
        ),
    },
]

def parse_log_entries(path):
    with open(path, 'r', errors='replace') as f:
        for line in f:
            line = line.rstrip('\n')
            m = LOG_RE.match(line)
            if not m:
                continue
            yield {
                'timestamp': m.group('timestamp'),
                'host': m.group('host'),
                'process': m.group('process'),
                'pid': m.group('pid'),
                'message': m.group('message').replace('\\', '/'),
                'raw': line,
            }

def load_iocs(path):
    iocs = {k: list(v) for k, v in BUNDLED_IOCS.items()}
    if not path:
        return iocs
    with open(path, 'r') as f:
        extra = json.load(f)
    for key in iocs:
        iocs[key] = list(set(iocs[key]) | set(extra.get(key, [])))
    return iocs

def match_rules(entry, iocs, min_severity):
    hits = []
    for rule in RULES:
        if SEVERITY_ORDER[rule['severity']] < SEVERITY_ORDER[min_severity]:
            continue
        try:
            if rule['fn'](entry, iocs):
                hits.append(rule)
        except Exception:
            pass
    return hits

def report_findings(log_path, iocs, min_severity):
    dedup = {}
    stage_counts = defaultdict(int)
    techniques = set()
    peak = 'low'
    exit_nonzero = False

    for entry in parse_log_entries(log_path):
        hits = match_rules(entry, iocs, min_severity)
        for rule in hits:
            key = (rule['name'], entry['process'].strip())
            ts_str = entry['timestamp']
            now = ts_str
            last = dedup.get(key)
            if last and last == now:
                continue
            dedup[key] = now

            stage_counts[rule['stage']] += 1
            techniques.add(f"{rule['stage']}:{rule['technique']}")
            if SEVERITY_ORDER[rule['severity']] > SEVERITY_ORDER[peak]:
                peak = rule['severity']
            if rule['severity'] == 'high':
                exit_nonzero = True

            print(
                f"[{entry['timestamp']}] ALERT stage={rule['stage']} technique={rule['technique']} "
                f"severity={rule['severity'].upper()} rule={rule['name']} "
                f"process={entry['process'].strip()}[{entry['pid']}] | {entry['raw']}"
            )

    print("\n--- Summary ---")
    for stage, count in sorted(stage_counts.items()):
        print(f"  {stage}: {count} hit(s)")
    print(f"  ATT&CK techniques: {', '.join(sorted(techniques)) or 'none'}")
    print(f"  Peak severity: {peak.upper()}")
    return exit_nonzero

def main():
    parser = argparse.ArgumentParser(
        description='Detect PamStealer macOS PAM abuse and AppleScript indicators in unified log exports.'
    )
    parser.add_argument('log_file', help='Path to macOS unified log export (syslog style)')
    parser.add_argument('--iocs', help='Path to supplemental JSON IOC file', default=None)
    parser.add_argument('--severity', choices=['low', 'medium', 'high'], default='low',
                        help='Minimum alert severity to emit (default: low)')
    args = parser.parse_args()

    try:
        iocs = load_iocs(args.iocs)
    except Exception as e:
        print(f"ERROR loading IOCs: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        exit_nonzero = report_findings(args.log_file, iocs, args.severity)
    except FileNotFoundError:
        print(f"ERROR: log file not found: {args.log_file}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    sys.exit(1 if exit_nonzero else 0)

if __name__ == '__main__':
    main()