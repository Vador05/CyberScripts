#!/usr/bin/env python3
"""
Autonomous AI Agent Post-Exploitation Behavioral Detector

Scans auditd, syslog, or bash history exports for behavioral signatures of
autonomous AI agent post-exploitation activity — non-TTY command execution,
machine-precise timing cadence, SSH lateral movement, and persistence deployment.

Usage:
    python autonomous_agent_postex_detector.py audit.log
    python autonomous_agent_postex_detector.py syslog.txt --severity high
    python autonomous_agent_postex_detector.py history.txt --iocs iocs.json --severity medium

IOC JSON: {"patterns":["cmd"],"allowlist":[{"uid":"1001","cmd_prefix":"ansible"}],"lateral_hosts":["10.0.0.1"]}
"""
import argparse, json, re, sys
from collections import defaultdict
from datetime import datetime
from statistics import mean, pstdev

RULES = [
    ('UnattendedExec', 'CurlPipeBash',        'high',   r'curl\s.+\|\s*(ba)?sh'),
    ('UnattendedExec', 'WgetPipeBash',         'high',   r'wget\s.+-\s*\|\s*(ba)?sh'),
    ('UnattendedExec', 'Base64DecodeExec',     'high',   r'base64\s+(-d|--decode).+\|\s*(ba)?sh'),
    ('LateralMovement','SSHNoHostCheck',       'high',   r'ssh\s.*-o\s*StrictHostKeyChecking=no'),
    ('LateralMovement','SSHInlineKey',         'medium', r'ssh\s+.*-i\s+\S+'),
    ('LateralMovement','SudoNonInteractive',   'medium', r'sudo\s+-n\b'),
    ('LateralMovement','SuFromNonTTY',         'medium', r'\bsu\s+(-\s+)?\w+'),
    ('Persistence',    'CrontabEdit',          'high',   r'crontab\s+-[el]'),
    ('Persistence',    'CronDirWrite',         'high',   r'>>\s*/etc/cron'),
    ('Persistence',    'SystemdUnit',          'high',   r'(cp|mv|tee|cat)[^|]+/(etc|lib)/systemd'),
    ('Persistence',    'AuthorizedKeysAppend', 'high',   r'>>\s*[\w~/]*\.ssh/authorized_keys'),
    ('Persistence',    'PasswdShadowMod',      'high',   r'(echo|tee)\s.*>>\s*/etc/(passwd|shadow)'),
]
SEV = {'low': 0, 'medium': 1, 'high': 2}

def parse_entries(path):
    entries, ts_pend = [], None
    aud = re.compile(r'audit\((\d+\.\d+):\d+\).*?pid=(\d+).*?uid=(\d+).*?tty=(\S+).*?(?:comm|exe)="([^"]+)"')
    slg = re.compile(r'(\w{3}\s+\d+\s+[\d:]+)\s+\S+\s+([\w.-]+)\[(\d+)\]:\s*(.*)')
    hst = re.compile(r'^#(\d{10,})$')
    with open(path, errors='replace') as fh:
        for raw in fh:
            ln = raw.rstrip()
            m = aud.search(ln)
            if m:
                entries.append({'ts': float(m.group(1)), 'pid': m.group(2), 'uid': m.group(3),
                                'tty': m.group(4), 'cmd': m.group(5), 'raw': ln})
                continue
            m = hst.match(ln)
            if m:
                ts_pend = float(m.group(1)); continue
            if ts_pend is not None:
                entries.append({'ts': ts_pend, 'pid': '0', 'uid': '?', 'tty': '?', 'cmd': ln, 'raw': ln})
                ts_pend = None; continue
            m = slg.match(ln)
            if m:
                try:
                    now = datetime.now()
                    dt = datetime.strptime(f"{now.year} {m.group(1)}", "%Y %b %d %H:%M:%S")
                    if dt > now:
                        dt = dt.replace(year=now.year - 1)
                    ts = dt.timestamp()
                except Exception:
                    continue
                uid_match = re.search(r'uid=(\d+)', m.group(4))
                uid = uid_match.group(1) if uid_match else '?'
                entries.append({'ts': ts, 'pid': m.group(3), 'uid': uid, 'tty': '?',
                                'cmd': m.group(4), 'raw': ln})
    return sorted(entries, key=lambda e: e['ts'])

def cadence_cv(times):
    if len(times) < 3: return None
    deltas = [(times[i+1] - times[i]) * 1000 for i in range(len(times) - 1)]
    m = mean(deltas)
    return (pstdev(deltas) / m * 100) if m else 0.0

def match_rules(sessions, rules, allowlist, extra_hosts, min_sev):
    hits = []
    for (uid, pid), evts in sessions.items():
        tty_absent = all(e['tty'] in ('?', '') for e in evts)
        cv = cadence_cv([e['ts'] for e in evts])
        if not tty_absent and not (cv is not None and cv < 15.0): continue
        skip = False
        for a in allowlist:
            if uid == a.get('uid'):
                cmd_prefix = a.get('cmd_prefix')
                if cmd_prefix and all(e['cmd'].startswith(cmd_prefix) for e in evts):
                    skip = True
                    break
        if skip: continue
        seen_hosts, prev_ts, first_host_ts = set(), None, None
        for e in evts:
            delta = int((e['ts'] - prev_ts) * 1000) if prev_ts else 0
            prev_ts = e['ts']
            cmd = e['cmd']
            hm = re.search(r'(?:ssh|nc)\s+(?:[\w@-]+\s+)*(?:.*@)?(\w+(?:[.-]\w+)*)', cmd)
            if hm:
                host = hm.group(1)
                if host not in seen_hosts:
                    if first_host_ts is None:
                        first_host_ts = e['ts']
                    if (e['ts'] - first_host_ts) <= 30.0:
                        seen_hosts.add(host)
                        if len(seen_hosts) > 1 or host in extra_hosts:
                            hits.append({'stage': 'LateralMovement', 'rule': 'MultiHostPivot', 'sev': 'high',
                                         'ts': e['ts'], 'uid': uid, 'pid': pid, 'delta': delta,
                                         'tty': tty_absent, 'cv': cv, 'raw': e['raw']})
            for stage, name, sev, pat in rules:
                if SEV.get(sev, 0) < SEV.get(min_sev, 0): continue
                if re.search(pat, cmd, re.I):
                    hits.append({'stage': stage, 'rule': name, 'sev': sev, 'ts': e['ts'],
                                 'uid': uid, 'pid': pid, 'delta': delta,
                                 'tty': tty_absent, 'cv': cv, 'raw': e['raw']})
    return hits

def report(hits, min_sev):
    seen, peak, counts, sess_info, rc = set(), 'low', defaultdict(int), {}, 0
    print(f"{'TIMESTAMP':24} {'STAGE':20} {'SEV':8} {'RULE':28} {'UID/PID':16} {'DELTA_MS':10} LOG")
    print('-' * 120)
    for h in sorted(hits, key=lambda x: x['ts']):
        key = (h['uid'], h['pid'], h['rule'], int(h['ts'] // 60))
        if key in seen or SEV.get(h['sev'], 0) < SEV.get(min_sev, 0): continue
        seen.add(key)
        ts = datetime.fromtimestamp(h['ts']).strftime('%Y-%m-%dT%H:%M:%S') if h['ts'] else 'unknown'
        print(f"{ts:24} {h['stage']:20} {h['sev']:8} {h['rule']:28} {h['uid']}/{h['pid']:8} "
              f"{h['delta']:10} {h['raw'][:80]}")
        counts[h['stage']] += 1
        if SEV.get(h['sev'], 0) > SEV.get(peak, 0): peak = h['sev']
        if h['sev'] == 'high': rc = 1
        sess_info[(h['uid'], h['pid'])] = {'cv': h['cv'], 'tty': h['tty']}
    print('\n--- KILL-CHAIN SUMMARY ---')
    for stage, cnt in counts.items(): print(f"  {stage}: {cnt} match(es)")
    print(f"  Peak severity: {peak}")
    print(f"\n{'SESSION':26} {'CV':10} {'TTY':8}")
    for (uid, pid), info in sess_info.items():
        cv_s = f"{info['cv']:.1f}%" if info['cv'] is not None else "N/A"
        print(f"  uid={uid} pid={pid:6} {cv_s:10} {'noTTY' if info['tty'] else 'hasTTY'}")
    return rc

def main():
    ap = argparse.ArgumentParser(description='Autonomous AI Agent Post-Exploitation Behavioral Detector',
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument('log_file', help='Path to auditd, syslog, or bash history log')
    ap.add_argument('--iocs', help='Supplemental IOC JSON file')
    ap.add_argument('--severity', choices=['low', 'medium', 'high'], default='low',
                    help='Minimum alert severity (default: low)')
    args = ap.parse_args()
    extra_rules, allowlist, extra_hosts = [], [], []
    if args.iocs:
        try:
            with open(args.iocs) as fh:
                d = json.load(fh)
            extra_rules = [('UnattendedExec', f"IOC:{p[:20]}", 'high', re.escape(p))
                           for p in d.get('patterns', [])]
            allowlist, extra_hosts = d.get('allowlist', []), d.get('lateral_hosts', [])
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[WARN] IOC load error: {e}", file=sys.stderr)
        except Exception as e:
            print(f"[WARN] Unexpected IOC error: {e}", file=sys.stderr)
    try:
        entries = parse_entries(args.log_file)
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {args.log_file}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"[ERROR] Cannot parse log: {e}", file=sys.stderr)
        sys.exit(2)
    sessions = defaultdict(list)
    for e in entries: sessions[(e['uid'], e['pid'])].append(e)
    hits = match_rules(sessions, RULES + extra_rules, allowlist, extra_hosts, args.severity)
    sys.exit(report(hits, args.severity))

if __name__ == '__main__':
    main()