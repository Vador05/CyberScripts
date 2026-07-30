#!/usr/bin/env python3
"""
Hermes Autonomous Agent Lateral Movement TTP Detector and Sigma Rule Generator

Scans plain-text endpoint, authentication, or Windows Security log exports for
behavioral signatures of the Hermes autonomous agent operating in YOLO mode.

Usage:
    python hermes_agent_lateral_movement_sigma_mapper.py auth.log
    python hermes_agent_lateral_movement_sigma_mapper.py sec.log --sigma
    python hermes_agent_lateral_movement_sigma_mapper.py endpoint.log --iocs iocs.json --sigma

IOC JSON: {"source_hosts":["10.0.0.5"],"session_tokens":[],"authorized_destinations":["10.0.0.1"]}
"""
import argparse, json, re, sys
from collections import defaultdict
from datetime import datetime
from statistics import pstdev

WIN = 30; DEDUP = 60
_mean = lambda d: sum(d) / len(d) if d else 0

def _var_ok(w):
    ts = sorted(e['ts'] for e in w)
    if len(ts) < 3: return False
    deltas = [ts[i+1]-ts[i] for i in range(len(ts)-1)]
    m = _mean(deltas)
    return m > 0 and pstdev(deltas) / m < 0.15
def _sub2s(w):
    ts = sorted(e['ts'] for e in w)
    return len(ts) > 1 and any(ts[i+1]-ts[i] < 2.0 for i in range(len(ts)-1))
def _hop(w, proto):
    return (any(proto in (e.get('proc','') + e.get('etype','')).lower() for e in w)
            and len(set(e.get('dst','') for e in w if e.get('dst'))) >= 2)

RULES = [
    ('CredentialAccess','T1110.003','PasswordSprayBurst','high',
     lambda w: len(set(e['user'] for e in w if e.get('fail') and e.get('user'))) >= 4 and _var_ok(w)),
    ('CredentialAccess','T1003.001','LSASSAccess','high',
     lambda w: any('lsass' in e.get('proc','').lower() for e in w)),
    ('CredentialAccess','T1558.003','KerberoastingSequence','medium',
     lambda w: sum(1 for e in w if any(k in e.get('etype','').lower() for k in ('tgs','krb'))) >= 3),
    ('HostDiscovery','T1046','AutomatedPortScan','medium',
     lambda w: len(set(e.get('dst','') for e in w if e.get('dst'))) >= 5),
    ('HostDiscovery','T1087','LDAPEnumerationBurst','medium',
     lambda w: sum(1 for e in w if e.get('port') in ('389','636','3268')) >= 4 and _var_ok(w)),
    ('RemotePivoting','T1021.001','RDPLateralMove','high',
     lambda w: _hop(w,'rdp') and _sub2s(w)),
    ('RemotePivoting','T1021.004','SSHLateralMove','high',
     lambda w: _hop(w,'ssh') and _sub2s(w)),
    ('RemotePivoting','T1047','WMIExecPattern','high',
     lambda w: any('wmi' in e.get('proc','').lower() for e in w) and len(set(e.get('dst','') for e in w if e.get('dst'))) >= 2),
]
EVIDS = {'T1110.003':'4625','T1003.001':'4656','T1558.003':'4769','T1046':'5156',
         'T1087':'4662','T1021.001':'4624','T1021.004':'4624','T1047':'4688'}

def sigma_stub(stage, tid, name, sev):
    return (f"---\ntitle: \"{name}\"\nstatus: experimental\n"
            f"description: \"Detects Hermes agent {stage} - {tid}\"\n"
            f"logsource:\n  product: windows\n  service: security\n"
            f"detection:\n  selection:\n    EventID: {EVIDS.get(tid,'4624')}\n  condition: selection\n"
            f"falsepositives:\n  - Authorized scanners\n  - Provisioning agents\n"
            f"level: {sev}\ntags:\n  - attack.{tid.lower().replace('.','_')}\n")

_TS = ['%Y-%m-%dT%H:%M:%S','%Y-%m-%dT%H:%M:%S.%f','%b %d %H:%M:%S','%d/%b/%Y:%H:%M:%S %z']
def _ts(s):
    for f in _TS:
        try: return datetime.strptime(s[:25].strip(), f).timestamp()
        except (ValueError, TypeError): pass

def parse_entry(line):
    m = re.search(r'(\d{4}-\d\d-\d\dT[\d:.]+|\w{3}\s+\d+\s+[\d:]+)', line)
    if not m: return None
    ts = _ts(m.group(1))
    if ts is None: return None
    e = {'ts': ts, 'raw': line[:200]}
    for pat, key in [(r'(?:src|source|shost|from)[=:\s"]+(\S+)', 'src'),
                     (r'(?:dst|dest|dhost|to)[=:\s"]+(\S+)', 'dst'),
                     (r'(?:user|account|username)[=:\s"]+(\S+)', 'user'),
                     (r'(?:proc|process|image)[=:\s"]+(\S+)', 'proc'),
                     (r'(?:port|dport)[=:\s"]+(\d+)', 'port'),
                     (r'(?:etype|type|logon_type)[=:\s"]+(\S+)', 'etype')]:
        m2 = re.search(pat, line, re.I)
        if m2: e[key] = m2.group(1).strip('",;')
    e['fail'] = bool(re.search(r'fail|denied|invalid|bad.pass|wrong.cred', line, re.I))
    for kw in ('lsass','wmiprvse','wmi','psexec','winrm','ssh','rdp'):
        if kw in line.lower(): e.setdefault('proc', kw); break
    for kw in ('tgs-req','tgs','kerberos','krb'):
        if kw in line.lower(): e.setdefault('etype', kw); break
    for p in ('389','636','3268'):
        if re.search(r'\b' + p + r'\b', line): e.setdefault('port', p); break
    return e

def main():
    ap = argparse.ArgumentParser(description='Hermes lateral movement detector and Sigma rule generator')
    ap.add_argument('log_file', help='Path to Windows Security, SSH auth, or endpoint telemetry log')
    ap.add_argument('--iocs', help='JSON with source_hosts, session_tokens, authorized_destinations')
    ap.add_argument('--sigma', action='store_true', help='Emit Sigma rule YAML stubs for detected TTPs')
    args = ap.parse_args()

    allow_src, allow_dst = set(), set()
    if args.iocs:
        try:
            with open(args.iocs) as f:
                d = json.load(f)
            allow_src.update(d.get('source_hosts',[])); allow_dst.update(d.get('authorized_destinations',[]))
        except Exception as ex: print(f'[WARN] IOC load failed: {ex}', file=sys.stderr)

    try:
        with open(args.log_file, errors='replace') as f:
            lines = f.readlines()
    except Exception as ex: sys.exit(f'[ERROR] {ex}')
    entries = [e for e in (parse_entry(l.rstrip()) for l in lines) if e]

    wins = defaultdict(list)
    for e in entries:
        wins[(e.get('src','?'), int(e['ts'] // WIN))].append(e)

    counts = defaultdict(int); peak_sev = []; dedup = {}; seen_sigma = set(); hit_tids = set()
    for (src, _), w in sorted(wins.items()):
        if src in allow_src: continue
        w = [e for e in w if e.get('dst','') not in allow_dst]
        for stage, tid, name, sev, chk in RULES:
            try: hit = chk(w)
            except Exception: hit = False
            if not hit: continue
            t0 = min(e['ts'] for e in w)
            if (src,tid) in dedup and t0 - dedup[(src,tid)] < DEDUP: continue
            dedup[(src,tid)] = t0
            dt = datetime.fromtimestamp(t0).strftime('%Y-%m-%dT%H:%M:%S')
            dsts = list(set(e.get('dst','') for e in w if e.get('dst')))[:3]
            users = list(set(e.get('user','?') for e in w if e.get('user')))[:2]
            print(f"[{dt}] {stage} | {tid} | sev={sev} | rule={name} | src={src} | dst={dsts} | users={users}")
            print(f"  >> {w[0]['raw'][:120]}")
            counts[stage] += 1; peak_sev.append(sev); hit_tids.add(tid)
            if args.sigma and tid not in seen_sigma:
                seen_sigma.add(tid); print(sigma_stub(stage, tid, name, sev))

    print('\n--- Summary ---')
    for stage, cnt in counts.items(): print(f'  {stage}: {cnt} hit(s)')
    triggered_tids = sorted(hit_tids)
    pivots = set(f"{e.get('src','?')}->{e.get('dst','?')}" for e in entries if e.get('src') and e.get('dst'))
    print(f'  ATT&CK coverage: {", ".join(triggered_tids) or "none"}')
    print(f'  Unique pivot paths: {len(pivots)}')
    sord = {'low':0,'medium':1,'high':2}
    peak = max(peak_sev, key=lambda s: sord[s]) if peak_sev else 'none'
    print(f'  Peak severity: {peak}')
    sys.exit(1 if peak == 'high' else 0)

if __name__ == '__main__': main()