#!/usr/bin/env python3
"""
AI Agent Post-Exploitation Egress and Tool-Call Sequencing Detector

Scans forward proxy access logs or LLM orchestration framework exports for
autonomous AI agent behavioral signatures: LLM provider egress, sub-human
tool-call sequencing, and machine-regular YOLO-mode beaconing.

Usage:
    python ai_agent_postex_egress_detector.py proxy.log
    python ai_agent_postex_egress_detector.py proxy.log --severity high
    python ai_agent_postex_egress_detector.py orch.log --iocs iocs.json --severity medium

IOC JSON: {"hostnames":["llm.corp.internal"],"user_agents":["MyBot/1.0"],"allowlist":["10.0.0.1"]}
"""
import argparse, json, re, sys
from collections import defaultdict
from datetime import datetime
from statistics import mean, pstdev

LLM_HOSTS = {'api.openai.com','api.anthropic.com','generativelanguage.googleapis.com',
             'api.mistral.ai','api.cohere.com','api.together.xyz','api.groq.com',
             'openrouter.ai','api.deepseek.com','api.perplexity.ai'}
AGENT_UA  = re.compile(r'langchain|autogen|crewai|smolagents|openai-agents|litellm', re.I)
TOOL_PATH = re.compile(r'/(tools|functions|invoke|run)/', re.I)
LLM_PATH  = re.compile(r'/v1/(chat/completions|messages|generate|completions)', re.I)
RE_HOST   = re.compile(r'https?://([^/:?#]+)')
RE_AUTH   = re.compile(r'(Authorization|Bearer|api[-_]key)\S*', re.I)
SEV       = {'low': 0, 'medium': 1, 'high': 2}

_SQUID  = re.compile(r'^(\d+\.\d+)\s+\d+\s+(\S+)\s+\S+\s+\S+\s+\w+\s+(\S+)\s+-\s+\S+\s+(\S+)')
_NGINX  = re.compile(r'^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"\w+\s+(\S+)[^"]*"\s+\d+\s+\d+[^"]*"([^"]*)"')
_TSFMTS = ['%d/%b/%Y:%H:%M:%S %z', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%S.%f']

def _ts(s):
    for f in _TSFMTS:
        try: return datetime.strptime(s[:25], f).timestamp()
        except: pass

def parse_log_entries(path):
    sessions = defaultdict(list)
    with open(path, errors='replace') as fh:
        for raw in fh:
            ln = raw.rstrip(); e = None
            m = _SQUID.match(ln)
            if m:
                e = {'ts': float(m.group(1)), 'src': m.group(2), 'uri': m.group(3), 'ua': m.group(4)}
            if not e:
                m = _NGINX.match(ln)
                if m:
                    ts = _ts(m.group(2))
                    if ts: e = {'ts': ts, 'src': m.group(1), 'uri': m.group(3), 'ua': m.group(4)}
            if not e:
                iso = re.search(r'(\d{4}-\d\d-\d\dT[\d:]+(?:\.\d+)?)', ln)
                src = re.search(r'(?:src|source|client)[=: "]+(\d[\d.]+)', ln, re.I)
                uri = re.search(r'(?:uri|url|path)[=: "]+(\S+)', ln, re.I)
                ts  = _ts(iso.group(1)) if iso else None
                if ts: e = {'ts': ts, 'src': src.group(1) if src else '?',
                            'uri': uri.group(1) if uri else '?', 'ua': ''}
            if e:
                h = RE_HOST.search(e['uri'])
                e['host'] = h.group(1).lower() if h else ''
                e['raw'] = ln
                sessions[e['src']].append(e)
    for s in sessions.values(): s.sort(key=lambda x: x['ts'])
    return sessions

def _cv(ds):
    if len(ds) < 2: return 999.0
    m = mean(ds)
    return (pstdev(ds) / m * 100) if m > 0 else 999.0

def match_rules(sessions, llm_hosts, allowlist):
    alerts = []
    for src, evts in sessions.items():
        if src in allowlist: continue
        for e in evts:
            if e['host'] in llm_hosts or LLM_PATH.search(e['uri']):
                sev = 'high' if AGENT_UA.search(e['ua']) else 'medium'
                alerts.append(('LLMEgress', 'LLMProviderEgress', sev, src, e['ts'], 0, e['raw']))
        tools = [e for e in evts if TOOL_PATH.search(e['uri'])]
        for i in range(len(tools) - 2):
            w = tools[i:i+3]
            ds = [(w[j+1]['ts'] - w[j]['ts']) * 1000 for j in range(2)]
            if (w[2]['ts'] - w[0]['ts']) < 2.0 and _cv(ds) < 20.0:
                alerts.append(('ToolCallSequencing', 'SubHumanToolDispatch', 'high', src,
                               w[0]['ts'], int(mean(ds)), w[0]['raw'])); break
        llm_e = [e for e in evts if e['host'] in llm_hosts or LLM_PATH.search(e['uri'])]
        if len(llm_e) >= 3:
            ds = [llm_e[j+1]['ts'] - llm_e[j]['ts'] for j in range(len(llm_e)-1)]
            vd = [d for d in ds if 5 <= d <= 120]
            if len(vd) >= 2 and _cv(vd) < 10.0:
                alerts.append(('YOLOBeaconing', 'RegularLLMBeacon', 'high', src,
                               llm_e[0]['ts'], int(mean(vd)*1000), llm_e[0]['raw']))
    return alerts

def report_findings(alerts, min_sev, sessions, llm_hosts):
    seen, counts, exit_code = {}, defaultdict(int), 0
    for stage, rule, sev, src, ts, dms, raw in sorted(alerts, key=lambda x: x[4]):
        if SEV.get(sev, 0) < SEV[min_sev]: continue
        key = (stage, rule, src, int(ts / 60))
        if key in seen: continue
        seen[key] = True; counts[stage] += 1
        if sev == 'high': exit_code = 1
        dt   = datetime.utcfromtimestamp(ts).strftime('%Y-%m-%dT%H:%M:%SZ')
        line = RE_AUTH.sub(lambda m: m.group(1) + ' [REDACTED]', raw)[:120]
        print(f"[{dt}] {stage} | {sev.upper()} | {rule} | src={src} | delta={dms}ms | {line}")
    print("\n--- Detection Summary ---")
    for s in ('LLMEgress', 'ToolCallSequencing', 'YOLOBeaconing'):
        print(f"  {s}: {counts.get(s, 0)} hit(s)")
    print("\n--- Session Cadence ---")
    done = set()
    for _, _, _, src, _, _, _ in alerts:
        if src in done: continue
        done.add(src)
        llm_e = [e for e in sessions.get(src, []) if e['host'] in llm_hosts or LLM_PATH.search(e['uri'])]
        if len(llm_e) >= 2:
            ds    = [llm_e[j+1]['ts'] - llm_e[j]['ts'] for j in range(len(llm_e)-1)]
            dests = ','.join({e['host'] for e in llm_e if e['host']})
            print(f"  src={src} mean={mean(ds):.1f}s cv={_cv(ds):.1f}% dst={dests}")
    return exit_code

def main():
    ap = argparse.ArgumentParser(description='AI Agent post-exploitation egress and tool-call sequencing detector.')
    ap.add_argument('log_file', help='Path to proxy or orchestration log file')
    ap.add_argument('--iocs',     help='JSON file with additional hostnames, user_agents, allowlist')
    ap.add_argument('--severity', choices=['low','medium','high'], default='low',
                    help='Minimum alert severity to emit (default: low)')
    args = ap.parse_args()
    llm_hosts, allowlist = set(LLM_HOSTS), set()
    if args.iocs:
        try:
            with open(args.iocs) as f: ioc = json.load(f)
            llm_hosts.update(ioc.get('hostnames', [])); allowlist.update(ioc.get('allowlist', []))
        except Exception as e: print(f"[WARN] IOC load failed: {e}", file=sys.stderr)
    try:
        sessions = parse_log_entries(args.log_file)
    except OSError as e:
        print(f"[ERROR] {e}", file=sys.stderr); sys.exit(2)
    sys.exit(report_findings(match_rules(sessions, llm_hosts, allowlist), args.severity, sessions, llm_hosts))

if __name__ == '__main__':
    main()