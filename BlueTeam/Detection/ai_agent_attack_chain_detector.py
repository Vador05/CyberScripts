"""AI Agent Attack Chain Behavioral Detector

Scans API gateway, LLM orchestration, or cloud function logs for behavioral signatures
of autonomous AI agent attack chains across reconnaissance, lateral movement, and impact stages.

Usage:
    python ai_agent_attack_chain_detector.py access.log
    python ai_agent_attack_chain_detector.py access.log --iocs iocs.json --severity high
"""
import argparse, json, math, re, sys
from collections import defaultdict
from datetime import datetime

RECON_AGENTS = ["langchain", "autogpt", "crewai", "babyagi", "agentgpt", "openagents"]
RECON_PATHS = ["/.well-known/", "/v1/models", "/openapi.json", "/actuator/env", "/api-docs", "/swagger"]
CRED_PATHS = ["/oauth/token", "/.env", "/169.254.169.254/", "/latest/meta-data", "/vault/v1/"]
KMS_PATHS = ["/kms/", "/v1/transit/", "/secretsmanager/", "/encrypt", "/decrypt"]
RULES = {
    "Reconnaissance": [
        ("api_enumeration", "high", lambda s: s["rps"] > 5 and len(s["evts"]) > 10),
        ("metadata_harvest", "medium", lambda s: sum(1 for u in s["uris"] if any(p in u for p in RECON_PATHS)) >= 2),
        ("agent_useragent", "medium", lambda s: any(a in s["ua"] for a in RECON_AGENTS)),
    ],
    "LateralMovement": [
        ("token_relay", "high", lambda s: len(s["hosts"]) > 2 and bool(s["token"])),
        ("cred_probe", "high", lambda s: sum(1 for u in s["uris"] if any(p in u for p in CRED_PATHS)) >= 2),
        ("tool_chain", "medium", lambda s: s["unique_paths"] > 8 and s["cv"] < 0.3 and s["nonhuman"]),
    ],
    "Encryption": [
        ("kms_abuse", "high", lambda s: any(p in u for u in s["uris"] for p in KMS_PATHS) and s["nonhuman"]),
        ("bulk_readwrite", "high", lambda s: s["reads"] > 5 and s["writes"] > 3),
    ],
}
LOG_PATS = [
    re.compile(r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\w+) (?P<uri>\S+)[^"]*" (?P<status>\d+) \S+ "[^"]*" "(?P<ua>[^"]*)"'),
    re.compile(r'"timestamp"\s*:\s*"(?P<ts>[^"]+)".*?"method"\s*:\s*"(?P<method>[^"]+)".*?"uri"\s*:\s*"(?P<uri>[^"]+)".*?"(?:session_?id|sessionId)"\s*:\s*"(?P<sid>[^"]+)".*?"(?:user.?[Aa]gent)"\s*:\s*"(?P<ua>[^"]*)"'),
    re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s+(?P<method>GET|POST|PUT|DELETE|PATCH)\s+(?P<uri>\S+)'),
]
TS_FMTS = ["%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S"]

def parse_ts(s):
    for fmt in TS_FMTS:
        try: return datetime.strptime(s.strip(), fmt).timestamp()
        except ValueError: pass
    return None

def parse_log_entries(path, iocs):
    entries, tok_re = [], re.compile(r'Bearer ([A-Za-z0-9\-._~+/]+=*)')
    extra_agents = [a.lower() for a in iocs.get("user_agents", [])]
    extra_paths = iocs.get("endpoint_paths", [])
    RECON_AGENTS.extend(a for a in extra_agents if a not in RECON_AGENTS)
    RECON_PATHS.extend(p for p in extra_paths if p not in RECON_PATHS)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            for pat in LOG_PATS:
                m = pat.search(line)
                if not m: continue
                d = m.groupdict()
                ts = parse_ts(d.get("ts", ""))
                if ts is None: continue
                tok_m = tok_re.search(line)
                entries.append({"ts": ts, "method": d.get("method", "GET"), "uri": d.get("uri", "/"),
                    "ua": d.get("ua", "").lower(), "ip": d.get("ip", ""), "raw": line[:200],
                    "sid": d.get("sid", d.get("ip", "unknown")),
                    "token": tok_m.group(1) if tok_m else "",
                    "host": re.search(r'[Hh]ost:\s*(\S+)', line, re.I) and re.search(r'[Hh]ost:\s*(\S+)', line, re.I).group(1) or ""})
                break
    return entries

def build_sessions(entries):
    buckets = defaultdict(list)
    for e in entries: buckets[e["sid"]].append(e)
    sessions = {}
    for sid, evts in buckets.items():
        evts.sort(key=lambda x: x["ts"])
        deltas = [evts[i+1]["ts"] - evts[i]["ts"] for i in range(len(evts)-1)] or [1]
        mean_d = sum(deltas) / len(deltas)
        cv = math.sqrt(sum((d-mean_d)**2 for d in deltas)/len(deltas)) / max(mean_d, 1e-6)
        dur = max(evts[-1]["ts"] - evts[0]["ts"], 1)
        uris = [e["uri"] for e in evts]
        sessions[sid] = {"sid": sid, "evts": evts, "mean_delta": mean_d, "cv": round(cv, 3),
            "rps": round(len(evts)/dur, 2), "ua": " ".join(e["ua"] for e in evts),
            "uris": uris, "unique_paths": len(set(uris)),
            "hosts": {e["host"] for e in evts if e["host"]},
            "token": next((e["token"] for e in evts if e["token"]), ""),
            "reads": sum(1 for e in evts if e["method"] == "GET"),
            "writes": sum(1 for e in evts if e["method"] in {"PUT","POST","DELETE"}),
            "nonhuman": cv < 0.35 and mean_d < 2.0 and len(evts) > 5}
    return sessions

def match_rules(sessions, min_sev):
    SEV = {"low": 0, "medium": 1, "high": 2}
    findings, seen = [], set()
    for sid, s in sessions.items():
        for stage, rules in RULES.items():
            for name, sev, check in rules:
                if SEV.get(sev, 0) < SEV.get(min_sev, 0): continue
                try: hit = check(s)
                except Exception: hit = False
                if hit and (sid, stage, name) not in seen:
                    seen.add((sid, stage, name))
                    findings.append({"stage": stage, "sev": sev, "rule": name, "sid": sid,
                        "delta_ms": int(s["mean_delta"]*1000), "cv": s["cv"], "rps": s["rps"],
                        "raw": s["evts"][-1]["raw"], "ts": datetime.fromtimestamp(s["evts"][-1]["ts"]).isoformat()})
    return findings

def report_findings(findings, sessions):
    counts, has_high = defaultdict(int), False
    for f in sorted(findings, key=lambda x: x["ts"]):
        print(f"[{f['ts']}] STAGE={f['stage']} SEV={f['sev'].upper()} RULE={f['rule']} SID={f['sid']} DELTA={f['delta_ms']}ms | {f['raw']}")
        counts[f["stage"]] += 1
        if f["sev"] == "high": has_high = True
    print("\n--- Kill-Chain Stage Summary ---")
    for stage, cnt in counts.items(): print(f"  {stage}: {cnt} alert(s)")
    flagged = {f["sid"] for f in findings}
    if flagged:
        print(f"\n--- Non-Human Cadence Summary ---\n  {'Session':<24} {'MeanDelta(ms)':<16} {'CV':<8} {'RPS'}")
        for sid in flagged:
            s = sessions[sid]
            print(f"  {sid:<24} {int(s['mean_delta']*1000):<16} {s['cv']:<8.3f} {s['rps']}")
    print(f"\nPeak severity: {'HIGH' if has_high else 'MEDIUM' if counts else 'NONE'}")
    return has_high

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log_file", help="Path to API gateway or orchestration log")
    ap.add_argument("--iocs", help="Path to supplemental JSON IOC file")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low")
    args = ap.parse_args()
    iocs = {}
    if args.iocs:
        try:
            with open(args.iocs) as f: iocs = json.load(f)
        except Exception as e: print(f"Warning: could not load --iocs: {e}", file=sys.stderr)
    try: entries = parse_log_entries(args.log_file, iocs)
    except Exception as e: print(f"Error reading log: {e}", file=sys.stderr); sys.exit(2)
    if not entries: print("No parseable entries found."); sys.exit(0)
    sessions = build_sessions(entries)
    findings = match_rules(sessions, args.severity)
    if not findings: print("No findings at specified severity."); sys.exit(0)
    sys.exit(1 if report_findings(findings, sessions) else 0)

if __name__ == "__main__":
    main()