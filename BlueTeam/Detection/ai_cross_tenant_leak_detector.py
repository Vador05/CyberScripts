"""
AI SaaS Cross-Tenant Session Isolation & WriteOut Leak Detector

Scans AI API session logs for cross-tenant context contamination (WriteOut pattern),
detecting when one tenant's system prompt fragments or data markers surface in another
tenant's context window or assistant response payloads across three kill-chain stages.

Usage example:
    python ai_cross_tenant_leak_detector.py session.log
    python ai_cross_tenant_leak_detector.py session.log --tenants markers.json --severity medium
    python ai_cross_tenant_leak_detector.py session.log --severity high

Log format (whitespace-separated; payload may contain spaces):
    2024-01-15T10:23:45 tenantA sess001 0 system You are the ACME Corp AI assistant
    2024-01-15T10:23:46 tenantA sess001 1 user What is my account balance?
    2024-01-15T10:23:47 tenantB sess002 0 system You assist BetaCorp customers only
    2024-01-15T10:23:48 tenantB sess002 1 assistant ACME Corp account balance is 5000
"""

import argparse, json, re, sys
from collections import defaultdict

SEV = {"low": 0, "medium": 1, "high": 2}

HEURISTICS = [
    {"name": "system_prompt_role", "pat": r"you are (?:the |an? )?[A-Z][A-Za-z]+(?: AI| assistant| bot| agent)",
     "sev": "high", "fix": "Flush context window between tenant requests; reinitialize per-tenant session isolation."},
    {"name": "tenant_id_token", "pat": r"\b(?:tenant[_\-]?id|org[_\-]?id|client[_\-]?id)\s*[:=]\s*\S+",
     "sev": "high", "fix": "Strip tenant identity tokens from payloads before cross-request context evaluation."},
    {"name": "embedded_api_key", "pat": r"\b(?:api[_\-]?key|bearer token|x-api-key)\s*[:=]\s*\S{8,}",
     "sev": "high", "fix": "Remove API credentials from system prompts; inject secrets outside model context window."},
    {"name": "confidential_label", "pat": r"\b(?:confidential|proprietary|internal use only|trade secret)\b",
     "sev": "medium", "fix": "Audit confidentiality-marked content surfacing cross-tenant; enforce inference-layer barriers."},
    {"name": "instruction_directive", "pat": r"(?:your (?:role|purpose|task) is|you must (?:always|never)|respond only as)",
     "sev": "medium", "fix": "Block system-prompt instruction directives from leaking into cross-tenant inference sessions."},
]

LOG_RE = re.compile(r"(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(system|user|assistant)\s+(.+)")


def parse_log(path):
    sessions = defaultdict(list)
    with open(path) as fh:
        for line in fh:
            m = LOG_RE.match(line.strip())
            if not m:
                continue
            ts, tenant, sid, turn, role, payload = m.groups()
            sessions[sid].append({"tenant": tenant, "sid": sid, "turn": int(turn), "role": role, "payload": payload})
    for sid in sessions:
        sessions[sid].sort(key=lambda e: e["turn"])
    return sessions


def build_markers(sessions, tenants_path):
    markers = defaultdict(list)
    if tenants_path:
        with open(tenants_path) as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("Tenants file must contain a JSON object")
        for tid, info in data.items():
            if not isinstance(info, dict):
                raise ValueError(f"Tenant '{tid}' entry must be a JSON object, got {type(info).__name__}")
            markers_list = info.get("markers", [])
            if not isinstance(markers_list, list):
                raise ValueError(f"Tenant '{tid}' markers must be a list, got {type(markers_list).__name__}")
            for frag in markers_list:
                if not isinstance(frag, str):
                    raise ValueError(f"Tenant '{tid}' marker must be a string, got {type(frag).__name__}")
                markers[tid].append((re.compile(re.escape(frag), re.I), f"custom:{frag[:24]}", "high",
                                     "Custom tenant marker found cross-tenant; isolate inference context immediately."))
    for sid, entries in sessions.items():
        for e in entries:
            if e["role"] != "system":
                continue
            for h in HEURISTICS:
                m = re.search(h["pat"], e["payload"], re.I)
                if m:
                    markers[e["tenant"]].append((re.compile(re.escape(m.group(0)), re.I), h["name"], h["sev"], h["fix"]))
    for tid in markers:
        seen, deduped = set(), []
        for item in markers[tid]:
            pattern_key = (item[1], item[0].pattern)
            if pattern_key not in seen:
                seen.add(pattern_key)
                deduped.append(item)
        markers[tid] = deduped
    return markers


def detect(sessions, markers, min_sev):
    findings, emitted = [], set()
    for sid, entries in sessions.items():
        sink_tenant = entries[0]["tenant"] if entries else None
        if not sink_tenant:
            continue
        for src_tenant, mlist in markers.items():
            if src_tenant == sink_tenant:
                continue
            for cpat, name, sev, fix in mlist:
                if SEV[sev] < SEV[min_sev]:
                    continue
                hits = [(e["turn"], e["role"], e["payload"]) for e in entries if cpat.search(e["payload"])]
                if not hits:
                    continue
                turns, roles = [h[0] for h in hits], [h[1] for h in hits]
                if any(r == "assistant" for r in roles):
                    stage = "Exfiltration"
                elif len(turns) >= 2 and any(turns[i+1] - turns[i] == 1 for i in range(len(turns)-1)):
                    stage = "Persistence"
                else:
                    stage = "Contamination"
                key = (sid, src_tenant, name, stage)
                if key in emitted:
                    continue
                emitted.add(key)
                payload = next(h[2] for h in hits)
                m2 = cpat.search(payload)
                fragment = payload[max(0, m2.start()-15):m2.end()+15].strip()[:120]
                findings.append({"sev": sev, "stage": stage, "rule": name,
                                  "src": src_tenant, "sink": sink_tenant, "sid": sid,
                                  "fragment": fragment, "fix": fix})
    findings.sort(key=lambda f: -SEV[f["sev"]])
    return findings


def report(findings):
    counts, pairs, peak = defaultdict(int), set(), "low"
    for f in findings:
        print(f"[{f['sev'].upper()}][{f['stage']}] rule={f['rule']} src_tenant={f['src']} -> sink_tenant={f['sink']} session={f['sid']}")
        print(f"  leaked: {f['fragment']}")
        print(f"  fix:    {f['fix']}")
        counts[f["stage"]] += 1
        pairs.add((f["src"], f["sink"]))
        if SEV[f["sev"]] > SEV[peak]:
            peak = f["sev"]
    print("\n=== Summary ===")
    for stage in ("Contamination", "Exfiltration", "Persistence"):
        print(f"  {stage}: {counts[stage]} hit(s)")
    print(f"  Unique tenant pairs affected: {len(pairs)}")
    print(f"  Peak severity: {peak.upper()}")
    if not findings:
        print("  No findings above threshold.")
    return peak == "high"


def main():
    ap = argparse.ArgumentParser(description="Detect WriteOut cross-tenant leakage in AI API session logs.")
    ap.add_argument("log_file", help="Path to AI API session log file")
    ap.add_argument("--tenants", metavar="FILE", help="JSON file mapping tenant IDs to known marker fragments")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low", help="Minimum alert severity (default: low)")
    args = ap.parse_args()
    try:
        sessions = parse_log(args.log_file)
    except OSError as e:
        print(f"ERROR reading log: {e}", file=sys.stderr); sys.exit(2)
    try:
        markers = build_markers(sessions, args.tenants)
    except (OSError, json.JSONDecodeError, ValueError, AttributeError, TypeError) as e:
        print(f"ERROR loading tenants file: {e}", file=sys.stderr); sys.exit(2)
    findings = detect(sessions, markers, args.severity)
    sys.exit(1 if report(findings) else 0)


if __name__ == "__main__":
    main()