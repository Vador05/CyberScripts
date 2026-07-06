"""
Langflow Agentic Tool-Call Abuse & Lateral Movement Detector

Scans Langflow/LLM orchestration logs for agentic attack patterns across
three kill-chain stages: ToolCallAbuse, LateralMovement, Exfiltration.

Usage:
    python langflow_agentic_abuse_detector.py execution.log
    python langflow_agentic_abuse_detector.py execution.log --iocs extra_iocs.json --severity high
"""

import argparse
import base64
import json
import re
import sys
from collections import defaultdict
from datetime import datetime

RULES = {
    "ToolCallAbuse": [
        {"name": "ShellExecution", "severity": "high", "fields": ["tool_name", "input"], "pattern": r"(?i)(bash|shell|exec|subprocess|os\.system|cmd\.exe|powershell|/bin/sh)"},
        {"name": "CredentialFileAccess", "severity": "high", "fields": ["tool_name", "input"], "pattern": r"(?i)(\.env|credentials|\.aws/|\.ssh/|passwd|shadow|id_rsa|secret_key|api_key)"},
        {"name": "RecursiveSelfInvocation", "severity": "medium", "fields": ["tool_name", "input"], "pattern": r"(?i)(invoke_self|call_flow|recursive|self_call|agent_loop|loop_back)"},
        {"name": "PrivilegedFileWrite", "severity": "high", "fields": ["tool_name", "input"], "pattern": r"(?i)(write_file|file_write|save_file).{0,80}(/etc/|/root/|C:\\Windows\\|/usr/bin/)"},
    ],
    "LateralMovement": [
        {"name": "CrossFlowPivot", "severity": "high", "fields": ["input", "component"], "pattern": r"(?i)(cross.?flow|pivot.?flow|invoke.?flow|transfer.?session|hijack.?session|flow.?id\s*[:=]\s*['\"]?\w{8,})"},
        {"name": "MemoryStoreInjection", "severity": "medium", "fields": ["input", "tool_name"], "pattern": r"(?i)(memory.?store|vector.?store|inject.?context|prior.?session|load.?memory|retrieve.?context)"},
        {"name": "RAGCredentialQuery", "severity": "medium", "fields": ["input"], "pattern": r"(?i)(rag.{0,20}(credential|password|secret|token|api.?key)|retrieve.{0,20}(\.env|\.aws|ssh.?key))"},
        {"name": "InternalNetworkProbe", "severity": "medium", "fields": ["input", "tool_name"], "pattern": r"(?i)(192\.168\.|10\.\d+\.\d+\.|172\.(1[6-9]|2\d|3[01])\.|localhost|internal\.|intranet\.)"},
    ],
    "Exfiltration": [
        {"name": "OutboundDomainToolCall", "severity": "high", "fields": ["input", "tool_name"], "pattern": r"(?i)(http[s]?://(?!localhost|127\.0\.0\.1|192\.168\.|10\.\d|172\.(1[6-9]|2\d|3[01])\.)\S+)"},
        {"name": "Base64EncodedPayload", "severity": "medium", "fields": ["input", "output"], "pattern": r"(?:[A-Za-z0-9+/]{40,}={0,2})"},
        {"name": "HexEncodedPayload", "severity": "medium", "fields": ["input", "output"], "pattern": r"(?i)(0x[0-9a-f]{32,}|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){15,})"},
        {"name": "AnomalousLongOutput", "severity": "low", "fields": ["output"], "pattern": r"(?s).{2000,}"},
    ],
}

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

LOG_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*)"
    r".*?(?:flow[_\s]?id[=:\s]+['\"]?(?P<flow_id>[\w-]+))?"
    r".*?(?:session[_\s]?id[=:\s]+['\"]?(?P<session_id>[\w-]+))?"
    r".*?(?:component[=:\s]+['\"]?(?P<component>[\w-]+))?"
    r".*?(?:tool[_\s]?name[=:\s]+['\"]?(?P<tool_name>[\w._-]+))?"
    r".*?(?:input[=:\s]+['\"]?(?P<input>[^\"'\n]{0,500}))?"
    r".*?(?:output[=:\s]+['\"]?(?P<output>[^\"'\n]{0,2100}))?",
    re.IGNORECASE,
)


def parse_log_entry(line):
    entry = {"raw": line.rstrip(), "timestamp": "", "flow_id": "", "session_id": "", "component": "", "tool_name": "", "input": "", "output": ""}
    try:
        data = json.loads(line)
        for key in entry:
            for variant in [key, key.replace("_", ""), key.replace("_", "-")]:
                if variant in data:
                    entry[key] = str(data[variant])
                    break
        entry["raw"] = line.rstrip()
        return entry
    except (json.JSONDecodeError, ValueError):
        pass
    m = LOG_PATTERN.match(line)
    if m:
        for k, v in m.groupdict().items():
            if v:
                entry[k] = v
    entry["raw"] = line.rstrip()
    return entry


def is_likely_base64(payload):
    try:
        if len(payload) < 40:
            return False
        base64.b64decode(payload + "==", validate=True)
        return True
    except Exception:
        return False


def load_iocs(path):
    with open(path) as f:
        data = json.load(f)
    extra = {"ToolCallAbuse": [], "LateralMovement": [], "Exfiltration": []}
    for stage, rules_list in data.get("rules", {}).items():
        if stage in extra:
            extra[stage].extend(rules_list)
    for stage, names in data.get("tool_names", {}).items():
        if stage in extra and names:
            pattern = r"(?i)(" + "|".join(re.escape(n) for n in names) + ")"
            extra[stage].append({"name": "SupplementalToolName", "severity": "medium", "fields": ["tool_name"], "pattern": pattern})
    return extra


def match_rules(entry, rules, min_severity):
    hits = []
    for stage, stage_rules in rules.items():
        for rule in stage_rules:
            if SEVERITY_RANK.get(rule["severity"], 0) < SEVERITY_RANK[min_severity]:
                continue
            combined = " ".join(str(entry.get(f, "")) for f in rule["fields"])
            if not combined.strip():
                continue
            if re.search(rule["pattern"], combined):
                hits.append({"stage": stage, "rule": rule["name"], "severity": rule["severity"]})
    return hits


def format_alert(entry, hit, line_num):
    ts = entry.get("timestamp") or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    flow = entry.get("flow_id") or "unknown"
    session = entry.get("session_id") or "unknown"
    raw = entry["raw"][:200]
    return f"[{ts}] [{hit['severity'].upper()}] {hit['stage']}/{hit['rule']} flow={flow} session={session} line={line_num} | {raw}"


def report_findings(log_path, rules, min_severity):
    dedup = defaultdict(set)
    stage_counts = defaultdict(int)
    sessions_hit = set()
    peak_severity = "low"
    found_high = False
    line_num = 0

    try:
        with open(log_path, errors="replace") as f:
            for line in f:
                line_num += 1
                if not line.strip():
                    continue
                entry = parse_log_entry(line)
                hits = match_rules(entry, rules, min_severity)
                session = entry.get("session_id") or "unknown"
                for hit in hits:
                    dedup_key = (session, hit["stage"], hit["rule"])
                    if dedup_key in dedup and len(dedup[dedup_key]) >= 3:
                        continue
                    dedup[dedup_key].add(line_num)
                    print(format_alert(entry, hit, line_num))
                    stage_counts[hit["stage"]] += 1
                    sessions_hit.add(session)
                    if SEVERITY_RANK[hit["severity"]] > SEVERITY_RANK[peak_severity]:
                        peak_severity = hit["severity"]
                    if hit["severity"] == "high":
                        found_high = True
    except OSError as e:
        print(f"ERROR: Cannot read log file: {e}", file=sys.stderr)
        sys.exit(2)

    print("\n--- Detection Summary ---")
    for stage in ("ToolCallAbuse", "LateralMovement", "Exfiltration"):
        print(f"  {stage}: {stage_counts.get(stage, 0)} hits")
    print(f"  Unique sessions involved: {len(sessions_hit)}")
    print(f"  Peak severity: {peak_severity.upper()}")
    return found_high


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("log_file", help="Path to Langflow execution log or LLM orchestration log export")
    parser.add_argument("--iocs", metavar="FILE", help="JSON file with supplemental IOCs (tool names, patterns, domains)")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low", help="Minimum alert severity to emit (default: low)")
    args = parser.parse_args()

    rules = {stage: list(stage_rules) for stage, stage_rules in RULES.items()}

    if args.iocs:
        try:
            extra = load_iocs(args.iocs)
            for stage, additions in extra.items():
                rules.setdefault(stage, []).extend(additions)
        except (OSError, json.JSONDecodeError, KeyError) as e:
            print(f"ERROR: Failed to load IOCs from {args.iocs}: {e}", file=sys.stderr)
            sys.exit(2)

    found_high = report_findings(args.log_file, rules, args.severity)
    sys.exit(1 if found_high else 0)


if __name__ == "__main__":
    main()