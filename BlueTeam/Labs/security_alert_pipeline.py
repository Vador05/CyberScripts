"""
Security Log Alert Pipeline Lab — apply detection rules to log files.

Usage:
    python security_alert_pipeline.py /var/log/auth.log
    python security_alert_pipeline.py auth.log --severity high
    python security_alert_pipeline.py auth.log --rules custom_rules.json

Custom rule JSON: [{"name":"X","severity":"high","pattern":"regex","co_pattern":"opt"}]
"""

import argparse
import json
import re
import sys
from collections import defaultdict, deque

BUNDLED_RULES = [
    {"name": "CREDENTIAL_STUFFING", "severity": "high",
     "pattern": r"(?i)(failed password|authentication failure|invalid credentials?).*from\s+[\d\.]+",
     "co_pattern": r"(?i)(accepted password|session opened|authentication success)"},
    {"name": "BRUTE_FORCE_AUTH", "severity": "medium",
     "pattern": r"(?i)(failed password|invalid user|authentication failure)"},
    {"name": "LATERAL_MOVEMENT_SSH", "severity": "high",
     "pattern": r"(?i)accepted (password|publickey) for \S+ from [\d\.:]+",
     "co_pattern": r"(?i)(new session|session opened|sudo|su\[)"},
    {"name": "PRIVILEGE_ESCALATION", "severity": "high",
     "pattern": r"(?i)(sudo|su\[|pkexec).{0,60}(root|/bin/bash|/bin/sh|/bin/su)"},
    {"name": "ACCOUNT_MANIPULATION", "severity": "medium",
     "pattern": r"(?i)(useradd|usermod|groupadd|passwd).{0,60}(root|sudo|wheel|admin)"},
    {"name": "SUSPICIOUS_CRON", "severity": "medium",
     "pattern": r"(?i)(crontab|cron\[).{0,60}(wget|curl|bash|sh\b|python|perl|nc\b)"},
    {"name": "REMOTE_CODE_EXEC", "severity": "high",
     "pattern": r"(?i)(exec|eval|shell_exec).{0,60}(wget|curl|http|/tmp|base64)"},
]

SEVERITIES = {"low": 0, "medium": 1, "high": 2}
TS_PATS = [
    re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*)(.*)"),
    re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})(.*)"),
]


def parse_log_events(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                raw = raw.rstrip("\n")
                if not raw.strip():
                    continue
                ts, msg = "", raw
                for pat in TS_PATS:
                    m = pat.match(raw)
                    if m:
                        ts, msg = m.group(1), m.group(2).strip()
                        break
                else:
                    try:
                        obj = json.loads(raw)
                        msg = obj.get("message") or obj.get("msg") or raw
                        ts = str(obj.get("timestamp") or obj.get("time") or "")
                    except (json.JSONDecodeError, AttributeError):
                        pass
                yield {"raw_line": raw, "timestamp_str": ts, "message": msg}
    except OSError as exc:
        sys.exit(f"ERROR: cannot open log file: {exc}")


def compile_rules(raw_rules):
    out = []
    for i, r in enumerate(raw_rules):
        if not isinstance(r, dict):
            print(f"WARNING: skipping rule[{i}] — not a dict", file=sys.stderr)
            continue
        name = r.get("name") or f"rule[{i}]"
        pattern = r.get("pattern")
        if pattern is None:
            print(f"WARNING: skipping rule '{name}' — missing required 'pattern' field", file=sys.stderr)
            continue
        try:
            e = dict(r)
            e["_pat"] = re.compile(pattern)
            co_pattern = r.get("co_pattern")
            if co_pattern is not None:
                e["_co_pat"] = re.compile(co_pattern)
            out.append(e)
        except (re.error, KeyError, TypeError, AttributeError) as exc:
            print(f"WARNING: skipping rule '{name}' — {exc}", file=sys.stderr)
    return out


def apply_detections(events, rules):
    windows = defaultdict(deque)
    for event in events:
        text = event["message"] or event["raw_line"]
        for rule in rules:
            co = rule.get("_co_pat")
            if co:
                win = windows[rule["name"]]
                win.append(text)
                if len(win) > 10:
                    win.popleft()
            if rule["_pat"].search(text):
                correlated = co is not None and any(co.search(ln) for ln in windows[rule["name"]])
                yield {"rule": rule["name"], "severity": rule["severity"],
                       "timestamp": event["timestamp_str"], "snippet": text[:120],
                       "correlated": correlated}


def report_alerts(alerts, min_severity):
    min_level = SEVERITIES.get(min_severity, 0)
    counts = defaultdict(int)
    any_high = False
    for alert in alerts:
        counts[alert["rule"]] += 1
        if SEVERITIES.get(alert["severity"], 0) >= min_level:
            prefix = "[CORRELATED] " if alert["correlated"] else ""
            ts = alert["timestamp"] or "no-timestamp"
            print(f"{prefix}[{alert['severity'].upper()}] {alert['rule']} | {ts} | {alert['snippet']}")
            if alert["severity"] == "high":
                any_high = True
    print("\n--- Detection Summary ---")
    for rule, count in sorted(counts.items()):
        print(f"  {rule}: {count} hit(s)")
    print(f"  Total alerts: {sum(counts.values())}")
    if any_high:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("log_file", help="Path to the plain-text log file to scan")
    parser.add_argument("--rules", metavar="FILE", help="JSON file with custom detection rules to merge")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum severity to emit (default: low)")
    args = parser.parse_args()

    rules = list(BUNDLED_RULES)
    if args.rules:
        try:
            with open(args.rules, encoding="utf-8") as fh:
                custom = json.load(fh)
            if not isinstance(custom, list):
                sys.exit("ERROR: --rules file must be a JSON array")
            rules.extend(custom)
        except (OSError, json.JSONDecodeError) as exc:
            sys.exit(f"ERROR: cannot load rules file: {exc}")

    report_alerts(apply_detections(parse_log_events(args.log_file), compile_rules(rules)), args.severity)


if __name__ == "__main__":
    main()