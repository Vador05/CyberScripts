"""
AI IDE Prompt Injection Escape Lab

Simulates and detects zero-click prompt injection sandbox escapes in AI-powered IDEs
by scanning endpoint process logs for anomalous child-process lineage.

Usage:
    python ai_ide_escape_detector.py /var/log/endpoint_procs.log
    python ai_ide_escape_detector.py /var/log/endpoint_procs.log --severity high
    python ai_ide_escape_detector.py /var/log/endpoint_procs.log --patterns extra.json --severity medium

Log format expected (whitespace-delimited or key=value):
    2024-01-15T10:23:45 pid=1234 ppid=567 name=cursor cmd=/bin/bash -c 'curl http://evil.com'
"""

import argparse
import json
import re
import sys
from pathlib import Path

EDITOR_PROCESSES = {"code", "cursor", "windsurf", "copilot-agent", "codeium", "code-server"}

RULES = [
    {
        "name": "shell_interpreter_spawn",
        "stage": "Escape",
        "severity": "high",
        "pattern": r"(?i)(^|/)(?:bash|sh|zsh|fish|dash|ksh|tcsh|csh|cmd\.exe|powershell(?:\.exe)?|pwsh)(\s|$)",
        "mitigation": "Restrict editor extension sandbox via AppArmor/seccomp; disable untrusted workspace execution.",
    },
    {
        "name": "scripting_runtime_spawn",
        "stage": "Escape",
        "severity": "medium",
        "pattern": r"(?i)(^|/)(?:python3?|ruby|perl|node|nodejs|php|lua|tclsh|expect)(\s|$)",
        "mitigation": "Allowlist permitted runtimes in IDE workspace settings; audit extension permissions.",
    },
    {
        "name": "credential_store_read",
        "stage": "Exfiltration",
        "severity": "high",
        "pattern": r"(?i)(\.aws/credentials|\.ssh/id_rsa|\.npmrc|\.pypirc|keychain|secret-tool|kwallet|/etc/passwd|/etc/shadow|HISTFILE|\.bash_history|\.zsh_history)",
        "mitigation": "Encrypt credential stores at rest; use secret managers (Vault, AWS Secrets Manager) instead of plaintext files.",
    },
    {
        "name": "network_exfil_tool",
        "stage": "Exfiltration",
        "severity": "high",
        "pattern": r"(?i)(^|/)(?:curl|wget|nc|ncat|netcat|socat|scp|sftp|ftp|rsync)(\s|$)",
        "mitigation": "Apply egress firewall rules on developer workstations; monitor outbound connections from editor processes.",
    },
    {
        "name": "python_network_flags",
        "stage": "Exfiltration",
        "severity": "medium",
        "pattern": r"(?i)python[23]?\s.*(-c\s+['\"].*(?:urllib|requests|socket|http)|import\s+(?:urllib|requests|socket))",
        "mitigation": "Sandbox inline Python execution in extensions; disable -c flag execution via process policy.",
    },
    {
        "name": "prompt_injection_ignore_previous",
        "stage": "Injection",
        "severity": "high",
        "pattern": r"(?i)ignore\s+(previous|prior|all\s+previous|above)\s+(instructions?|prompts?|context)",
        "mitigation": "Implement prompt injection filters on AI IDE agent input; never render untrusted file content as instructions.",
    },
    {
        "name": "prompt_injection_system_tag",
        "stage": "Injection",
        "severity": "high",
        "pattern": r"(?i)(system\s*:|<\s*system\s*>|\[SYSTEM\]|\bSYSTEM\b\s*:)",
        "mitigation": "Sanitize workspace file content before passing to LLM context; use structured message formats with clear boundaries.",
    },
    {
        "name": "prompt_injection_inst_delimiter",
        "stage": "Injection",
        "severity": "medium",
        "pattern": r"(\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>|\[CONTEXT\]|\[OVERRIDE\])",
        "mitigation": "Detect and strip model-specific delimiter tokens from user-supplied content before LLM submission.",
    },
    {
        "name": "encoded_payload",
        "stage": "Escape",
        "severity": "medium",
        "pattern": r"(?i)(base64\s+-d|echo\s+[A-Za-z0-9+/]{20,}={0,2}\s*\|\s*(?:bash|sh|python)|eval\s+\$\(|exec\s+\()",
        "mitigation": "Block eval/exec of base64-decoded payloads via static analysis hooks in the IDE extension sandbox.",
    },
]

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

LOG_PATTERN = re.compile(
    r"(?P<ts>\S+)\s+.*?pid[=:\s](?P<pid>\d+).*?ppid[=:\s](?P<ppid>\d+).*?name[=:\s](?P<name>\S+).*?cmd[=:\s](?P<cmd>.+)",
    re.IGNORECASE,
)


def parse_log_entries(log_path):
    entries = []
    try:
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                m = LOG_PATTERN.match(line)
                if not m:
                    continue
                entries.append({
                    "ts": m.group("ts"),
                    "pid": m.group("pid"),
                    "ppid": m.group("ppid"),
                    "name": m.group("name").lower(),
                    "cmd": m.group("cmd").strip(),
                    "lineno": lineno,
                })
    except OSError as exc:
        print(f"ERROR: Cannot read log file: {exc}", file=sys.stderr)
        sys.exit(2)
    return entries


def load_supplemental_patterns(patterns_path):
    try:
        with open(patterns_path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("editor_processes", []), data.get("rules", [])
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: Cannot load patterns file: {exc}", file=sys.stderr)
        sys.exit(2)


def match_rules(entries, extra_editors=None, extra_rules=None):
    editors = EDITOR_PROCESSES | set(e.lower() for e in (extra_editors or []))
    rules = RULES + (extra_rules or [])
    findings = []
    compiled = [(r, re.compile(r["pattern"])) for r in rules]
    for entry in entries:
        if entry["name"] not in editors:
            continue
        for rule, regex in compiled:
            if regex.search(entry["cmd"]):
                findings.append({**entry, "rule": rule["name"], "stage": rule["stage"],
                                  "severity": rule["severity"], "mitigation": rule["mitigation"]})
    return findings


def report_findings(findings, min_severity):
    min_rank = SEVERITY_RANK.get(min_severity, 0)
    stage_counts = {}
    peak = "low"
    emitted = 0
    for f in findings:
        if SEVERITY_RANK.get(f["severity"], 0) < min_rank:
            continue
        emitted += 1
        stage_counts[f["stage"]] = stage_counts.get(f["stage"], 0) + 1
        if SEVERITY_RANK.get(f["severity"], 0) > SEVERITY_RANK.get(peak, 0):
            peak = f["severity"]
        cmd_truncated = f["cmd"][:120]
        print(f"[{f['severity'].upper()}] stage={f['stage']} rule={f['rule']} "
              f"editor={f['name']}(pid={f['pid']}) cmd={cmd_truncated!r}")
        print(f"  MITIGATION: {f['mitigation']}")
    print()
    print("=== Summary ===")
    if stage_counts:
        for stage, count in sorted(stage_counts.items()):
            print(f"  {stage}: {count} hit(s)")
        print(f"  Peak severity: {peak.upper()}")
    else:
        print("  No findings matched the specified severity threshold.")
    return peak == "high" and emitted > 0


def main():
    parser = argparse.ArgumentParser(
        description="Detect zero-click prompt injection sandbox escapes in AI IDE process logs.",
        epilog="Example: python ai_ide_escape_detector.py /var/log/procs.log --severity medium",
    )
    parser.add_argument("log_file", help="Path to plain-text endpoint process log")
    parser.add_argument("--patterns", metavar="FILE", help="JSON file with supplemental editor names and rules")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum alert severity to emit (default: low)")
    args = parser.parse_args()

    extra_editors, extra_rules = [], []
    if args.patterns:
        extra_editors, extra_rules = load_supplemental_patterns(args.patterns)

    entries = parse_log_entries(args.log_file)
    if not entries:
        print("No parseable log entries found.", file=sys.stderr)
        sys.exit(0)

    findings = match_rules(entries, extra_editors, extra_rules)
    had_high = report_findings(findings, args.severity)
    sys.exit(1 if had_high else 0)


if __name__ == "__main__":
    main()