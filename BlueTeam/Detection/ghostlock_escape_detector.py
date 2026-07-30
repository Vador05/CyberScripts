#!/usr/bin/env python3
"""
GhostLock CVE-2026-43499 Privilege Escalation & Container Escape Detector

Scans auditd or Falco log exports for behavioral signatures of the GhostLock
exploit chain across two kill-chain stages.

Usage:
    python ghostlock_escape_detector.py /var/log/audit/audit.log
    python ghostlock_escape_detector.py falco.log --severity high
    python ghostlock_escape_detector.py audit.log --iocs custom_iocs.json --severity medium

Example IOC JSON:
    {
        "binary_names": ["ghostlock2", "gl_exploit"],
        "socket_paths": ["/run/containerd/custom.sock"],
        "cgroup_paths": ["/sys/fs/cgroup/custom/release_agent"]
    }
"""

import argparse
import json
import re
import sys
from collections import defaultdict, deque

SEVERITY_LEVELS = {"low": 0, "medium": 1, "high": 2}

BUNDLED_BINARY_NAMES = {"ghostlock", "gl_exploit", "cve-2026-43499", "ghostlock_poc"}
BUNDLED_CGROUP_PATHS = {"/release_agent", "/notify_on_release", "cgroup/memory/release_agent"}
BUNDLED_SOCKET_PATHS = {"/var/run/docker.sock", "/run/containerd/containerd.sock", "/run/crio/crio.sock"}
BASELINE_SETUID_ALLOWLIST = {"/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/bin/ping", "/usr/bin/pkexec"}

PRIV_ESC_RULES = [
    {"name": "CLONE_NEWUSER_UNSHARE", "stage": "PrivilegeEscalation", "severity": "high",
     "match": lambda e, _: (e.get("syscall") in ("unshare", "clone")) and "CLONE_NEWUSER" in e.get("raw", "") and e.get("uid", "0") != "0"},
    {"name": "GHOSTLOCK_BINARY_EXEC", "stage": "PrivilegeEscalation", "severity": "high",
     "match": lambda e, iocs: any(b in (e.get("exe", "") + e.get("comm", "") + e.get("proctitle", "")) for b in iocs["binary_names"])},
    {"name": "PROC_SELF_MEM_WRITE", "stage": "PrivilegeEscalation", "severity": "high",
     "match": lambda e, _: "/proc/self/mem" in e.get("raw", "") and e.get("syscall") in ("write", "open", "openat", "pwrite64")},
    {"name": "SUSPICIOUS_SETUID_EXEC", "stage": "PrivilegeEscalation", "severity": "medium",
     "match": lambda e, _: e.get("syscall") in ("execve", "execveat") and e.get("uid", "1000") != "0" and e.get("euid", "") == "0" and e.get("exe", "") not in BASELINE_SETUID_ALLOWLIST},
    {"name": "CAP_SYS_ADMIN_GRANT", "stage": "PrivilegeEscalation", "severity": "high",
     "match": lambda e, _: e.get("falco_rule", "") in ("GhostLock_Exploit", "Privilege_Escalation") or ("cap_sys_admin" in e.get("raw", "").lower() and e.get("uid", "0") != "0")},
    {"name": "FALCO_GHOSTLOCK_RULE", "stage": "PrivilegeEscalation", "severity": "high",
     "match": lambda e, _: "ghostlock" in e.get("falco_rule", "").lower() or "cve-2026-43499" in e.get("raw", "").lower()},
]

CONTAINER_ESCAPE_RULES = [
    {"name": "CGROUP_RELEASE_AGENT_WRITE", "stage": "ContainerEscape", "severity": "high",
     "match": lambda e, iocs: any(p in e.get("raw", "") for p in iocs["cgroup_paths"]) and e.get("syscall") in ("write", "open", "openat", "creat")},
    {"name": "CORE_PATTERN_TAMPER", "stage": "ContainerEscape", "severity": "high",
     "match": lambda e, _: "/proc/sys/kernel/core_pattern" in e.get("raw", "") and e.get("syscall") in ("write", "open", "openat")},
    {"name": "HOST_DEV_ACCESS_FROM_CONTAINER", "stage": "ContainerEscape", "severity": "high",
     "match": lambda e, _: e.get("container_id", "") and re.search(r"/dev/(sda|mem|kmem|port)\b", e.get("raw", "")) and e.get("syscall") in ("open", "openat", "read", "write")},
    {"name": "RUNC_SYMLINK_RACE", "stage": "ContainerEscape", "severity": "high",
     "match": lambda e, _: "runc" in e.get("exe", "") and "/proc/" in e.get("raw", "") and "/exe" in e.get("raw", "")},
    {"name": "FALCO_CONTAINER_ESCAPE", "stage": "ContainerEscape", "severity": "high",
     "match": lambda e, _: e.get("falco_rule", "") in ("container_escape", "privileged_shell_spawned", "Container_Escape")},
    {"name": "NAMESPACE_BREAKOUT_SYSCALL", "stage": "ContainerEscape", "severity": "medium",
     "match": lambda e, _: e.get("syscall") in ("setns", "pivot_root") and e.get("container_id", "")},
]

def parse_auditd_line(line):
    entry = {"raw": line.strip()}
    m = re.match(r"^(?:node=\S+\s+)?type=(\w+)\s+msg=audit\(([^)]+)\):\s*(.*)", line)
    if not m:
        return None
    entry["type"], ts_serial, fields_str = m.group(1), m.group(2), m.group(3)
    ts_parts = ts_serial.split(":")
    entry["timestamp"] = ts_parts[0]
    entry["serial"] = ts_parts[1] if len(ts_parts) > 1 else ""
    for k, v in re.findall(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)', fields_str):
        entry[k.lower()] = v.strip('"')
    if "proctitle" in entry:
        try:
            entry["proctitle"] = bytes.fromhex(entry["proctitle"]).replace(b"\x00", b" ").decode(errors="replace")
        except ValueError:
            pass
    return entry

def parse_falco_line(line):
    m = re.match(r"^(\d{2}:\d{2}:\d{2}\.\d+):\s+(\w+)\s+(.*)", line)
    if not m:
        return None
    entry = {"raw": line.strip(), "timestamp": m.group(1), "type": "FALCO"}
    severity_map = {"Emergency": "high", "Alert": "high", "Critical": "high", "Error": "high", "Warning": "medium", "Notice": "low", "Informational": "low", "Debug": "low"}
    entry["falco_severity"] = severity_map.get(m.group(2), "low")
    rest = m.group(3)
    rule_m = re.match(r"^([A-Za-z_][A-Za-z0-9_\s]+?)\s*(?:\(|evt\.type)", rest)
    if rule_m:
        entry["falco_rule"] = rule_m.group(1).strip().replace(" ", "_")
    for k, v in re.findall(r'(\w+)=<([^>]*)>', rest):
        entry[k.lower()] = v
    container_m = re.search(r'container(?:\.id)?[=\s]+([a-f0-9]{8,})', rest, re.I)
    if container_m:
        entry["container_id"] = container_m.group(1)
    return entry

def parse_log_entries(log_file):
    entries, serial_windows = [], defaultdict(list)
    with open(log_file, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if re.match(r"^\d{2}:\d{2}:\d{2}\.\d+:", line):
                entry = parse_falco_line(line)
            else:
                entry = parse_auditd_line(line)
            if not entry:
                continue
            entries.append(entry)
            if entry.get("serial"):
                serial_windows[entry["serial"]].append(entry)
    for serial, group in serial_windows.items():
        merged = {"raw": " | ".join(e["raw"] for e in group), "serial": serial, "type": "MERGED"}
        for e in group:
            for k, v in e.items():
                if k not in merged:
                    merged[k] = v
        entries.append(merged)
    return entries

def match_rules(entries, iocs):
    findings = []
    for entry in entries:
        for ruleset in (PRIV_ESC_RULES, CONTAINER_ESCAPE_RULES):
            for rule in ruleset:
                try:
                    if rule["match"](entry, iocs):
                        pid = entry.get("pid", entry.get("container_id", "unknown"))
                        findings.append({"stage": rule["stage"], "rule": rule["name"], "severity": rule["severity"],
                                         "pid": pid, "comm": entry.get("comm", entry.get("container_id", "?")),
                                         "timestamp": entry.get("timestamp", ""), "raw": entry["raw"]})
                except (AttributeError, TypeError, KeyError) as e:
                    print(f"[DEBUG] Rule '{rule['name']}' evaluation error: {e}", file=sys.stderr)

    pid_stages = defaultdict(set)
    for f in findings:
        pid_stages[f["pid"]].add(f["stage"])
    for f in findings:
        if pid_stages[f["pid"]] == {"PrivilegeEscalation", "ContainerEscape"}:
            f["severity"] = "high"

    return findings

def report_findings(findings, min_severity):
    min_level = SEVERITY_LEVELS[min_severity]
    seen = deque(maxlen=30)
    stage_counts, unique_ids, peak = defaultdict(int), set(), "low"

    for f in findings:
        if SEVERITY_LEVELS[f["severity"]] < min_level:
            continue
        dedup_key = (f["pid"], f["rule"])
        if dedup_key in seen:
            continue
        seen.append(dedup_key)
        stage_counts[f["stage"]] += 1
        unique_ids.add(f["pid"])
        if SEVERITY_LEVELS[f["severity"]] > SEVERITY_LEVELS[peak]:
            peak = f["severity"]
        truncated = (f["raw"][:137] + "...") if len(f["raw"]) > 140 else f["raw"]
        print(f"[{f['timestamp']}] [{f['severity'].upper()}] {f['stage']} | {f['rule']} | proc={f['comm']} pid={f['pid']} | {truncated}")
    print("\n--- Summary ---")
    for stage, count in stage_counts.items():
        print(f"  {stage}: {count} hit(s)")
    print(f"  Unique process/container IDs flagged: {len(unique_ids)}")
    print(f"  Peak severity: {peak.upper()}")
    return peak == "high"

def main():
    parser = argparse.ArgumentParser(description="GhostLock CVE-2026-43499 Privilege Escalation & Container Escape Detector")
    parser.add_argument("log_file", help="Path to auditd text export or Falco log")
    parser.add_argument("--iocs", help="Path to supplemental JSON IOC file")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low", help="Minimum severity to report (default: low)")
    args = parser.parse_args()
    iocs = {"binary_names": set(BUNDLED_BINARY_NAMES), "cgroup_paths": set(BUNDLED_CGROUP_PATHS), "socket_paths": set(BUNDLED_SOCKET_PATHS)}
    if args.iocs:
        try:
            with open(args.iocs) as f:
                custom = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"[WARNING] Failed to load IOC file: {e}", file=sys.stderr)
        else:
            for key in ("binary_names", "cgroup_paths", "socket_paths"):
                try:
                    items = custom.get(key, [])
                    if isinstance(items, str):
                        items = [items]
                    iocs[key].update(items)
                except (TypeError, ValueError, AttributeError) as e:
                    print(f"[WARNING] IOC file key '{key}' has invalid format: {e}", file=sys.stderr)
    try:
        entries = parse_log_entries(args.log_file)
    except OSError as e:
        print(f"[ERROR] Cannot read log file: {e}", file=sys.stderr)
        sys.exit(2)
    findings = match_rules(entries, iocs)
    high_found = report_findings(findings, args.severity)
    sys.exit(1 if high_found else 0)

if __name__ == "__main__":
    main()