#!/usr/bin/env python3
"""
snap-confine CVE-2026-8933 Local Privilege Escalation Detector

Scans plain-text auditd or AppArmor log exports for behavioral signatures of
CVE-2026-8933 snap-confine LPE exploitation across Trigger and PostEscalation
kill-chain stages.

Usage:
    python snap_confine_lpe_detector.py /var/log/audit/audit.log
    python snap_confine_lpe_detector.py apparmor.log --severity medium
    python snap_confine_lpe_detector.py audit.log --iocs custom_iocs.json --severity high

Example IOC JSON:
    {
        "exploit_binaries": ["snap_poc", "cve-2026-8933"],
        "suspicious_snap_paths": ["/snap/malicious/current"],
        "authorized_snapd_parents": ["systemd", "snapd", "init"]
    }
"""

import argparse
import json
import re
import sys
from collections import defaultdict, deque

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
DEFAULT_SNAPD_PARENTS = {"snapd", "systemd", "init", "launchd", "upstart"}
SNAP_CONFINE = "snap-confine"

TRIGGER_RULES = [
    {"name": "SNAP_CONFINE_UNEXPECTED_PARENT", "stage": "Trigger", "severity": "low",
     "match": lambda e, iocs, _: (SNAP_CONFINE in e.get("exe", "") or any(eb in e.get("exe", "") for eb in iocs["exploit_binaries"])) and e.get("comm_parent", e.get("pcomm", "")) not in iocs["authorized_snapd_parents"] and e.get("syscall") in ("execve", "execveat")},
    {"name": "SNAP_CONFINE_SUID_ELEVATION", "stage": "Trigger", "severity": "medium",
     "match": lambda e, iocs, _: (SNAP_CONFINE in e.get("exe", "") or any(eb in e.get("exe", "") for eb in iocs["exploit_binaries"])) and e.get("uid", "0") not in ("0", "") and e.get("euid", "") == "0" and e.get("comm_parent", e.get("pcomm", "")) not in iocs["authorized_snapd_parents"]},
    {"name": "SNAP_CONFINE_NAMESPACE_CLONE", "stage": "Trigger", "severity": "medium",
     "match": lambda e, iocs, snap_pids: e.get("pid") in snap_pids and e.get("syscall") in ("unshare", "clone") and re.search(r"CLONE_NEW(NS|USER)", e.get("raw", "")) and e.get("comm", "") not in iocs["authorized_snapd_parents"]},
]

POST_ESC_RULES = [
    {"name": "ROOT_SHELL_FROM_SNAP_CONFINE", "stage": "PostEscalation", "severity": "high",
     "match": lambda e, _, snap_pids: e.get("euid", "") == "0" and e.get("ppid") in snap_pids and e.get("exe", "") in ("/bin/sh", "/bin/bash", "/usr/bin/bash", "/usr/bin/sh") and e.get("syscall") in ("execve", "execveat")},
    {"name": "SUSPICIOUS_PATH_WRITE_BY_ROOT", "stage": "PostEscalation", "severity": "high",
     "match": lambda e, iocs, snap_pids: e.get("euid", "") == "0" and e.get("uid", "0") != "0" and e.get("pid") in snap_pids and (re.search(r"(/tmp/|/var/lib/snapd/)", e.get("raw", "")) or any(sp in e.get("raw", "") for sp in iocs["suspicious_snap_paths"])) and e.get("syscall") in ("write", "open", "openat", "creat")},
    {"name": "APPARMOR_PERMIT_AFTER_DENY", "stage": "PostEscalation", "severity": "high",
     "match": lambda e, _, __: SNAP_CONFINE in e.get("profile", "") and e.get("apparmor_decision") == "PERMITTED_AFTER_DENY"},
]

KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
AA_RE = re.compile(r'apparmor="(\w+)".*?profile="([^"]+)"')
TS_RE = re.compile(r'audit\((\d+\.\d+):(\d+)\)')


def parse_kv(line):
    return {k: v.strip('"') for k, v in KV_RE.findall(line)}


def parse_log_entries(path):
    sessions = defaultdict(dict)
    apparmor_window = deque(maxlen=50)
    entries = []
    with open(path, errors="replace") as fh:
        for raw in fh:
            raw = raw.rstrip()
            aa = AA_RE.search(raw)
            if aa or "apparmor=" in raw:
                decision = aa.group(1) if aa else ""
                profile = aa.group(2) if aa else ""
                apparmor_window.append({"type": "apparmor", "raw": raw, "apparmor_decision": decision, "profile": profile, "syscall": "", "uid": "", "euid": "", "pid": "", "ppid": "", "exe": "", "comm": "", "pcomm": "", "comm_parent": ""})
                for prev in list(apparmor_window)[:-1]:
                    if prev.get("profile") == profile and prev.get("apparmor_decision") == "DENIED" and decision in ("PERMITTED", "ALLOWED"):
                        entries.append({**apparmor_window[-1], "apparmor_decision": "PERMITTED_AFTER_DENY"})
                        break
                else:
                    entries.append(apparmor_window[-1])
                continue
            ts_m = TS_RE.search(raw)
            if not ts_m:
                continue
            serial = ts_m.group(2)
            fields = parse_kv(raw)
            rec_type = fields.get("type", re.search(r"type=(\w+)", raw).group(1) if re.search(r"type=(\w+)", raw) else "")
            sessions[serial].update(fields)
            sessions[serial]["raw"] = sessions[serial].get("raw", "") + " " + raw
            sessions[serial]["ts"] = ts_m.group(1)
            sessions[serial]["type"] = sessions[serial].get("type", rec_type)
            if rec_type in ("SYSCALL", "EXECVE", "PATH", "CWD"):
                s = sessions[serial]
                entries.append({"type": rec_type, "raw": raw, "ts": s.get("ts", ""), "syscall": s.get("syscall", ""), "uid": s.get("uid", ""), "euid": s.get("euid", ""), "pid": s.get("pid", ""), "ppid": s.get("ppid", ""), "exe": s.get("exe", ""), "comm": s.get("comm", ""), "pcomm": s.get("pcomm", ""), "comm_parent": s.get("pcomm", ""), "apparmor_decision": "", "profile": ""})
    return entries


def load_iocs(path):
    base = {"exploit_binaries": set(), "suspicious_snap_paths": set(), "authorized_snapd_parents": set(DEFAULT_SNAPD_PARENTS)}
    if not path:
        return base
    with open(path) as fh:
        data = json.load(fh)
    base["exploit_binaries"].update(data.get("exploit_binaries", []))
    base["suspicious_snap_paths"].update(data.get("suspicious_snap_paths", []))
    base["authorized_snapd_parents"].update(data.get("authorized_snapd_parents", []))
    return base


def main():
    ap = argparse.ArgumentParser(description="snap-confine CVE-2026-8933 LPE Detector")
    ap.add_argument("log_file", help="Path to auditd text export or AppArmor log")
    ap.add_argument("--iocs", help="Path to supplemental IOC JSON file")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low", help="Minimum severity to emit (default: low)")
    args = ap.parse_args()

    try:
        iocs = load_iocs(args.iocs)
        entries = parse_log_entries(args.log_file)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(2)

    snap_pids = set()
    for entry in entries:
        if SNAP_CONFINE in entry.get("exe", "") and entry.get("pid"):
            snap_pids.add(entry["pid"])

    dedup = deque(maxlen=30)
    counts = defaultdict(int)
    seen_pids = set()
    seen_uid_pairs = set()
    peak = "low"
    any_high = False
    min_rank = SEVERITY_RANK[args.severity]
    all_rules = TRIGGER_RULES + POST_ESC_RULES

    for entry in entries:
        for rule in all_rules:
            if SEVERITY_RANK[rule["severity"]] < min_rank:
                continue
            try:
                hit = rule["match"](entry, iocs, snap_pids)
            except Exception:
                continue
            if not hit:
                continue
            dedup_key = (entry.get("pid", ""), rule["name"])
            if dedup_key in dedup:
                continue
            dedup.append(dedup_key)
            pid = entry.get("pid", "-")
            uid = entry.get("uid", "-")
            euid = entry.get("euid", "-")
            ts = entry.get("ts", "?")
            verb = entry.get("raw", "")[:140]
            sev = rule["severity"]
            stage = rule["stage"]
            if SEVERITY_RANK[sev] > SEVERITY_RANK[peak]:
                peak = sev
            if sev == "high":
                any_high = True
            counts[stage] += 1
            seen_pids.add(pid)
            seen_uid_pairs.add((uid, euid))
            print(f"[{ts}] [{stage}] [{sev.upper()}] {rule['name']} proc={entry.get('comm', '-')} pid={pid} uid={uid} euid={euid} | {verb}")

    print(f"\n--- Summary ---")
    for stage, n in counts.items():
        print(f"  {stage}: {n} hit(s)")
    print(f"  Unique PIDs flagged: {len(seen_pids)}")
    print(f"  Unique UID->EUID pairs: {len(seen_uid_pairs)}")
    print(f"  Peak severity: {peak.upper()}")
    sys.exit(1 if any_high else 0)


if __name__ == "__main__":
    main()