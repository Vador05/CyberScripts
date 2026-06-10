#!/usr/bin/env python3
"""Container Escape & Privesc Detector

Parses Linux audit and syslog plaintext output to detect exploitation
signatures associated with kernel privilege-escalation and container
breakout techniques (nf_tables UAF, runc/OverlayFS escapes, capability abuse).

Usage:
    python container_escape_detector.py /var/log/audit/audit.log
    python container_escape_detector.py - --mode detect --severity high
    python container_escape_detector.py /dev/null --mode lab
    journalctl --no-pager | python container_escape_detector.py - --severity low
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone

RULES = [
    ("nsenter_container_escape", "high",
     re.compile(r"nsenter|setns.*(?:pid|mnt|net)")),
    ("unshare_namespace_escape", "medium",
     re.compile(r"\bunshare\b.*(?:--mount|--pid|--net|-[mpn]\b)")),
    ("cap_sys_admin_grant", "high",
     re.compile(r"cap_effective=(?:3fffffffff|1ffffffffff|ffffffffffffffff)")),
    ("nf_tables_netlink_write", "high",
     re.compile(r"nf_tables|nfnetlink.*(?:write|sendmsg)|NFNL_SUBSYS")),
    ("proc_self_mem_write", "high",
     re.compile(r"/proc/(?:self|\d+)/mem")),
    ("overlay_upperdir_traversal", "medium",
     re.compile(r"upperdir.*\.\./|ovl_copy_up|overlayfs.*escape")),
    ("runc_fd_escape", "high",
     re.compile(r"runc.*(?:/proc/self/exe|memfd_create)|memfd.*runc")),
    ("cgroup_release_agent_escape", "medium",
     re.compile(r"release_agent|notify_on_release")),
]

_SEV = {"low": 0, "medium": 1, "high": 2}

_AUDIT_RE = re.compile(
    r"audit\((?P<ts>\d+\.\d+):\d+\).*?"
    r"(?:pid=(?P<pid>\d+))?.*?"
    r"(?:comm=\"(?P<comm>[^\"]+)\")?.*?"
    r"(?:name=\"(?P<path>[^\"]+)\")?",
    re.DOTALL,
)
_SYSLOG_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"(?P<comm>[^\s\[]+)(?:\[(?P<pid>\d+)\])?:"
)

LAB_EVENTS = [
    'type=SYSCALL msg=audit(1717401600.001:1): arch=c000003e syscall=308 success=yes '
    'pid=9001 comm="nsenter" exe="/usr/bin/nsenter" name="/proc/1/ns/pid"',
    'Jun  3 10:00:01 host bash[9002]: unshare --mount --pid --net /bin/bash',
    'type=CAPSET msg=audit(1717401602.003:3): cap_effective=3fffffffff pid=9003 comm="exploit"',
    'type=SYSCALL msg=audit(1717401603.004:4): pid=9004 comm="nft" key="nf_tables NFNL_SUBSYS write"',
    'type=OPENAT msg=audit(1717401604.005:5): pid=9005 comm="memwrv" name="/proc/self/mem"',
    'type=SYSCALL msg=audit(1717401605.006:6): pid=9006 comm="ovl_esc" '
    'name="/overlay2/upperdir/../../etc/passwd"',
    'type=EXECVE msg=audit(1717401606.007:7): pid=9007 comm="runc" '
    'name="/proc/self/exe" key="runc memfd_create escape"',
    'Jun  3 10:00:07 host sh[9008]: echo 1 > /sys/fs/cgroup/memory/release_agent',
    'Jun  3 10:00:08 host kernel: clean line with no IOCs — should not fire',
]


def parse_log(line):
    m = _AUDIT_RE.search(line)
    if m and m.group("ts"):
        try:
            ts = datetime.fromtimestamp(float(m.group("ts")), tz=timezone.utc).isoformat()
        except (ValueError, OSError):
            ts = m.group("ts")
        return {
            "timestamp": ts,
            "pid": m.group("pid") or "",
            "comm": m.group("comm") or "",
            "raw": line,
        }
    m = _SYSLOG_RE.search(line)
    if m:
        return {
            "timestamp": m.group("ts"),
            "pid": m.group("pid") or "",
            "comm": m.group("comm"),
            "raw": line,
        }
    return {"timestamp": "", "pid": "", "comm": "", "raw": line} if line.strip() else None


def detect(event, min_severity):
    for name, severity, pattern in RULES:
        if _SEV[severity] < _SEV[min_severity]:
            continue
        if pattern.search(event["raw"]):
            return {
                "timestamp": event["timestamp"],
                "rule": name,
                "severity": severity,
                "pid": event["pid"],
                "comm": event["comm"],
                "evidence": event["raw"].strip(),
            }
    return None


def main():
    ap = argparse.ArgumentParser(
        description="Detect container escape and kernel privesc from audit/syslog"
    )
    ap.add_argument("logfile", help="Path to log file or '-' for stdin")
    ap.add_argument("--mode", choices=["detect", "lab"], default="detect")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="medium")
    args = ap.parse_args()

    alerted = False

    def iter_lines():
        if args.mode == "lab":
            yield from LAB_EVENTS
            return
        try:
            fh = open(args.logfile) if args.logfile != "-" else sys.stdin
        except OSError as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(2)
        try:
            for line in fh:
                yield line.rstrip("\n")
        except OSError as e:
            print(f"read error: {e}", file=sys.stderr)
        finally:
            if fh is not sys.stdin:
                fh.close()

    for line in iter_lines():
        event = parse_log(line)
        if event is None:
            continue
        alert = detect(event, args.severity)
        if alert:
            print(json.dumps(alert))
            alerted = True

    sys.exit(1 if alerted else 0)


if __name__ == "__main__":
    main()
