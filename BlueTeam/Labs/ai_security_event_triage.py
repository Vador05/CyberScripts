"""
AI Security Event Triage Pipeline — score, deduplicate, and priority-rank security log events.

Usage:
    python ai_security_event_triage.py /var/log/auth.log
    python ai_security_event_triage.py auth.log --threshold 50 --top 20
"""

import argparse, re, sys
from collections import defaultdict
from datetime import datetime

SIGNALS = [
    ("CRED_FAILED_AUTH",    r"(?i)failed (password|login)|authentication failure|invalid (user|credentials?)", 15, "CREDENTIAL_ABUSE"),
    ("CRED_INVALID_USER",   r"(?i)invalid user \S+ from", 10, "CREDENTIAL_ABUSE"),
    ("PRIV_SUDO",           r"(?i)sudo[:\[].{0,80}(root|/bin/(ba)?sh)", 25, "PRIVILEGE_ESCALATION"),
    ("PRIV_SU_ROOT",        r"(?i)\bsu\b.{0,40}root", 20, "PRIVILEGE_ESCALATION"),
    ("PRIV_ADMIN_GROUP",    r"(?i)(usermod|groupmod|useradd).{0,60}(sudo|wheel|admin|root)", 20, "PRIVILEGE_ESCALATION"),
    ("PRIV_SETUID",         r"(?i)(chmod [ugo+]+s|setuid|setgid)", 20, "PRIVILEGE_ESCALATION"),
    ("LAT_SSH_INTERNAL",    r"(?i)accepted (password|publickey) for .+ from (10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)", 25, "LATERAL_MOVEMENT"),
    ("LAT_SERVICE_INSTALL", r"(?i)(systemctl (enable|start)|insserv).{0,60}(service|daemon)", 15, "LATERAL_MOVEMENT"),
    ("LAT_REMOTE_SCHED",    r"(?i)(crontab|at\[|schtasks).{0,60}(wget|curl|bash|python|nc\b)", 20, "LATERAL_MOVEMENT"),
    ("LAT_SSH_ACCEPTED",    r"(?i)accepted (password|publickey) for \S+ from", 10, "LATERAL_MOVEMENT"),
]

TS_PATS = [re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"), re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")]
HOST_PAT = re.compile(r"from\s+([\d\.]+)")
USER_PAT = re.compile(r"(?:for|user)\s+(\S+)")
COMPILED = [(t, re.compile(p), w, c) for t, p, w, c in SIGNALS]


def parse_line(line):
    ts = ""
    for p in TS_PATS:
        m = p.match(line)
        if m: ts = m.group(1); break
    hm, um = HOST_PAT.search(line), USER_PAT.search(line)
    return ts, (hm.group(1) if hm else "unknown"), (um.group(1) if um else "")


def score_event(line, host, user, host_counts, user_counts):
    tags, score, category = [], 0, "GENERIC"
    for tag, pat, weight, cat in COMPILED:
        if pat.search(line):
            tags.append(tag)
            score += weight
            if len(tags) == 1: category = cat
    if host_counts.get(host, 0) >= 5:
        score += 15; tags.append("BURST_HOST")
    if host_counts.get(host, 0) >= 20:
        score += 10; tags.append("BURST_EXTREME")
    if user and user_counts.get(user, 0) >= 3:
        score += 10; tags.append("ACCOUNT_TARGET")
    return min(score, 100), category, tags


def time_bucket(ts):
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
        try:
            dt = datetime.strptime(ts.strip(), fmt)
            return dt.strftime(f"%Y%m%d%H{(dt.minute // 5) * 5:02d}")
        except ValueError: continue
    return ts[:13]


def deduplicate_and_rank(scored):
    groups = defaultdict(list)
    for entry in scored:
        score, cat, tags, ts, host, line = entry
        groups[f"{host}|{cat}|{time_bucket(ts)}"].append(entry)
    result = []
    for entries in groups.values():
        best = max(entries, key=lambda e: e[0])
        result.append((*best, len(entries)))
    return sorted(result, key=lambda e: e[0], reverse=True)


def emit_report(deduped, threshold, top, total_raw):
    cats, buckets = defaultdict(int), [0] * 5
    emitted, noise_suppressed, cap_suppressed = 0, 0, 0
    critical = any(score >= 80 for score, _, _, _, _, _, _ in deduped)
    cap = top or len(deduped)
    for score, cat, tags, ts, host, line, count in deduped:
        if score < threshold:
            noise_suppressed += 1
            continue
        if emitted >= cap:
            cap_suppressed += 1
            continue
        cats[cat] += 1
        buckets[min(score // 20, 4)] += 1
        cnt_str = f" (x{count})" if count > 1 else ""
        print(f"[{score:3d}/100] [{cat}] {ts} | {','.join(tags) or 'GENERIC'} | {line[:120]}{cnt_str}")
        emitted += 1
    top_cat = max(cats, key=cats.get) if cats else "N/A"
    print("\n--- Triage Summary ---")
    print(f"Total scanned    : {total_raw}")
    print(f"Alerts emitted   : {emitted}")
    print(f"Noise suppressed : {noise_suppressed}")
    if top:
        print(f"Output limited   : {cap_suppressed}")
    print(f"Top category     : {top_cat}")
    print("Score distribution:")
    for lbl, cnt in zip(["0-19", "20-39", "40-59", "60-79", "80-100"], buckets):
        print(f"  {lbl:7s} {'#' * cnt} ({cnt})")
    return critical


def main():
    ap = argparse.ArgumentParser(description="AI Security Event Triage Pipeline")
    ap.add_argument("log_file", help="Path to plain-text log file (syslog, auth.log, JSON-per-line)")
    ap.add_argument("--threshold", type=int, default=30, help="Minimum triage score 0-100 to emit (default: 30)")
    ap.add_argument("--top", type=int, default=0, help="Emit only top N events after deduplication; 0=unlimited")
    args = ap.parse_args()

    if args.top < 0:
        ap.error("--top must be non-negative")

    host_counts, user_counts, raw_events = defaultdict(int), defaultdict(int), []
    try:
        with open(args.log_file, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line.strip(): continue
                ts, host, user = parse_line(line)
                host_counts[host] += 1
                if user: user_counts[user] += 1
                raw_events.append((ts, host, user, line))
    except OSError as e:
        print(f"Error reading {args.log_file!r}: {e}", file=sys.stderr); sys.exit(2)

    scored = [(s, c, t, ts, h, l) for ts, h, u, l in raw_events
              for s, c, t in [score_event(l, h, u, host_counts, user_counts)] if s > 0]
    deduped = deduplicate_and_rank(scored)
    sys.exit(1 if emit_report(deduped, args.threshold, args.top, len(raw_events)) else 0)


if __name__ == "__main__":
    main()