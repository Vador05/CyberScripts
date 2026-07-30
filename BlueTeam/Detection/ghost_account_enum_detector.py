"""
Ghost Account GitHub Org Enumeration Detector

Analyzes GitHub API access logs to identify ghost and newly-created accounts
performing rapid enumeration of organization members and repositories.

Usage:
    python ghost_account_enum_detector.py access.log --org myorg --age-days 30
    python ghost_account_enum_detector.py access.log --org myorg
    python ghost_account_enum_detector.py access.log
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import parse_qs

TS_FMTS = ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S")


def parse_ts(s):
    for fmt in TS_FMTS:
        try:
            return datetime.strptime(s.strip(), fmt).replace(tzinfo=None)
        except ValueError:
            pass
    return None


def parse_entries(log_path, age_days):
    entries, dropped = [], 0
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                ts = parse_ts(str(r.get("timestamp", "")))
                actor = str(r.get("actor_login", "")).strip()
                created = parse_ts(str(r.get("account_created_at", "")))
                path = str(r.get("path", ""))
                qs = str(r.get("query_string", ""))
                status = int(r.get("status_code") or r.get("status") or 0)
                if not ts or not actor:
                    dropped += 1
                    continue
                age = (now - created).days if created else None
                entries.append({
                    "ts": ts, "actor": actor, "age": age,
                    "ghost": age is not None and age < age_days,
                    "path": path, "qs": qs, "status": status,
                })
            except (json.JSONDecodeError, ValueError, TypeError):
                dropped += 1
    return entries, dropped


def _is_members(path, org):
    return (f"/orgs/{org}/members" in path) if org else ("/orgs/" in path and "/members" in path)


def _is_repos(path, org):
    return (f"/orgs/{org}/repos" in path) if org else ("/orgs/" in path and "/repos" in path)


def detect_ghost_enum(entries, org):
    by_actor = defaultdict(list)
    for e in entries:
        by_actor[e["actor"]].append(e)

    for actor, evts in by_actor.items():
        evts.sort(key=lambda x: x["ts"])
        org_evts = [e for e in evts if _is_members(e["path"], org) or _is_repos(e["path"], org)]

        for anchor in org_evts:
            window = [e for e in org_evts if 0 <= (e["ts"] - anchor["ts"]).total_seconds() < 60]
            if len(window) > 20:
                sev = "high" if anchor["ghost"] else "medium"
                yield ("GhostAccountBurst", sev, actor, anchor["age"], anchor["path"], anchor["status"], anchor["ts"])
                break

        paged = []
        for e in org_evts:
            params = parse_qs(e["qs"])
            pg = params.get("page", [None])[0] or params.get("per_page", [None])[0]
            if pg is not None:
                try:
                    paged.append((e["ts"], int(pg), e))
                except ValueError:
                    pass
        for i in range(len(paged)):
            t0, _, e0 = paged[i]
            win_pages = [p for t, p, _ in paged[i:] if (t - t0).total_seconds() < 120]
            if len(win_pages) >= 3 and all(win_pages[j] < win_pages[j+1] for j in range(len(win_pages)-1)):
                sev = "high" if e0["ghost"] else "medium"
                yield ("PaginationSweep", sev, actor, e0["age"], e0["path"], e0["status"], e0["ts"])
                break

        mem_evts = [e for e in evts if _is_members(e["path"], org)]
        rep_evts = [e for e in evts if _is_repos(e["path"], org)]
        for me in mem_evts:
            for repo_e in rep_evts:
                if abs((me["ts"] - repo_e["ts"]).total_seconds()) < 60:
                    anchor = me if me["ts"] <= repo_e["ts"] else repo_e
                    yield ("CrossEndpointCampaign", "high", actor, anchor["age"],
                           anchor["path"], anchor["status"], anchor["ts"])
                    break
            else:
                continue
            break


def report_findings(alerts, age_days, dropped):
    counts = defaultdict(int)
    actor_sets = defaultdict(set)
    ghost_actors = set()
    dedup_burst = {}
    exit_nonzero = False
    peak = "none"

    for sig, sev, actor, age, path, status, ts in alerts:
        if sig == "GhostAccountBurst":
            last = dedup_burst.get(actor)
            if last and (ts - last).total_seconds() < 60:
                continue
            dedup_burst[actor] = ts

        counts[sig] += 1
        actor_sets[sig].add(actor)
        if age is not None and age < age_days:
            ghost_actors.add(actor)
        if peak == "none" or (sev == "high" and peak != "high"):
            peak = sev
        if sig in ("GhostAccountBurst", "CrossEndpointCampaign"):
            exit_nonzero = True

        age_str = str(age) if age is not None else "unknown"
        print(f"[{sig}] sev={sev} actor={actor} age_days={age_str} path={path} status={status} ts={ts.strftime('%Y-%m-%dT%H:%M:%S')}")

    all_actors = set().union(*actor_sets.values()) if actor_sets else set()
    established = all_actors - ghost_actors
    print("\n--- Summary ---")
    for sig, cnt in counts.items():
        print(f"  {sig}: {cnt} alert(s), {len(actor_sets[sig])} unique actor(s)")
    print(f"  Unique actors: {len(all_actors)} | ghost/new: {len(ghost_actors)} | established: {len(established)}")
    print(f"  Peak severity: {peak}")
    print(f"  Dropped log lines: {dropped}")
    return exit_nonzero


def main():
    ap = argparse.ArgumentParser(description="Ghost Account GitHub Org Enumeration Detector")
    ap.add_argument("log_file", help="Path to GitHub API access log (JSON-lines)")
    ap.add_argument("--org", default=None, help="GitHub org name to scope path matching")
    ap.add_argument("--age-days", type=int, default=30, dest="age_days",
                    help="Max account age in days for ghost classification (default: 30)")
    args = ap.parse_args()

    try:
        entries, dropped = parse_entries(args.log_file, args.age_days)
    except OSError as e:
        print(f"Error reading log file: {e}", file=sys.stderr)
        sys.exit(2)

    print(f"Parsed {len(entries)} entries, {dropped} dropped\n")
    alerts = list(detect_ghost_enum(entries, args.org))
    exit_nonzero = report_findings(alerts, args.age_days, dropped)
    sys.exit(1 if exit_nonzero else 0)


if __name__ == "__main__":
    main()