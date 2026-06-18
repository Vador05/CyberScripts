"""
Tailscale+SSH Persistence Detector

Parses plain-text system logs to detect co-installation of Tailscale and OpenSSH,
flagging the combination as a potential covert persistence indicator.

Usage:
    python tailscale_ssh_detector.py /var/log/syslog --window 300 --hostname webserver01
    python tailscale_ssh_detector.py /var/log/auth.log --window 600
    cat /var/log/dpkg.log | python tailscale_ssh_detector.py /dev/stdin
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from typing import Generator


LOG_PATTERNS = [
    re.compile(
        r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<proc>\S+):\s+(?P<msg>.+)$"
    ),
    re.compile(
        r"^(?P<year>\d{4})-(?P<month2>\d{2})-(?P<day2>\d{2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<msg>.+)$"
    ),
]

TAILSCALE_RE = re.compile(
    r"(tailscale|tailscaled|com\.tailscale)", re.IGNORECASE
)
OPENSSH_RE = re.compile(
    r"(openssh|ssh-server|sshd\s+installed|install.*openssh|openssh.*install"
    r"|Unpacking openssh|Setting up openssh)", re.IGNORECASE
)
INSTALL_ACTION_RE = re.compile(
    r"(install|upgrade|unpack|setting up|started|enabled|status=installed)",
    re.IGNORECASE
)

MONTH_MAP = {m: i for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], 1
)}


def parse_timestamp(match: re.Match) -> datetime | None:
    try:
        gd = match.groupdict()
        if "month" in gd and gd.get("month") in MONTH_MAP:
            month_num = MONTH_MAP[gd["month"]]
            now = datetime.now()
            # If the log month is ahead of the current month, the entry is from
            # the previous year (year-boundary logs analyzed after rollover).
            year = now.year if month_num <= now.month else now.year - 1
            dt = datetime(
                year,
                month_num,
                int(gd["day"]),
                *map(int, gd["time"].split(":")),
                tzinfo=timezone.utc,
            )
            return dt
        if "month2" in gd:
            dt = datetime(
                int(gd["year"]),
                int(gd["month2"]),
                int(gd["day2"]),
                *map(int, gd["time"].split(":")),
                tzinfo=timezone.utc,
            )
            return dt
    except (ValueError, KeyError):
        return None
    return None


def parse_log_events(path: str, hostname_filter: str | None) -> list[dict]:
    events = []
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                line = line.rstrip()
                matched = None
                for pat in LOG_PATTERNS:
                    m = pat.match(line)
                    if m:
                        matched = m
                        break
                if not matched:
                    continue
                gd = matched.groupdict()
                # ISO-format patterns (e.g. dpkg.log) have no host field.
                # Only apply the hostname filter when the log line actually
                # carries a host; hostless formats cannot be filtered by host.
                raw_host = gd.get("host")
                has_host_field = raw_host is not None
                host = raw_host if raw_host else "unknown"
                if hostname_filter and has_host_field and host != hostname_filter:
                    continue
                msg = gd.get("msg", line)
                ts = parse_timestamp(matched)
                if ts is None:
                    continue
                if not INSTALL_ACTION_RE.search(msg):
                    continue
                if TAILSCALE_RE.search(msg):
                    events.append({"ts": ts, "host": host, "msg": msg, "kind": "tailscale"})
                elif OPENSSH_RE.search(msg):
                    events.append({"ts": ts, "host": host, "msg": msg, "kind": "openssh"})
    except OSError as exc:
        print(f"ERROR: cannot open log file: {exc}", file=sys.stderr)
        sys.exit(2)
    return sorted(events, key=lambda e: e["ts"])


def correlate_persistence(events: list[dict], window_seconds: int) -> Generator[dict, None, None]:
    for i, ev in enumerate(events):
        anchor_kind = ev["kind"]
        pair_kind = "openssh" if anchor_kind == "tailscale" else "tailscale"
        for j in range(i + 1, len(events)):
            other = events[j]
            delta = (other["ts"] - ev["ts"]).total_seconds()
            if delta > window_seconds:
                break
            if other["kind"] != pair_kind or other["host"] != ev["host"]:
                continue
            yield {
                "timestamp": ev["ts"].isoformat(),
                "hostname": ev["host"],
                "rule_id": "PERSISTENCE_TAILSCALE_SSH_COINSTALL",
                "severity": "HIGH",
                "matched_events": [ev["msg"], other["msg"]],
                "sigma_condition": (
                    f"tailscale_install AND openssh_install WITHIN {window_seconds}s"
                ),
            }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect Tailscale+SSH co-installation as a persistence indicator."
    )
    parser.add_argument("log_file", help="Path to syslog/auth.log/dpkg.log")
    parser.add_argument(
        "--window", type=int, default=300,
        help="Correlation window in seconds (default: 300)"
    )
    parser.add_argument(
        "--hostname", default=None,
        help="Filter log entries by hostname"
    )
    args = parser.parse_args()

    if args.window <= 0:
        print("ERROR: --window must be a positive integer", file=sys.stderr)
        sys.exit(2)

    events = parse_log_events(args.log_file, args.hostname)
    hits = 0
    for alert in correlate_persistence(events, args.window):
        print(json.dumps(alert))
        hits += 1

    if hits == 0:
        print(json.dumps({"status": "clean", "hits": 0}))
    sys.exit(1 if hits > 0 else 0)


if __name__ == "__main__":
    main()