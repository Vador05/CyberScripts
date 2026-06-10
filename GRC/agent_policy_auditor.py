"""
Agent Policy Auditor - Detects over-privileged access patterns in agent audit logs.

Usage:
    python agent_policy_auditor.py --log-file audit.log --policy "DROP TABLE,kubectl delete,pg_dump" --severity medium

Example log format:
    2024-01-15T10:23:45Z agent-001 EXEC: kubectl delete pod nginx-abc
    2024-01-15T10:24:01Z agent-002 QUERY: SELECT * FROM users
    2024-01-15T10:24:15Z agent-003 EXEC: pg_dump mydb > backup.sql
"""

import argparse
import re
import sys
from dataclasses import dataclass

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}

BUILTIN_SEVERITY = {
    "DROP TABLE": "high",
    "DROP DATABASE": "high",
    "kubectl delete": "high",
    "kubectl exec": "high",
    "pg_dump": "medium",
    "pg_restore": "medium",
    "TRUNCATE": "medium",
    "DELETE FROM": "medium",
    "ALTER TABLE": "medium",
    "CREATE USER": "high",
    "GRANT": "high",
    "kubectl apply": "medium",
    "kubectl patch": "medium",
}

LOG_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
    r"(?P<agent_id>\S+)\s+"
    r"(?P<action>.+)"
)

# Strips ANSI/VT100 escape sequences and C0/C1 control characters before printing,
# preventing terminal injection from malicious log content.
_ANSI_ESCAPE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


@dataclass
class LogEvent:
    timestamp: str
    agent_id: str
    action: str
    line_number: int


@dataclass
class Violation:
    timestamp: str
    agent_id: str
    action: str
    matched_rule: str
    severity: str


def sanitize_for_display(s: str) -> str:
    s = _ANSI_ESCAPE.sub("", s)
    return _CONTROL_CHARS.sub("?", s)


def parse_log(log_file: str) -> list[LogEvent]:
    events = []
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = LOG_PATTERN.match(line)
                if m:
                    events.append(LogEvent(
                        timestamp=m.group("timestamp"),
                        agent_id=m.group("agent_id"),
                        action=m.group("action"),
                        line_number=lineno,
                    ))
    except OSError as e:
        print(f"ERROR: Cannot read log file {log_file!r}: {e}", file=sys.stderr)
        sys.exit(1)
    except UnicodeDecodeError as e:
        print(f"ERROR: Log file contains invalid UTF-8 data ({log_file!r}): {e}", file=sys.stderr)
        sys.exit(1)
    return events


def infer_severity(rule: str) -> str:
    for key, sev in BUILTIN_SEVERITY.items():
        if key.lower() in rule.lower():
            return sev
    return "low"


def evaluate_policy(events: list[LogEvent], deny_rules: list[str]) -> list[Violation]:
    """Report one violation per event: the matching rule with the highest severity."""
    violations = []
    for event in events:
        best_rule: str | None = None
        best_severity: str | None = None
        best_level = 0
        for rule in deny_rules:
            rule_stripped = rule.strip()
            if not rule_stripped:
                continue
            if rule_stripped.lower() in event.action.lower():
                severity = infer_severity(rule_stripped)
                level = SEVERITY_ORDER.get(severity, 0)
                if level > best_level:
                    best_level = level
                    best_rule = rule_stripped
                    best_severity = severity
        if best_rule is not None:
            assert best_severity is not None
            violations.append(Violation(
                timestamp=event.timestamp,
                agent_id=event.agent_id,
                action=event.action,
                matched_rule=best_rule,
                severity=best_severity,
            ))
    return violations


def report_violations(violations: list[Violation], min_severity: str) -> None:
    min_level = SEVERITY_ORDER.get(min_severity, 1)
    filtered = [v for v in violations if SEVERITY_ORDER.get(v.severity, 0) >= min_level]

    if not filtered:
        print("No violations found above the specified severity threshold.")
        return

    def slen(s: str) -> int:
        return len(sanitize_for_display(s))

    col_ts = max(len("TIMESTAMP"), max(slen(v.timestamp) for v in filtered))
    col_ag = max(len("AGENT_ID"), max(slen(v.agent_id) for v in filtered))
    col_ac = max(len("ACTION"), min(60, max(slen(v.action) for v in filtered)))
    col_ru = max(len("MATCHED_RULE"), max(slen(v.matched_rule) for v in filtered))
    col_sv = max(len("SEVERITY"), max(slen(v.severity) for v in filtered))

    header = (
        f"{'TIMESTAMP':<{col_ts}}  {'AGENT_ID':<{col_ag}}  "
        f"{'ACTION':<{col_ac}}  {'MATCHED_RULE':<{col_ru}}  {'SEVERITY':<{col_sv}}"
    )
    divider = "-" * len(header)
    print(divider)
    print(header)
    print(divider)

    counts = {"low": 0, "medium": 0, "high": 0}
    for v in filtered:
        ts = sanitize_for_display(v.timestamp)
        ag = sanitize_for_display(v.agent_id)
        ac_full = sanitize_for_display(v.action)
        ac = ac_full if len(ac_full) <= col_ac else ac_full[:col_ac - 3] + "..."
        ru = sanitize_for_display(v.matched_rule)
        sv = sanitize_for_display(v.severity)
        print(
            f"{ts:<{col_ts}}  {ag:<{col_ag}}  "
            f"{ac:<{col_ac}}  {ru:<{col_ru}}  {sv:<{col_sv}}"
        )
        counts[v.severity] = counts.get(v.severity, 0) + 1

    print(divider)
    print(f"Total violations: {len(filtered)}  (high={counts['high']}, medium={counts['medium']}, low={counts['low']})")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit agent activity logs against a least-privilege policy baseline."
    )
    parser.add_argument("--log-file", required=True, help="Path to plain-text agent audit log")
    parser.add_argument(
        "--policy",
        required=True,
        help="Comma-separated deny rules (e.g. 'DROP TABLE,kubectl delete,pg_dump')",
    )
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum severity level to report (default: low)",
    )
    args = parser.parse_args()

    deny_rules = [r.strip() for r in args.policy.split(",") if r.strip()]
    if not deny_rules:
        print("ERROR: No valid deny rules provided in --policy", file=sys.stderr)
        sys.exit(1)

    events = parse_log(args.log_file)
    violations = evaluate_policy(events, deny_rules)
    report_violations(violations, args.severity)


if __name__ == "__main__":
    main()