"""
pwn_request_guard.py - Scans GitHub Actions logs for malicious PR patterns.

Usage:
    python pwn_request_guard.py workflow.log --repo owner/repo --severity medium
    python pwn_request_guard.py /tmp/actions.log --severity high
"""

import argparse
import re
import sys
from datetime import datetime, timezone

_REPO_RE = re.compile(r'^[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+$')
_MAX_LINE_LEN = 65536  # Bound regex runtime against attacker-controlled log lines


def load_rules():
    return {
        "WORKFLOW_FILE_MODIFIED": {
            "severity": "high",
            "pattern": re.compile(
                r"(?i)((?:modified|changed|updated|overwritten).*\.github/workflows/[^\s]+\.(?:yml|yaml)|"
                r"\.github/workflows/[^\s]+\.(?:yml|yaml).*(?:modified|changed|updated|overwritten))"
            ),
            "description": "Workflow file modification detected in PR context",
        },
        "TOKEN_PERMISSION_WRITE": {
            "severity": "high",
            "pattern": re.compile(
                r"(?i)(permissions?\s*:\s*write-all|GITHUB_TOKEN.*write|token.*permissions?.*write)"
            ),
            "description": "GITHUB_TOKEN write permission escalation attempt",
        },
        "SELF_HOSTED_RUNNER_INJECTION": {
            "severity": "high",
            "pattern": re.compile(
                r"(?i)(runs-on\s*:\s*self-hosted|runner.*self.hosted.*label)"
            ),
            "description": "Self-hosted runner label injection in workflow context",
        },
        "EXFIL_CURL_SECRET": {
            "severity": "high",
            "pattern": re.compile(
                r"(?i)(curl\s+.*\$\{\{?\s*secrets\.|wget\s+.*\$\{\{?\s*secrets\.)"
            ),
            "description": "Potential secret exfiltration via curl/wget",
        },
        "ENV_SECRET_PRINT": {
            "severity": "high",
            "pattern": re.compile(
                r"(?i)(echo\s+\$\{\{?\s*secrets\.[A-Z0-9_]+\s*\}?\}?|printenv.*SECRET|env\s*\|.*grep.*TOKEN)"
            ),
            "description": "Secret value echo or printenv exposure",
        },
        "PULL_REQUEST_TARGET_ABUSE": {
            "severity": "high",
            "pattern": re.compile(
                r"(?i)(on\s*:\s*pull_request_target\b.*\$\{\{.*github\.event\.pull_request|"
                r"pull_request_target.*checkout.*ref.*head)"
            ),
            "description": "pull_request_target with untrusted ref checkout",
        },
        "WORKFLOW_DISPATCH_INJECT": {
            "severity": "medium",
            "pattern": re.compile(
                r"(?i)(workflow_dispatch.*inputs.*\$\{\{|run\s*:\s*\$\{\{\s*github\.event\.inputs)"
            ),
            "description": "Unsanitized workflow_dispatch input used in run step",
        },
        "CACHE_POISONING": {
            "severity": "medium",
            "pattern": re.compile(
                r"(?i)(actions/cache.*restore-keys.*\$\{\{.*github\.event|cache.*key.*pull_request)"
            ),
            "description": "Cache key includes PR-controlled data (poisoning risk)",
        },
        "ARTIFACT_UPLOAD_SENSITIVE": {
            "severity": "medium",
            "pattern": re.compile(
                r"(?i)(upload-artifact.*(?:\.env|id_rsa|\.pem|credentials|secrets))"
            ),
            "description": "Sensitive file name in artifact upload path",
        },
        "BASE64_EXEC": {
            "severity": "medium",
            "pattern": re.compile(
                r"(?i)(base64\s+(?:-d|--decode)\s*\|.*(?:bash|sh|python|perl|ruby)|"
                r"echo\s+[A-Za-z0-9+/]{20,}={0,2}\s*\|\s*base64\s+(?:-d|--decode)\s*\|.*(?:bash|sh|python|perl|ruby))"
            ),
            "description": "Base64-encoded payload piped to interpreter",
        },
        "OIDC_TOKEN_REQUEST": {
            "severity": "medium",
            "pattern": re.compile(
                r"(?i)(ACTIONS_ID_TOKEN_REQUEST_URL|id-token\s*:\s*write|getIDToken)"
            ),
            "description": "OIDC token request detected — verify cloud role scope",
        },
        "PR_NUMBER_COMMAND_INJECT": {
            "severity": "medium",
            "pattern": re.compile(
                r"(?i)(\$\{\{\s*github\.event\.pull_request\.(?:title|body|head\.label|head\.ref)\s*\}\})"
            ),
            "description": "PR metadata interpolated directly into run step",
        },
        "WORKFLOW_WRITE_PERMISSION_SCOPE": {
            "severity": "low",
            "pattern": re.compile(
                r"(?i)(contents\s*:\s*write|actions\s*:\s*write|packages\s*:\s*write)"
            ),
            "description": "Elevated write permission scope declared in workflow",
        },
        "THIRD_PARTY_ACTION_UNPINNED": {
            "severity": "low",
            "pattern": re.compile(
                r"uses\s*:\s*(?!actions/|github/)([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)@(?![\da-fA-F]{40})(v?\d|\w+$)"
            ),
            "description": "Third-party action pinned to mutable tag, not commit SHA",
        },
    }


def scan_log(lines, rules, min_severity):
    severity_rank = {"low": 0, "medium": 1, "high": 2}
    min_rank = severity_rank.get(min_severity, 0)

    for lineno, line in enumerate(lines, start=1):
        stripped = line.rstrip("\n")[:_MAX_LINE_LEN]
        for rule_id, rule in rules.items():
            if severity_rank[rule["severity"]] < min_rank:
                continue
            match = rule["pattern"].search(stripped)
            if match:
                yield {
                    "line": lineno,
                    "rule": rule_id,
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "evidence": match.group(0)[:200],
                }


def main():
    parser = argparse.ArgumentParser(
        description="Scan GitHub Actions logs for malicious PR patterns."
    )
    parser.add_argument("log_file", help="Path to plain-text GitHub Actions log file")
    parser.add_argument("--repo", default="", help="Repository slug (owner/name)")
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum severity threshold to report",
    )
    args = parser.parse_args()

    if args.repo and not _REPO_RE.match(args.repo):
        print(
            "ERROR: --repo must be 'owner/name' (alphanumeric, hyphens, dots, underscores only)",
            file=sys.stderr,
        )
        sys.exit(2)

    rules = load_rules()

    try:
        with open(args.log_file, "r", encoding="utf-8", errors="replace") as fh:
            findings = list(scan_log(fh, rules, args.severity))
    except OSError as exc:
        print(f"ERROR: Cannot open log file: {exc}", file=sys.stderr)
        sys.exit(2)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    repo_tag = f" [{args.repo}]" if args.repo else ""
    high_found = False

    for f in findings:
        if f["severity"] == "high":
            high_found = True
        print(
            f"{timestamp}{repo_tag} "
            f"[{f['severity'].upper()}] "
            f"L{f['line']} "
            f"{f['rule']}: {f['description']} "
            f"| evidence: {f['evidence']!r}"
        )

    if not findings:
        print(f"{timestamp}{repo_tag} No findings at or above '{args.severity}' severity.")

    sys.exit(1 if high_found else 0)


if __name__ == "__main__":
    main()