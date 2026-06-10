"""
VS Code URI Token Hunter - Scans CI/CD logs for GitHub token exfiltration via VS Code abuse.

Usage:
    python vscode_token_hunter.py pipeline.log
    python vscode_token_hunter.py pipeline.log --severity high --format json
    cat pipeline.log | python vscode_token_hunter.py --severity medium
"""

import re
import sys
import json
import argparse
import datetime
from typing import Generator, Iterable

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}
MAX_LINE_LEN = 4096  # Bound regex input to prevent ReDoS on adversary-controlled lines

_GH_TOKEN_PAT = r"(?:ghp_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36})"
_ALLOWLISTED_HOSTS = r"(?:github\.com|raw\.githubusercontent\.com)(?:[/?#\s\"']|$)"
_EXTENDED_ALLOWLISTED_HOSTS = r"(?:github\.com|gitlab\.com|bitbucket\.org|raw\.githubusercontent\.com)(?:[/?#\s\"']|$)"

# Matches ANSI CSI escape sequences first, then remaining ASCII control chars.
# Order matters: the longer CSI pattern must precede the single-char \x1b match so
# the full sequence is consumed as a unit rather than just stripping the leading ESC.
_CTRL_CHARS = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|[\x00-\x1f\x7f]")


def _sanitize(s: str) -> str:
    return _CTRL_CHARS.sub("", s)


def load_rules() -> list[dict]:
    return [
        {
            "name": "vscode_uri_handler_invocation",
            "severity": "high",
            "pattern": re.compile(r"vscode://[^\s\"'<>]{10,}", re.IGNORECASE),
            "description": "VS Code URI handler invoked — possible workspace trust abuse",
        },
        {
            "name": "vscode_uri_with_token_param",
            "severity": "high",
            "pattern": re.compile(
                r"vscode://[^\s\"'<>]*[?&](token|secret|key|auth|credential|access_token)=[^\s\"'<>&]{8,}",
                re.IGNORECASE,
            ),
            "description": "VS Code URI contains credential parameter",
        },
        {
            "name": "vscode_settings_token_sink",
            "severity": "high",
            "pattern": re.compile(
                r"\.vscode/settings\.json.*?(?:github[_.]token|GITHUB_TOKEN|" + _GH_TOKEN_PAT + r")",
                re.IGNORECASE,
            ),
            "description": ".vscode/settings.json contains GitHub token pattern",
        },
        {
            "name": "vscode_settings_remote_url",
            "severity": "medium",
            "pattern": re.compile(
                r"\.vscode/settings\.json.*?https?://(?!" + _ALLOWLISTED_HOSTS + r")[^\s\"'<>]{10,}",
                re.IGNORECASE,
            ),
            "description": ".vscode/settings.json references suspicious external URL",
        },
        {
            "name": "vscode_settings_exec_hook",
            "severity": "high",
            "pattern": re.compile(
                r"\.vscode/settings\.json.*?terminal\.integrated\.env.*?(?:curl|wget|nc |ncat|bash|sh |python|ruby|perl)",
                re.IGNORECASE,
            ),
            "description": ".vscode/settings.json terminal.integrated.env references network/exec tool",
        },
        {
            "name": "github_token_env_exposure",
            "severity": "high",
            "pattern": re.compile(
                r"(?:GITHUB_TOKEN|GH_TOKEN)\s*[=:]\s*(?:" + _GH_TOKEN_PAT + r"|github_pat_[A-Za-z0-9_]{80,}|[A-Za-z0-9]{40})",
            ),
            "description": "GitHub token value exposed in log output",
        },
        {
            "name": "github_pat_pattern",
            "severity": "high",
            "pattern": re.compile(
                _GH_TOKEN_PAT + r"|github_pat_[A-Za-z0-9_]{80,}",
            ),
            "description": "GitHub personal access token pattern detected",
        },
        {
            "name": "vscode_workspace_trust_bypass",
            "severity": "medium",
            "pattern": re.compile(
                r"(?:security\.workspace\.trust\.enabled.*?false|workspaceTrust.*?false)",
                re.IGNORECASE,
            ),
            "description": "VS Code workspace trust explicitly disabled",
        },
        {
            "name": "token_exfil_curl",
            "severity": "high",
            "pattern": re.compile(
                r"curl.*?(?:"
                r"(?:GITHUB_TOKEN|GH_TOKEN|" + _GH_TOKEN_PAT + r").*?https?://"
                r"|https?://.*?(?:GITHUB_TOKEN|GH_TOKEN|" + _GH_TOKEN_PAT + r")"
                r")",
                re.IGNORECASE,
            ),
            "description": "GitHub token passed to curl — likely exfiltration attempt",
        },
        {
            "name": "vscode_open_remote_repo",
            "severity": "medium",
            "pattern": re.compile(
                r"vscode://vscode\.git/clone\?url=https?://(?!" + _EXTENDED_ALLOWLISTED_HOSTS + r")[^\s\"'<>]+",
                re.IGNORECASE,
            ),
            "description": "VS Code URI clones from suspicious non-standard host",
        },
        {
            "name": "token_in_git_remote",
            "severity": "high",
            "pattern": re.compile(
                r"https?://[^@\s]*?(?:" + _GH_TOKEN_PAT + r"|:[A-Za-z0-9]{40}@)[^\s]*",
            ),
            "description": "GitHub token embedded in git remote URL",
        },
        {
            "name": "vscode_extension_install_url",
            "severity": "low",
            "pattern": re.compile(
                r"code\s+--install-extension\s+https?://[^\s]+",
                re.IGNORECASE,
            ),
            "description": "VS Code extension installed from URL (not marketplace)",
        },
    ]


def scan_log(
    lines: Iterable[str], rules: list[dict], min_severity: str
) -> Generator[dict, None, None]:
    min_level = SEVERITY_ORDER[min_severity]
    for lineno, line in enumerate(lines, start=1):
        stripped = line.rstrip("\n")
        if len(stripped) > MAX_LINE_LEN:
            continue
        for rule in rules:
            if SEVERITY_ORDER[rule["severity"]] < min_level:
                continue
            match = rule["pattern"].search(stripped)
            if match:
                yield {
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "severity": rule["severity"],
                    "rule": rule["name"],
                    "description": rule["description"],
                    "line_number": lineno,
                    "matched_text": match.group(0)[:120],
                    "raw_line": stripped[:200],
                }


def format_finding(finding: dict, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(finding)
    return (
        f"[{finding['timestamp']}] [{finding['severity'].upper():6}] "
        f"rule={finding['rule']} line={finding['line_number']}\n"
        f"  desc : {finding['description']}\n"
        f"  match: {_sanitize(finding['matched_text'])}\n"
        f"  raw  : {_sanitize(finding['raw_line'])}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan CI/CD logs for GitHub token exfiltration via VS Code abuse."
    )
    parser.add_argument(
        "log_file",
        nargs="?",
        help="Path to plain-text CI/CD log (reads stdin if omitted)",
    )
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum alert severity to emit (default: low)",
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    args = parser.parse_args()

    try:
        if args.log_file:
            fh = open(args.log_file, "r", encoding="utf-8", errors="replace")
        else:
            fh = sys.stdin
        with fh:
            rules = load_rules()
            found = 0
            for finding in scan_log(fh, rules, args.severity):
                print(format_finding(finding, args.format))
                found += 1
    except OSError as exc:
        print(f"ERROR: cannot read log: {exc}", file=sys.stderr)
        return 2

    if found == 0:
        print("No findings at the specified severity threshold.", file=sys.stderr)
    return 0 if found == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
