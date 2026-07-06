"""
OSS Secret Scanner — detect and prioritize leaked secrets by blast radius.

Usage:
    python oss_secret_scanner.py <input_file> [--threshold low|medium|high] [--format text|json]

Examples:
    python oss_secret_scanner.py ci_output.log
    python oss_secret_scanner.py source_dump.txt --threshold high --format json
    python oss_secret_scanner.py build.log --format json | jq '.findings[] | select(.blast_radius=="high")'
"""

import argparse
import json
import re
import sys
from typing import Any

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{10,16}\b")),
    ("aws_secret_key", re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]")),
    ("github_token", re.compile(r"\bghp_[A-Za-z0-9]{36,251}\b|\bgh[orsu]_[A-Za-z0-9]{36,251}\b")),
    ("github_app_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,2048}\.[A-Za-z0-9_-]{10,2048}\.[A-Za-z0-9_-]{10,2048}\b")),
    ("generic_password", re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,64})['\"]?")),
    ("api_key_generic", re.compile(r"(?i)api[_-]?key\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,64})['\"]?")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,100}\b")),
    ("stripe_key", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{24,64}\b")),
]

BLAST_RADIUS: dict[str, str] = {
    "aws_access_key": "high",
    "aws_secret_key": "high",
    "private_key": "high",
    "stripe_key": "high",
    "github_token": "medium",
    "github_app_token": "medium",
    "slack_token": "medium",
    "jwt": "medium",
    "api_key_generic": "medium",
    "generic_password": "low",
}

REMEDIATION: dict[str, str] = {
    "aws_access_key": "Revoke in AWS IAM immediately; rotate all dependent credentials.",
    "aws_secret_key": "Revoke in AWS IAM immediately; audit CloudTrail for unauthorized usage.",
    "private_key": "Revoke associated certificate/key pair; re-issue from a secrets manager.",
    "stripe_key": "Revoke in Stripe Dashboard; review transaction logs for fraud.",
    "github_token": "Revoke in GitHub Settings > Developer Settings > Personal access tokens.",
    "github_app_token": "Revoke in GitHub Settings > Developer Settings > GitHub Apps.",
    "slack_token": "Revoke in Slack API dashboard; audit workspace access logs.",
    "jwt": "Invalidate via token blacklist or shorten TTL; rotate signing secret.",
    "api_key_generic": "Identify issuing service and revoke; replace with a secrets manager reference.",
    "generic_password": "Change password; enforce secrets manager usage to eliminate plaintext storage.",
}

THRESHOLD_ORDER = {"low": 0, "medium": 1, "high": 2}


def redact(match: str) -> str:
    visible = min(4, max(0, len(match) - 4))
    stars = max(4, len(match) - visible)
    return match[:visible] + "*" * stars


def scan_secrets(text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[int, str, str]] = set()
    for line_no, line in enumerate(text.splitlines(), start=1):
        for secret_type, pattern in PATTERNS:
            for m in pattern.finditer(line):
                raw = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                key = (line_no, secret_type, raw)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "line_no": line_no,
                    "type": secret_type,
                    "redacted_match": redact(raw),
                    "blast_radius": classify_blast_radius(secret_type),
                    "remediation": REMEDIATION.get(secret_type, "Rotate credential and remove from source."),
                })
    return findings


def classify_blast_radius(secret_type: str) -> str:
    return BLAST_RADIUS.get(secret_type, "low")


def filter_by_threshold(findings: list[dict[str, Any]], threshold: str) -> list[dict[str, Any]]:
    min_level = THRESHOLD_ORDER[threshold]
    return [f for f in findings if THRESHOLD_ORDER[f["blast_radius"]] >= min_level]


def format_text(findings: list[dict[str, Any]], source: str) -> str:
    lines = [f"OSS Secret Scanner — {source}", "=" * 60]
    if not findings:
        lines.append("No secrets found above threshold.")
        return "\n".join(lines)
    for radius in ("high", "medium", "low"):
        group = [f for f in findings if f["blast_radius"] == radius]
        if not group:
            continue
        lines.append(f"\n[{radius.upper()} BLAST RADIUS] ({len(group)} finding(s))")
        lines.append("-" * 40)
        for f in group:
            lines.append(f"  Line {f['line_no']:>5} | {f['type']:<22} | match: {f['redacted_match']}")
            lines.append(f"           Remediation: {f['remediation']}")
    lines.append(f"\nTotal findings: {len(findings)}")
    return "\n".join(lines)


def format_json(findings: list[dict[str, Any]], source: str) -> str:
    return json.dumps({"source": source, "total": len(findings), "findings": findings}, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan source code or CI logs for leaked secrets, classified by blast radius."
    )
    parser.add_argument("input_file", help="Path to plain-text source dump or CI log")
    parser.add_argument(
        "--threshold",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum blast radius level to emit (default: low)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    args = parser.parse_args()

    try:
        with open(args.input_file, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except FileNotFoundError:
        print(f"Error: file not found: {args.input_file}", file=sys.stderr)
        sys.exit(2)
    except OSError as exc:
        print(f"Error reading file: {exc}", file=sys.stderr)
        sys.exit(2)

    findings = scan_secrets(text)
    findings = filter_by_threshold(findings, args.threshold)

    if args.format == "json":
        print(format_json(findings, args.input_file))
    else:
        print(format_text(findings, args.input_file))

    has_high = any(f["blast_radius"] == "high" for f in findings)
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()