"""
CI/CD Permission & Token Exposure Scanner

Scans plain-text CI/CD configuration files and pipeline logs for overly
permissive scope declarations and exposed credential patterns.

Usage:
    python cicd_perms_scanner.py --file .github/workflows/deploy.yml --platform github --verbose
    python cicd_perms_scanner.py --file .gitlab-ci.yml --platform gitlab
    echo $? # non-zero if HIGH findings present
"""

import argparse
import math
import re
import sys
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Finding:
    severity: str
    kind: str
    line_no: int
    line_text: str
    remediation: str


PERMISSION_PATTERNS = {
    "github": [
        (re.compile(r'permissions\s*:\s*write-all', re.I), "HIGH", "Wildcard write-all permission grants repo hijack surface", "Replace with least-privilege per-job permissions block"),
        (re.compile(r'contents\s*:\s*write', re.I), "HIGH", "contents:write allows branch/tag/release manipulation", "Restrict to contents:read unless push is required"),
        (re.compile(r'packages\s*:\s*write', re.I), "HIGH", "packages:write enables malicious package publishing", "Scope to specific job steps that require package push"),
        (re.compile(r'pull-requests\s*:\s*write', re.I), "MEDIUM", "pull-requests:write can merge unapproved code", "Grant only to bots/jobs that explicitly manage PRs"),
        (re.compile(r'actions\s*:\s*write', re.I), "HIGH", "actions:write allows workflow file tampering", "Remove unless workflow self-modification is intended"),
        (re.compile(r'id-token\s*:\s*write', re.I), "MEDIUM", "id-token:write needed only for OIDC; validate audience", "Confirm OIDC audience is tightly scoped"),
        (re.compile(r'administration\s*:\s*write', re.I), "HIGH", "administration:write grants full repo admin rights", "Remove from pipeline; use app installation tokens instead"),
    ],
    "gitlab": [
        (re.compile(r'GIT_STRATEGY\s*:\s*clone.*--depth\s+1.*push', re.I | re.S), "MEDIUM", "Clone-then-push pattern may expose push tokens in logs", "Use deploy keys scoped to target repo only"),
        (re.compile(r'CI_JOB_TOKEN_SCOPE\s*:\s*all', re.I), "HIGH", "Unrestricted CI_JOB_TOKEN scope enables cross-project access", "Set CI_JOB_TOKEN_SCOPE to allowlist of required projects"),
        (re.compile(r'protect\s*:\s*false', re.I), "MEDIUM", "Unprotected variable may leak to fork pipelines", "Set protect:true on variables containing credentials"),
        (re.compile(r'mask\s*:\s*false', re.I), "LOW", "Unmasked variable may appear in job logs", "Enable masking for sensitive variables"),
    ],
    "circleci": [
        (re.compile(r'resource_class\s*:\s*machine', re.I), "LOW", "machine executor shares host; escape risk higher than docker", "Prefer docker executor for untrusted code"),
        (re.compile(r'no_output_timeout\s*:\s*(\d+)h', re.I), "LOW", "Long timeout jobs may hold tokens open unnecessarily", "Set timeouts to minimum required duration"),
    ],
}

TOKEN_PATTERNS = [
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), "HIGH", "GitHub Personal Access Token exposed", "Rotate immediately; use ${{ secrets.TOKEN }} reference"),
    (re.compile(r'ghs_[A-Za-z0-9]{36}'), "HIGH", "GitHub Actions installation token exposed", "Never hard-code; token is ephemeral but leaks pipeline intent"),
    (re.compile(r'glpat-[A-Za-z0-9\-_]{20,}'), "HIGH", "GitLab Personal Access Token exposed", "Rotate immediately; store in CI/CD variable with mask:true"),
    (re.compile(r'CIRCLE_TOKEN\s*=\s*[A-Za-z0-9]{40}'), "HIGH", "CircleCI API token hardcoded", "Use $CIRCLE_TOKEN environment variable reference"),
    (re.compile(r'-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----'), "HIGH", "Private key material embedded in pipeline file", "Remove immediately; store in secrets manager"),
    (re.compile(r'(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+]{40}'), "HIGH", "AWS secret access key hardcoded", "Use IAM role/OIDC federation; never hardcode credentials"),
    (re.compile(r'(?i)password\s*[=:]\s*[^\s$\{\'\"]{8,}'), "MEDIUM", "Possible plaintext password assignment", "Reference secret via platform secret store"),
    (re.compile(r'\$\{\{\s*secrets\.[A-Z_]+\s*\}\}\s*\|\|\s*[\'"][^\'"]{4,}'), "HIGH", "Secret with hardcoded fallback bypasses secret store", "Remove fallback literal; fail explicitly if secret is absent"),
    (re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'), "LOW", "Base64 blob may encode credential material", "Inspect blob; store decoded secrets in secret manager"),
]

MIN_ENTROPY = 3.5


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def scan_permissions(lines: List[str], platform: str) -> List[Finding]:
    findings = []
    patterns = PERMISSION_PATTERNS.get(platform, [])
    for i, line in enumerate(lines, 1):
        for pattern, severity, kind, remediation in patterns:
            if pattern.search(line):
                findings.append(Finding(severity, kind, i, line.rstrip(), remediation))
    return findings


def scan_tokens(lines: List[str]) -> List[Finding]:
    findings = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        for pattern, severity, kind, remediation in TOKEN_PATTERNS:
            m = pattern.search(line)
            if not m:
                continue
            token_candidate = m.group(0)
            if severity == "LOW" and shannon_entropy(token_candidate) < MIN_ENTROPY:
                continue
            findings.append(Finding(severity, kind, i, line.rstrip(), remediation))
            break
    return findings


def severity_rank(s: str) -> int:
    return {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(s, 9)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CI/CD Permission & Token Exposure Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--file", required=True, help="Path to CI/CD config or pipeline log")
    parser.add_argument("--platform", choices=["github", "gitlab", "circleci"], default="github", help="Pipeline platform hint")
    parser.add_argument("--verbose", action="store_true", help="Emit every finding with full line text")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        print(f"ERROR: cannot read file: {exc}", file=sys.stderr)
        return 2

    findings = scan_permissions(lines, args.platform) + scan_tokens(lines)
    findings.sort(key=lambda f: (severity_rank(f.severity), f.line_no))

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"=== CI/CD Permission & Token Exposure Report ===")
    print(f"File    : {args.file}")
    print(f"Platform: {args.platform}")
    print(f"Findings: HIGH={counts['HIGH']} MEDIUM={counts['MEDIUM']} LOW={counts['LOW']}")
    print()

    if not findings:
        print("No issues detected.")
        return 0

    for f in findings:
        if args.verbose:
            print(f"[{f.severity}] Line {f.line_no}: {f.kind}")
            print(f"  >> {f.line_text[:120]}")
            print(f"  FIX: {f.remediation}")
            print()
        else:
            print(f"[{f.severity:6}] L{f.line_no:<5} {f.kind}")
            print(f"         FIX: {f.remediation}")

    return 1 if counts["HIGH"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())