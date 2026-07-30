"""
gitlost_lab - Scan local GitHub repository for GitLost attack patterns.

Usage:
    python gitlost_lab.py /path/to/repo
    python gitlost_lab.py /path/to/repo --severity medium
    python gitlost_lab.py /path/to/repo --severity high --org myorg
"""

import argparse
import re
import sys
from pathlib import Path

ISSUE_TRIGGERS = re.compile(r"^\s*(issues|issue_comment)\s*:", re.MULTILINE)

RULES = {
    "IssueBodyExec": [
        (r"\$\{\{\s*github\.event\.issue\.body\s*\}\}", "high",
         "Never interpolate issue.body into run blocks; assign to env var and validate before use"),
        (r"\$\{\{\s*github\.event\.issue\.title\s*\}\}", "high",
         "Issue titles are attacker-controlled; sanitize before shell execution or env assignment"),
        (r"\$\{\{\s*github\.event\.comment\.body\s*\}\}", "high",
         "Comment bodies are fully attacker-controlled; avoid direct shell interpolation"),
        (r"env\s*:.*?\$\{\{\s*github\.event\.issue", "medium",
         "Issue context in env vars flows into run steps; validate and encode before assignment"),
    ],
    "CrossRepoToken": [
        (r"actions/checkout@[^\n]+\brepository\s*:", "high",
         "Cross-repo checkout in issue-triggered workflow exposes GITHUB_TOKEN to attacker-supplied context"),
        (r"(?:curl|wget|gh\s|github\.com)[^\n]*\$\{\{\s*secrets\.[A-Z_]+\s*\}\}|\$\{\{\s*secrets\.[A-Z_]+\s*\}\}[^\n]*(?:curl|wget|gh\s|github\.com)", "high",
         "Secret used in HTTP call within issue-triggered workflow; restrict secret scope and add approval gate"),
        (r"GITHUB_TOKEN[^\n]*(?:api\.github\.com|gh\s|github\.com/)[^\n]*(?:orgs?|repos?/[^/]+/[^/\n]+/[^/\n]+)", "high",
         "GITHUB_TOKEN used for cross-repo or org-scoped API calls; pin to minimum required permission"),
        (r"secrets\.GITHUB_TOKEN[^\n]*(push|write|admin)", "medium",
         "GITHUB_TOKEN with write scope in issue workflow; limit to read-only for triage paths"),
        (r"(?:pat|token|PAT|TOKEN)\s*:\s*\$\{\{\s*secrets\.", "medium",
         "Named PAT injected via secrets in issue-triggered workflow; audit token scope and rotation policy"),
    ],
    "DataExfilVector": [
        (r"(?:curl|wget)[^\n]*\$\{\{\s*github\.event\.issue", "high",
         "Issue-controlled data in outbound HTTP call; block egress and sanitize all event fields"),
        (r"(?:curl|wget)[^\n]*(?:-d|--data|--data-raw|--data-binary)[^\n]*\$\{\{", "high",
         "Attacker-controlled expression in POST body of outbound request; restrict outbound network access"),
        (r"requests\.(get|post|put|patch)[^\n]*\$\{\{\s*github\.event\.issue", "high",
         "Python requests call with issue-controlled URL or body; validate and allowlist outbound destinations"),
        (r"(?:curl|wget)[^\n]*(?:https?://(?!github\.com|api\.github\.com))", "medium",
         "Outbound HTTP to non-GitHub host in issue workflow; enforce network egress policy"),
        (r"base64[^\n]*\$\{\{\s*github\.event\.issue", "medium",
         "Issue content encoded and potentially exfiltrated; audit base64 usage in issue-triggered jobs"),
    ],
}

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
MAX_FILE_SIZE = 256 * 1024


def scan_workflows(repo_path):
    wf_dir = Path(repo_path) / ".github" / "workflows"
    if not wf_dir.is_dir():
        return
    for p in sorted(wf_dir.rglob("*.y*ml")):
        if p.suffix not in (".yml", ".yaml"):
            continue
        if p.stat().st_size > MAX_FILE_SIZE:
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not ISSUE_TRIGGERS.search(content):
            continue
        triggers = set(ISSUE_TRIGGERS.findall(content))
        rel = str(p.relative_to(repo_path))
        yield rel, triggers, content


def match_gitlost_patterns(rel_path, content, min_severity):
    findings = []
    for rule_class, patterns in RULES.items():
        for pattern, severity, note in patterns:
            if SEVERITY_RANK[severity] < SEVERITY_RANK[min_severity]:
                continue
            for m in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
                snippet = m.group(0).replace("\n", " ")[:120]
                findings.append({
                    "path": rel_path,
                    "rule": rule_class,
                    "severity": severity,
                    "snippet": snippet,
                    "note": note,
                })
    return findings


def report_findings(all_findings, org):
    rule_counts = {k: 0 for k in RULES}
    peak = "low"
    files_by_rule = {}

    for f in all_findings:
        sev_label = f["severity"].upper()
        print(f"[{sev_label}] {f['path']} | {f['rule']} | {f['snippet']!r} | {f['note']}")
        rule_counts[f["rule"]] += 1
        if SEVERITY_RANK[f["severity"]] > SEVERITY_RANK[peak]:
            peak = f["severity"]
        files_by_rule.setdefault(f["rule"], set()).add(f["path"])

    print("\n--- GitLost Scan Summary ---")
    if org:
        print(f"Org scope: {org}")
    for rule, count in rule_counts.items():
        print(f"  {rule}: {count} finding(s)")
    print(f"  Peak severity: {peak.upper()}")

    chain_files = None
    exec_files = files_by_rule.get("IssueBodyExec", set())
    token_files = files_by_rule.get("CrossRepoToken", set())
    overlap = exec_files & token_files
    if overlap:
        chain_files = overlap
        chain_score = "CRITICAL"
    else:
        chain_score = peak.upper()

    print(f"  GitLost chain score: {chain_score}")
    if chain_files:
        for fp in sorted(chain_files):
            print(f"  [CRITICAL CHAIN] {fp} has both IssueBodyExec + CrossRepoToken — full harvest path present")

    return peak == "high"


def main():
    parser = argparse.ArgumentParser(
        description="Scan a local repo for GitLost issue-triggered workflow vulnerabilities.",
        epilog="Example: python gitlost_lab.py /path/to/repo --severity medium --org myorg",
    )
    parser.add_argument("repo_path", help="Local path to the cloned repository")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum severity level to report (default: low)")
    parser.add_argument("--org", default=None, help="GitHub org name for annotating cross-org findings")
    args = parser.parse_args()

    repo = Path(args.repo_path)
    if not repo.is_dir():
        print(f"[ERROR] Repository path not found: {repo}", file=sys.stderr)
        sys.exit(2)

    all_findings = []
    workflow_count = 0
    for rel_path, triggers, content in scan_workflows(repo):
        workflow_count += 1
        findings = match_gitlost_patterns(rel_path, content, args.severity)
        all_findings.extend(findings)

    if workflow_count == 0:
        print("[INFO] No issue-triggered workflows found under .github/workflows/")
        sys.exit(0)

    print(f"[INFO] Scanned {workflow_count} issue-triggered workflow(s) in {repo}\n")

    if not all_findings:
        print("[INFO] No findings at or above the specified severity threshold.")
        sys.exit(0)

    has_high = report_findings(all_findings, args.org)
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()