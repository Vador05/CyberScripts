"""
Vibe Code Vulnerability Scanner

Scans AI-generated application source code for DoS patterns, broken authorization,
and hardcoded secrets exposure. Designed for CI/CD pipeline gating.

Usage example:
    python vibe_code_vuln_scanner.py ./myapp
    python vibe_code_vuln_scanner.py ./myapp --severity high
    python vibe_code_vuln_scanner.py ./myapp --rules extra_rules.json --severity medium

Exit codes: 0 = clean or no high-severity findings at threshold, 1 = high-severity hit, 2 = usage error.
"""

import argparse, json, os, re, sys
from collections import defaultdict

SEV = {"low": 0, "medium": 1, "high": 2}
EXTS = {".py", ".js", ".ts", ".go", ".rb", ".php", ".env", ".yaml", ".yml", ".json", ".toml"}
MAX_BYTES = 256 * 1024

RULES = [
    {"name": "redos_nested_quantifier", "class": "DoS", "sev": "high",
     "pat": r"\([^)]*[+*]\)\s*[+*]",
     "fix": "Rewrite regex to eliminate nested quantifiers; use atomic groups or possessive quantifiers."},
    {"name": "no_timeout_http", "class": "DoS", "sev": "high",
     "pat": r"requests\.(get|post|put|delete|patch|head)\s*\((?:(?!timeout)[^)])*\)",
     "fix": "Pass timeout= to every requests call to prevent indefinite connection blocking."},
    {"name": "unbounded_retry_loop", "class": "DoS", "sev": "medium",
     "pat": r"while\s+True\s*:",
     "fix": "Cap retry loops with a maximum attempt counter and exponential backoff with jitter."},
    {"name": "unpaginated_db_query", "class": "DoS", "sev": "medium",
     "pat": r"\.(find|all)\(\s*\)(?!.*\b(limit|paginate|first|take)\b)|SELECT \* FROM \w+(?!\s+(WHERE|LIMIT|JOIN))",
     "fix": "Add LIMIT/pagination to database queries to prevent full-table scan DoS."},
    {"name": "hardcoded_role_bypass", "class": "BrokenAuthz", "sev": "high",
     "pat": r"if\s+\w+\s*==\s*['\"]admin['\"]|if\s+(role|group|user_type)\s*==\s*['\"][^'\"]+['\"]",
     "fix": "Replace hardcoded role string checks with RBAC middleware enforced at the framework layer."},
    {"name": "unauthenticated_route", "class": "BrokenAuthz", "sev": "high",
     "pat": r"@(app|router|blueprint)\.(route|get|post|put|delete|patch)\(",
     "fix": "Ensure every route has an auth decorator (login_required, jwt_required, etc.) within scope."},
    {"name": "unvalidated_object_ref", "class": "BrokenAuthz", "sev": "medium",
     "pat": r"request\.(args|params|form|json)\.get\(['\"]id['\"]|\brequest\.params\[.id.\]",
     "fix": "Validate resource ownership against the authenticated principal before returning data."},
    {"name": "auth_bypass_comment", "class": "BrokenAuthz", "sev": "medium",
     "pat": r"(#|//)\s*(skip|bypass|disable|todo)[^\n]*(auth|authz|authorization|login)",
     "fix": "Remove auth bypass comments and implement proper authentication checks."},
    {"name": "openai_api_key", "class": "SecretsExposure", "sev": "high",
     "pat": r"sk-[A-Za-z0-9]{20,}",
     "fix": "Rotate key immediately; load from environment variable or a secrets manager at runtime."},
    {"name": "aws_access_key", "class": "SecretsExposure", "sev": "high",
     "pat": r"AKIA[0-9A-Z]{16}",
     "fix": "Rotate IAM key immediately; use IAM roles or AWS Secrets Manager instead."},
    {"name": "google_api_key", "class": "SecretsExposure", "sev": "high",
     "pat": r"AIza[0-9A-Za-z\-_]{35}",
     "fix": "Revoke key in Google Cloud Console; inject via environment variable at runtime."},
    {"name": "hardcoded_credential", "class": "SecretsExposure", "sev": "high",
     "pat": r"(?i)(password|passwd|secret|api_key|auth_token)\s*=\s*['\"][^'\"]{4,}['\"]",
     "fix": "Remove hardcoded credential; source from environment variable or secrets vault."},
    {"name": "connection_string_creds", "class": "SecretsExposure", "sev": "high",
     "pat": r"(mongodb|postgres|postgresql|mysql|redis|amqp)://\w+:[^@\s]{3,}@",
     "fix": "Move connection string to environment variable; never embed credentials in source."},
]

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build", ".tox"}


def scan_files(app_dir):
    for root, dirs, files in os.walk(app_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            if not any(fname.endswith(ext) for ext in EXTS):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "rb") as fb:
                    raw = fb.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES or b"\x00" in raw[:512]:
                    continue
                rel = os.path.relpath(fpath, app_dir)
                for lineno, line in enumerate(raw.decode("utf-8", errors="ignore").splitlines(), 1):
                    yield rel, lineno, line
            except OSError:
                continue


def match_rules(rel, lineno, line, rules, recent):
    hits = []
    for rule in rules:
        try:
            pat = rule.get("pat", "")
            if not pat or not re.search(pat, line):
                continue
        except re.error:
            continue
        rule_name = rule.get("name", "unknown")
        rule_class = rule.get("class", "Unknown")
        rule_sev = rule.get("sev", "low")
        rule_fix = rule.get("fix", "No mitigation hint available.")
        key = (rel, rule_name)
        if lineno - recent.get(key, -99) <= 5:
            continue
        recent[key] = lineno
        hits.append({"file": rel, "line": lineno, "class": rule_class,
                     "sev": rule_sev, "rule": rule_name,
                     "snippet": line.strip()[:120], "fix": rule_fix})
    return hits


def report_findings(findings, min_sev):
    threshold = SEV[min_sev]
    counts, peak = defaultdict(int), 0
    visible = [f for f in findings if SEV.get(f["sev"], 0) >= threshold]
    for f in sorted(visible, key=lambda x: -SEV.get(x["sev"], 0)):
        peak = max(peak, SEV.get(f["sev"], 0))
        counts[f["class"]] += 1
        print(f"[{f['sev'].upper()}] {f['file']}:{f['line']} | {f['class']} | {f['rule']}")
        print(f"  snippet: {f['snippet']}")
        print(f"  fix:     {f['fix']}")
    print("\n--- Summary ---")
    for cls in ("DoS", "BrokenAuthz", "SecretsExposure"):
        print(f"  {cls}: {counts[cls]} finding(s)")
    peak_label = next((k for k, v in SEV.items() if v == peak), "none") if visible else "none"
    print(f"  Peak severity observed: {peak_label}")
    if peak >= SEV["high"]:
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description="Vibe Code Vulnerability Scanner — CI/CD gate for AI-generated code")
    ap.add_argument("app_dir", help="Path to the AI-generated application directory to scan")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum severity level to report (default: low)")
    ap.add_argument("--rules", metavar="FILE",
                    help="Supplemental JSON rules file to merge with bundled signatures")
    args = ap.parse_args()

    if not os.path.isdir(args.app_dir):
        print(f"error: {args.app_dir!r} is not a directory", file=sys.stderr)
        sys.exit(2)

    rules = list(RULES)
    if args.rules:
        try:
            with open(args.rules) as fh:
                extra = json.load(fh)
            for r in extra:
                required_keys = {"pat", "name", "class", "sev", "fix"}
                missing_keys = required_keys - set(r.keys())
                if missing_keys:
                    print(f"error: rule {r.get('name', '?')!r} in --rules file missing keys: {', '.join(sorted(missing_keys))}", file=sys.stderr)
                    sys.exit(2)
                try:
                    re.compile(r["pat"])
                except re.error as exc:
                    print(f"error: invalid regex in --rules file rule {r.get('name', '?')!r}: {exc}", file=sys.stderr)
                    sys.exit(2)
                if r["sev"] not in SEV:
                    print(f"error: rule {r['name']!r} has invalid sev {r['sev']!r}; must be one of {list(SEV)}", file=sys.stderr)
                    sys.exit(2)
            rules.extend(extra)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error loading --rules file: {exc}", file=sys.stderr)
            sys.exit(2)

    recent, findings = {}, []
    for rel, lineno, line in scan_files(args.app_dir):
        findings.extend(match_rules(rel, lineno, line, rules, recent))

    report_findings(findings, args.severity)


if __name__ == "__main__":
    main()