"""
pwn_request_guard - Scan GitHub Actions workflows for prompt injection vulnerabilities.

Usage:
    python pwn_request_guard.py /path/to/repo
    python pwn_request_guard.py /path/to/repo --severity high
    python pwn_request_guard.py /path/to/repo --rules extra_rules.json
"""

import argparse, json, re, sys
from pathlib import Path

INJECT = [
    (r"\$\{\{\s*github\.event\.issue\.body\s*\}\}", "high",
     "Sanitize issue body; strip shell metacharacters and enforce length limit before AI agent step"),
    (r"\$\{\{\s*github\.event\.pull_request\.body\s*\}\}", "high",
     "Sanitize PR body; strip shell metacharacters and enforce length limit before AI agent step"),
    (r"\$\{\{\s*github\.event\.comment\.body\s*\}\}", "high",
     "Sanitize comment body; strip shell metacharacters and enforce length limit before AI agent step"),
    (r"\$\{\{\s*github\.event\.issue\.title\s*\}\}", "medium",
     "Sanitize issue title before interpolation; titles can carry injection payloads"),
    (r"\$\{\{\s*github\.event\.pull_request\.title\s*\}\}", "medium",
     "Sanitize PR title before interpolation; titles can carry injection payloads"),
    (r"\$\{\{\s*github\.event\.review\.body\s*\}\}", "medium",
     "Sanitize review body before passing to agentic steps"),
]

PRIV = [
    (r"permissions\s*:\s*write-all", "high",
     "Scope to minimum permissions; avoid write-all in issue/PR-triggered workflows"),
    (r"permissions\s*:(?=[\s\S]*?(?:issues|pull-requests)\s*:\s*write)(?=[\s\S]*?contents\s*:\s*write)",
     "high", "Restrict combined write scopes; use read-only for triage workflows"),
]

AGENTIC = [r"actions/ai-inference", r"openai-actions", r"anthropic-run", r"anthropic/claude", r"openai/", r"github-models"]
GUARDS = [r"\bsed\s", r"\btr\s+-d\b", r"\bsanitize\b", r"allow.?list", r"whitelist",
          r"\[[A-Za-z0-9_,\s\\^-]{2,}\]"]
RANK = {"low": 0, "medium": 1, "high": 2}


def load_extra(path):
    try:
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        ei = []
        for p in d.get("injection_patterns", []):
            try:
                pattern = p["pattern"]
                re.compile(pattern)
                ei.append((pattern, p.get("severity", "medium"), p.get("remediation", "Review and sanitize")))
            except KeyError:
                print(f"[WARN] Supplemental injection entry missing 'pattern' key in {path}", file=sys.stderr)
            except re.error as e:
                print(f"[WARN] Skipping invalid injection pattern in {path}: {e}", file=sys.stderr)
        ep = []
        for p in d.get("overprivilege_patterns", []):
            try:
                pattern = p["pattern"]
                re.compile(pattern)
                ep.append((pattern, p.get("severity", "medium"), p.get("remediation", "Review permissions")))
            except KeyError:
                print(f"[WARN] Supplemental overprivilege entry missing 'pattern' key in {path}", file=sys.stderr)
            except re.error as e:
                print(f"[WARN] Skipping invalid overprivilege pattern in {path}: {e}", file=sys.stderr)
        ea = []
        for pattern in d.get("agentic_action_patterns", []):
            try:
                re.compile(pattern)
                ea.append(pattern)
            except re.error as e:
                print(f"[WARN] Skipping invalid agentic pattern in {path}: {e}", file=sys.stderr)
        return ei, ep, ea
    except Exception as e:
        print(f"[WARN] Cannot load supplemental rules {path}: {e}", file=sys.stderr)
        return [], [], []


def _safe_search(pat, text, flags=0):
    try:
        return re.search(pat, text, flags)
    except re.error as e:
        print(f"[WARN] Skipping invalid pattern {pat!r}: {e}", file=sys.stderr)
        return None


def _safe_finditer(pat, text, flags=0):
    try:
        return list(re.finditer(pat, text, flags))
    except re.error as e:
        print(f"[WARN] Skipping invalid pattern {pat!r}: {e}", file=sys.stderr)
        return []


def scan_workflows(repo):
    wf = Path(repo) / ".github" / "workflows"
    if not wf.is_dir():
        return
    wf_resolved = wf.resolve()
    for f in wf.rglob("*"):
        if f.is_symlink():
            continue
        # Reject files that resolve outside the workflows directory; this catches
        # cases where rglob descends into a symlinked subdirectory (the entries
        # inside it are not themselves symlinks, so is_symlink() alone misses them).
        try:
            f.resolve().relative_to(wf_resolved)
        except ValueError:
            continue
        if f.suffix.lower() not in (".yml", ".yaml"):
            continue
        try:
            if f.stat().st_size > 256 << 10:
                continue
            yield str(f.relative_to(repo)), f.read_text(encoding="utf-8")
        except Exception as e:
            print(f"[WARN] Skipping {f}: {e}", file=sys.stderr)


def match_rules(rel, content, inject, priv, agentic, min_sev):
    hits = []
    agentic_present = any(_safe_search(p, content, re.I) for p in agentic)
    guarded = any(_safe_search(p, content, re.I) for p in GUARDS)
    issue_trig = bool(_safe_search(r"on\s*:\s*\[?[^\]]*\b(?:issue_comment|issues|pull_request_review)\b", content, re.I))

    if agentic_present:
        for pat, sev, fix in inject:
            if RANK.get(sev, 0) < RANK[min_sev]:
                continue
            for m in _safe_finditer(pat, content, re.I | re.M):
                hits.append(("InjectionVector", sev, rel, m.group(0)[:120], fix))

    if issue_trig:
        for pat, sev, fix in priv:
            if RANK.get(sev, 0) < RANK[min_sev]:
                continue
            m = _safe_search(pat, content, re.I | re.S)
            if m:
                hits.append(("OverPrivilege", sev, rel, m.group(0)[:120].replace("\n", " "), fix))

    if agentic_present and not guarded and issue_trig and RANK["medium"] >= RANK[min_sev]:
        hits.append(("NoSanitization", "medium", rel,
                     "No input sanitization guard detected before agentic step",
                     "Add character allow-list and length-check step before AI agent input"))
    return hits


def main():
    """
    Scan a locally cloned repository for GitHub Actions workflows vulnerable to
    prompt injection via untrusted issue, PR, or comment content, flagging direct
    context variable interpolation, over-privileged token scopes, and absent guards.

    Example:
        python pwn_request_guard.py /repos/my-project
        python pwn_request_guard.py /repos/my-project --severity medium --rules extra.json
    """
    ap = argparse.ArgumentParser(description="Detect prompt injection vectors in GitHub Actions agentic workflows.",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=main.__doc__)
    ap.add_argument("repo_path", help="Local path to the cloned repository root")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum severity level to emit (default: low)")
    ap.add_argument("--rules", metavar="JSON_FILE", help="Supplemental rules JSON file")
    args = ap.parse_args()

    if not Path(args.repo_path).is_dir():
        print(f"[ERROR] Not a directory: {args.repo_path}", file=sys.stderr)
        sys.exit(2)

    inject, priv, agentic = list(INJECT), list(PRIV), list(AGENTIC)
    if args.rules:
        ei, ep, ea = load_extra(args.rules)
        inject.extend(ei); priv.extend(ep); agentic.extend(ea)

    all_hits = []
    counts = {k: 0 for k in ("InjectionVector", "OverPrivilege", "NoSanitization")}
    peak = "low"

    for rel, content in scan_workflows(args.repo_path):
        for cls, sev, _, snip, fix in match_rules(rel, content, inject, priv, agentic, args.severity):
            print(f"[{sev.upper():6}] [{cls}] {rel}")
            print(f"         Snippet   : {snip}")
            print(f"         Remediate : {fix}")
            counts[cls] += 1
            if RANK.get(sev, 0) > RANK.get(peak, 0):
                peak = sev
            all_hits.append((cls, sev, rel, snip, fix))

    print("\n--- Summary ---")
    for cls, n in counts.items():
        print(f"  {cls}: {n}")
    print(f"  Peak severity : {peak.upper()}")
    print(f"  Total findings: {len(all_hits)}")
    if peak == "high":
        sys.exit(1)


if __name__ == "__main__":
    main()