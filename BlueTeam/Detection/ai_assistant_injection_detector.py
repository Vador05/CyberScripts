"""AI Coding Assistant Prompt Injection Detector

Scans plain-text IDE and AI coding assistant activity logs for prompt-injection
signatures that mirror the Amazon Q CVE attack pattern. Correlates injection,
credential-access, and egress indicators within a sliding line window to surface
high-confidence exfiltration chains.

Usage:
    python ai_assistant_injection_detector.py activity.log
    python ai_assistant_injection_detector.py activity.log --window 30 --cve CVE-2025-4318
    python ai_assistant_injection_detector.py activity.log --window 10
"""

import argparse
import re
import sys
from collections import deque, defaultdict
from datetime import datetime

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def load_rules():
    I = re.IGNORECASE
    return {
        "injection": [
            re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions?", I),
            re.compile(r"disregard\s+(?:your\s+)?(?:previous\s+)?instructions?", I),
            re.compile(r"override\s+(?:your\s+)?(?:instructions?|system\s+prompt)", I),
            re.compile(r"forget\s+(?:all\s+)?previous\s+(?:instructions?|context)", I),
            re.compile(r"you\s+are\s+now\s+(?:a|an)\s+\w{1,40}", I),
            re.compile(r"new\s+system\s+prompt\s*:", I),
            re.compile(r"your\s+new\s+(?:role|instructions?|task)\s+is\b", I),
            re.compile(r"do\s+not\s+follow\s+(?:previous|original)\s+instructions?", I),
            re.compile(r"from\s+now\s+on[\s,]+you\s+(?:will|must|should)\b", I),
        ],
        "credential": [
            re.compile(r"AKIA[A-Z0-9]{16}"),
            re.compile(r"AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)\b", I),
            re.compile(r"\.aws[/\\]credentials\b", I),
            re.compile(r"AZURE_(?:CLIENT_SECRET|TENANT_ID|CLIENT_ID)\b", I),
            re.compile(r"GOOGLE_APPLICATION_CREDENTIALS\b", I),
            re.compile(r"gcloud\s+auth\s+print-access-token\b", I),
            re.compile(r"169\.254\.169\.254"),
            re.compile(r"instance[\s_-]?metadata[\s_-]?service|imdsv?2\b", I),
            re.compile(r"~[/\\]\.config[/\\]gcloud\b", I),
        ],
        "egress": [
            re.compile(r"\bcurl\b.{0,200}https?://(?!localhost\b|127\.0\.0\.1\b)", I),
            re.compile(r"\bwget\b.{0,200}https?://(?!localhost\b|127\.0\.0\.1\b)", I),
            re.compile(r"requests\.post\s*\(\s*['\"]https?://(?!localhost|127\.0\.0\.1)", I),
            re.compile(r"\bPOST\s+https?://(?!localhost\b|127\.0\.0\.1\b)", I),
            re.compile(r"[A-Za-z0-9+/]{60,200}={0,2}(?=\s|$)"),
            re.compile(r"exfil(?:trat\w{0,10})?\b|send\s+credentials?\b", I),
            re.compile(r"\bnc\s+[\w.\-]{1,50}\s+\d{2,5}\b", I),
            re.compile(r"base64.{0,20}(?:curl|wget|nc)\b", I),
        ],
    }


def safe_snippet(text):
    return _ANSI.sub("", text)[:120]


def scan_log(path, rules, window, cve_tag):
    findings = defaultdict(int)
    alerts = []
    window_hits = deque()

    try:
        with open(path, errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        print(f"ERROR: cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(2)

    ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    cve = f" [{cve_tag}]" if cve_tag else ""

    for lineno, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")[:2000]
        for cat, patterns in rules.items():
            for pat in patterns:
                m = pat.search(line)
                if m:
                    match_text = m.group(0)[:80]
                    findings[cat] += 1
                    window_hits.append((lineno, cat, match_text))
                    print(f"{ts} INFO  line={lineno} cat={cat}{cve} match={match_text!r}")
                    break

        while window_hits and window_hits[0][0] < lineno - window + 1:
            window_hits.popleft()

        cats_present = {h[1] for h in window_hits}
        if cats_present >= {"injection", "credential", "egress"}:
            start = window_hits[0][0]
            alerts.append((start, lineno))
            snip = safe_snippet(line)
            print(f"{ts} ALERT chain=injection+credential+egress lines={start}-{lineno}{cve} evidence={snip!r}")
            window_hits.clear()

    return findings, alerts


def report_summary(findings, alerts):
    cats = ["injection", "credential", "egress"]
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for cat in cats:
        print(f"  {cat:<22} {findings.get(cat, 0):>4} hit(s)")
    print(f"  {'chains (ALERT)':<22} {len(alerts):>4}")
    print("=" * 60)
    verdict = "CRITICAL" if alerts else ("WARN" if any(findings.get(c) for c in cats) else "CLEAN")
    print(f"VERDICT: {verdict}\n")
    return verdict


def main():
    parser = argparse.ArgumentParser(
        description="Detect prompt-injection exfiltration chains in AI assistant logs."
    )
    parser.add_argument("log_file", help="Path to plain-text AI assistant or IDE activity log")
    parser.add_argument("--window", type=int, default=20, help="Sliding line window for chain correlation (default: 20)")
    parser.add_argument("--cve", default="", metavar="CVE-ID", help="CVE tag to annotate output lines")
    args = parser.parse_args()
    if args.window < 1:
        parser.error("--window must be >= 1")
    rules = load_rules()
    findings, alerts = scan_log(args.log_file, rules, args.window, args.cve)
    report_summary(findings, alerts)
    sys.exit(1 if alerts else 0)


if __name__ == "__main__":
    main()