"""Agentjacking Prompt Injection Lab — scan a cloned repo for AI-agent prompt-injection payloads.
Usage: python agentjacking_lab.py /path/to/repo [--severity high] [--patterns extra.json]
"""
import argparse, json, os, re, sys
from collections import defaultdict

SEV = {"low": 0, "medium": 1, "high": 2}
MAX_SIZE = 512 * 1024

RULES = [
    ("UnicodeSteg", "high",
     r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]+",
     "Strip zero-width/RTL-override chars from repo files before agent processing."),
    ("HiddenInstruction", "high",
     r"(?i)(ignore\s+(all\s+)?(previous|prior)\s+instructions?|disregard\s+your\s+(system\s+)?prompt|you\s+are\s+now\s+a\s+different\s+AI|override\s+(your\s+)?instructions?)",
     "Sandbox repo files containing instruction-override phrases; never pass raw to an agent."),
    ("PromptOverride", "high",
     r"(?i)(new\s+instructions?\s*:|<\s*system\s*>|<\s*\/?instructions?\s*>|\[\s*INST\s*\]|<<SYS>>)",
     "Block agent from ingesting files with prompt-delimiter tokens."),
    ("EncodedPayload", "medium",
     r"(?:b64decode|eval\s*\(|exec\s*\()\s*['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]",
     "Audit eval/exec+base64 calls in setup scripts; run in an isolated environment."),
    ("EncodedPayload", "medium",
     r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{60,}={0,2})(?![A-Za-z0-9+/])",
     "Decode base64 blobs offline to inspect before executing any setup script."),
]

AI_FILES = {
    "AGENTS.md": ("HiddenInstruction", "high"),
    "CLAUDE.md": ("HiddenInstruction", "medium"),
    ".github/copilot-instructions.md": ("HiddenInstruction", "high"),
    ".cursor/rules": ("HiddenInstruction", "medium"),
    ".windsurfrules": ("HiddenInstruction", "medium"),
    ".cursorrules": ("HiddenInstruction", "medium"),
}

SCRIPT_EXTS = {".sh", ".bash", ".py", ".ps1", ".bat", ".cmd"}


def scan_files(repo_path):
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d != ".git"]
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, repo_path)
            try:
                if os.path.getsize(fpath) > MAX_SIZE:
                    continue
                with open(fpath, "rb") as f:
                    content = f.read().decode("utf-8")
                yield rel, content
            except (OSError, UnicodeDecodeError):
                continue


def match_injections(rel_path, content, extra_rules, min_sev):
    results = []
    min_level = SEV[min_sev]
    norm = rel_path.replace("\\", "/")

    for ai_file, (technique, sev) in AI_FILES.items():
        if (norm == ai_file or norm.endswith("/" + ai_file)) and SEV[sev] >= min_level:
            snippet = content[:120].replace("\n", " ")
            results.append((sev, rel_path, technique, snippet,
                            "Audit AI-agent config files for injected instructions before running any agent."))

    ext = os.path.splitext(rel_path)[1].lower()
    rules = RULES + extra_rules
    active = rules if ext in SCRIPT_EXTS else [r for r in rules if r[0] != "EncodedPayload"]

    for (technique, sev, pattern, mitigation) in active:
        if SEV[sev] < min_level:
            continue
        for m in re.finditer(pattern, content):
            results.append((sev, rel_path, technique, m.group(0)[:120].replace("\n", " "), mitigation))

    return results


def report_findings(findings):
    tally = defaultdict(int)
    peak = "low"
    for sev, path, technique, snippet, mitigation in findings:
        tally[technique] += 1
        if SEV[sev] > SEV[peak]:
            peak = sev
        print(f"[{sev.upper()}] {path} | {technique} | {snippet!r} | MITIGATE: {mitigation}")
    print("\n--- Summary ---")
    for t, c in sorted(tally.items()):
        print(f"  {t}: {c} finding(s)")
    print(f"  Peak severity: {peak.upper()} | Total: {sum(tally.values())} finding(s)")
    return peak


def main():
    ap = argparse.ArgumentParser(
        description="Scan a cloned repo for agentjacking prompt-injection payloads.",
        epilog="Example: python agentjacking_lab.py ./suspicious-repo --severity medium",
    )
    ap.add_argument("repo_path", help="Local path to the cloned repository directory")
    ap.add_argument("--patterns", help="JSON file with supplemental regex rules")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum severity to emit (default: low)")
    args = ap.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"ERROR: {args.repo_path!r} is not a directory", file=sys.stderr)
        sys.exit(2)

    extra_rules = []
    if args.patterns:
        try:
            with open(args.patterns) as f:
                data = json.load(f)
            extra_rules = [(r["technique"], r["severity"], r["pattern"], r["mitigation"])
                           for r in data if isinstance(r, dict)]
        except (OSError, json.JSONDecodeError, KeyError) as e:
            print(f"WARNING: Could not load supplemental patterns: {e}", file=sys.stderr)

    all_findings = []
    for rel_path, content in scan_files(args.repo_path):
        all_findings.extend(match_injections(rel_path, content, extra_rules, args.severity))

    if not all_findings:
        print("No agentjacking indicators found.")
        sys.exit(0)

    peak = report_findings(all_findings)
    sys.exit(1 if peak == "high" else 0)


if __name__ == "__main__":
    main()