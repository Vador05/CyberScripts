"""
GitHub Actions Packagist Abuse Detector

Scans a locally cloned repository's GitHub Actions workflow files and
Composer manifests for indicators of supply-chain compromise via malicious
Packagist dev-version packages targeting cPanel/WHM hosting credentials.

Usage:
    python github_actions_packagist_abuse_detector.py /path/to/repo
    python github_actions_packagist_abuse_detector.py /path/to/repo --severity medium
    python github_actions_packagist_abuse_detector.py /path/to/repo --iocs extra.json --severity high
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict

RULES = {
    "Injection": [
        ("MinStabilityDev",       r'"minimum-stability"\s*:\s*"dev"'),
        ("DevVersionConstraint",  r'composer\s+require\s+\S+\s+dev-\S+'),
        ("ComposerSuperuserEnv",  r'COMPOSER_ALLOW_SUPERUSER\s*[=:]\s*1'),
        ("DevConstraintLockfile", r'"version"\s*:\s*"dev-'),
    ],
    "Harvesting": [
        ("CPanelCredential", r'\b(CPANEL_PASS|CPANEL_USER|CPANEL_TOKEN|CP_PASS)\b'),
        ("WHMCredential",    r'\b(WHM_TOKEN|WHM_API_KEY|WHM_PASS|WHM_USER|WHMAPITOKEN)\b'),
        ("CPanelPort",       r':(2083|2087)\b'),
        ("WHMAPICall",       r'\b(whmapi1|cpapi2|whm\.cgi)\b'),
        ("CPanelAPIPath",    r'/json-api/(cpanel|whm)\b'),
    ],
    "Exfiltration": [
        ("CurlPost",       r'curl\s[^\n]*(-X\s*POST|--data(?:-raw)?|-d\s)'),
        ("WgetPost",       r'wget\s[^\n]*(--post-data|--post-file)'),
        ("Base64Decode",   r'\bbase64\b[^\n]*(--decode|-d\b)'),
        ("DiscordWebhook", r'discord\.com/api/webhooks/\d+/'),
        ("TelegramBot",    r'api\.telegram\.org/bot[A-Za-z0-9_:-]+/'),
    ],
}

BASE_SEVERITY = {"Injection": "low", "Harvesting": "medium", "Exfiltration": "medium"}
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
MAX_FILE_BYTES = 256 * 1024


def load_iocs(path):
    with open(path) as f:
        extra = json.load(f)
    for stage, entries in extra.items():
        if stage not in RULES:
            RULES[stage] = []
        for e in entries:
            RULES[stage].append((e["name"], e["pattern"]))


def scan_repo(repo_path):
    wf_dir = os.path.join(repo_path, ".github", "workflows")
    candidates = []
    if os.path.isdir(wf_dir):
        for name in os.listdir(wf_dir):
            if name.endswith((".yml", ".yaml")):
                candidates.append(os.path.join(wf_dir, name))
    for cfile in ("composer.json", "composer.lock"):
        p = os.path.join(repo_path, cfile)
        if os.path.isfile(p):
            candidates.append(p)
    for fpath in candidates:
        try:
            if os.path.getsize(fpath) > MAX_FILE_BYTES:
                continue
            with open(fpath, encoding="utf-8") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError):
            continue
        yield os.path.relpath(fpath, repo_path), content


def match_file(rel_path, content, min_severity):
    hits_by_stage = defaultdict(list)
    for stage, rules in RULES.items():
        for name, pattern in rules:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                start = max(0, m.start() - 20)
                snippet = content[start:m.end() + 80].replace("\n", " ")[:120]
                hits_by_stage[stage].append((name, snippet))

    injection = bool(hits_by_stage["Injection"])
    escalate = injection and (hits_by_stage["Harvesting"] or hits_by_stage["Exfiltration"])

    findings = []
    for stage, hits in hits_by_stage.items():
        sev = "high" if escalate else BASE_SEVERITY.get(stage, "medium")
        if SEVERITY_RANK[sev] < SEVERITY_RANK[min_severity]:
            continue
        for name, snippet in hits:
            findings.append((sev, rel_path, stage, name, snippet))
    return findings


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("repo_path", help="Local path to cloned repository")
    parser.add_argument("--iocs", metavar="FILE", help="Supplemental IOC JSON file")
    parser.add_argument(
        "--severity", choices=["low", "medium", "high"], default="low",
        help="Minimum alert level to emit (default: low)",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"ERROR: not a directory: {args.repo_path}", file=sys.stderr)
        sys.exit(2)

    if args.iocs:
        try:
            load_iocs(args.iocs)
        except (OSError, json.JSONDecodeError, KeyError) as e:
            print(f"ERROR loading --iocs: {e}", file=sys.stderr)
            sys.exit(2)

    stage_counts = defaultdict(int)
    peak = 0
    total = 0

    for rel_path, content in scan_repo(args.repo_path):
        for sev, path, stage, tech, snippet in match_file(rel_path, content, args.severity):
            print(f"[{sev.upper():<6}] {path} | {stage:<12} | {tech:<28} | {snippet}")
            stage_counts[stage] += 1
            peak = max(peak, SEVERITY_RANK[sev])
            total += 1

    rank_label = {0: "low", 1: "medium", 2: "high"}
    print("\n--- Summary ---")
    for stage in ("Injection", "Harvesting", "Exfiltration"):
        print(f"  {stage:<14}: {stage_counts[stage]} hit(s)")
    print(f"  Peak severity  : {rank_label[peak].upper()}")
    print(f"  Total findings : {total}")

    if peak == SEVERITY_RANK["high"]:
        sys.exit(1)


if __name__ == "__main__":
    main()