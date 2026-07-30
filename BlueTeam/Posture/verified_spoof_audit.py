"""
verified_spoof_audit - Audit a git log text export for GitHub Verified badge spoofing.

Usage:
    git log --all --format='%H|%ae|%G?|%GK|%s' > gitlog.txt
    python verified_spoof_audit.py gitlog.txt
    python verified_spoof_audit.py gitlog.txt --severity medium
    python verified_spoof_audit.py gitlog.txt --severity high --pr-only
"""

import argparse
import re
import sys
from collections import defaultdict

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
MERGE_RE = re.compile(r"Merge (pull request|branch)\b", re.IGNORECASE)
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
NOTES = {
    "HashCollision": "Reject and re-create this commit; duplicate SHA indicates a crafted content swap",
    "SignatureSpoof": "Re-sign with a valid unexpired key and cross-check via GitHub Signature Verification API",
    "KeyMismatch": "Audit all commits under this key; revoke and rotate if key integrity is compromised",
    "UnsignedMerge": "Require signed merge commits via branch protection or a repository GPG signing policy",
}


def parse_log(path, pr_only):
    entries, dropped = [], 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("|", 4)
            if len(parts) < 5 or not SHA_RE.match(parts[0]):
                dropped += 1
                continue
            commit_hash, email, gpg_status, key_id, subject = parts
            if pr_only and not MERGE_RE.search(subject):
                continue
            entries.append((commit_hash, email, gpg_status, key_id, subject))
    return entries, dropped


def detect_spoof_risk(entries):
    seen = defaultdict(list)
    key_good, key_bad = set(), set()
    for commit_hash, email, gpg_status, key_id, subject in entries:
        seen[commit_hash].append((email, gpg_status, key_id, subject))
        if key_id:
            if gpg_status in ("G", "U"):
                key_good.add(key_id)
            elif gpg_status in ("B", "E"):
                key_bad.add(key_id)

    key_mismatch = key_good & key_bad

    for commit_hash, items in seen.items():
        if len(items) > 1:
            for email, gpg_status, key_id, subject in items:
                yield "HashCollision", "high", commit_hash, email, key_id, NOTES["HashCollision"]

    for commit_hash, email, gpg_status, key_id, subject in entries:
        if gpg_status in ("B", "X"):
            yield "SignatureSpoof", "medium", commit_hash, email, key_id, NOTES["SignatureSpoof"]
        if key_id and gpg_status in ("B", "E") and key_id in key_mismatch:
            yield "KeyMismatch", "medium", commit_hash, email, key_id, NOTES["KeyMismatch"]
        if MERGE_RE.search(subject) and gpg_status == "N":
            yield "UnsignedMerge", "low", commit_hash, email, key_id, NOTES["UnsignedMerge"]


def report_findings(entries, dropped, findings_iter, min_severity):
    min_rank = SEVERITY_RANK[min_severity]
    counts = defaultdict(int)
    collision_keys, spoof_keys = set(), set()
    exit_nonzero = False

    for rule_class, severity, commit_hash, email, key_id, note in findings_iter:
        if SEVERITY_RANK[severity] < min_rank:
            continue
        counts[rule_class] += 1
        print(f"[{severity.upper()}] {rule_class} {commit_hash[:12]} <{email}> \u2014 {note}")
        if rule_class == "HashCollision":
            exit_nonzero = True
            if key_id:
                collision_keys.add(key_id)
        elif rule_class == "SignatureSpoof":
            exit_nonzero = True
            if key_id:
                spoof_keys.add(key_id)

    total = len(entries)
    unsigned = sum(1 for e in entries if e[2] == "N")
    ratio = (unsigned / total * 100) if total else 0.0

    print("\n=== Summary ===")
    print(f"Total commits scanned  : {total}")
    print(f"Unsigned commits       : {unsigned}/{total} ({ratio:.1f}%)")
    if dropped:
        print(f"Malformed lines dropped: {dropped}")
    for rule in ("HashCollision", "SignatureSpoof", "KeyMismatch", "UnsignedMerge"):
        if counts[rule]:
            print(f"  {rule}: {counts[rule]}")

    if exit_nonzero and (collision_keys & spoof_keys):
        print(
            "\n!!! CRITICAL: HashCollision and SignatureSpoof co-occur in the same key scope \u2014"
            " GitHub Verified badge is actively spoofable on merged PRs. Immediate audit required."
        )

    return exit_nonzero


def main():
    parser = argparse.ArgumentParser(
        description="Audit a git log export for GitHub Verified badge spoofing risks."
    )
    parser.add_argument(
        "log_file",
        help="Path to git log file (git log --all --format='%%H|%%ae|%%G?|%%GK|%%s')",
    )
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum alert severity to emit (default: low)",
    )
    parser.add_argument(
        "--pr-only",
        action="store_true",
        help="Restrict analysis to merge commits matching 'Merge pull request' or 'Merge branch'",
    )
    args = parser.parse_args()

    try:
        entries, dropped = parse_log(args.log_file, args.pr_only)
    except FileNotFoundError:
        print(f"error: log file not found: {args.log_file}", file=sys.stderr)
        sys.exit(2)
    except OSError as exc:
        print(f"error reading log file: {exc}", file=sys.stderr)
        sys.exit(2)

    if report_findings(entries, dropped, detect_spoof_risk(entries), args.severity):
        sys.exit(1)


if __name__ == "__main__":
    main()