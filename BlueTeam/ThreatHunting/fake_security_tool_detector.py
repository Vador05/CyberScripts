"""
fake_security_tool_detector.py - Hunt GitHub for repositories impersonating legitimate security tools.

Usage:
    python fake_security_tool_detector.py mimikatz
    python fake_security_tool_detector.py nmap --token ghp_xxx --min-score 4
    python fake_security_tool_detector.py burpsuite --token ghp_xxx

Exit code 1 if any repository meets or exceeds --min-score.
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

RULES = [
    {"name": "typosquat_leet", "pattern": r"(?i)[0o][a-z]{2,}|[a-z]{2,}[0o][a-z]+|[1il][a-z]{2,}"},
    {"name": "version_lure", "pattern": r"(?i)[-_](v\d|pro|plus|cracked|free|premium|2024|2025|latest|new)"},
    {"name": "infostealer_keyword", "pattern": r"(?i)\b(stealer|grabber|exfil|exfiltrat|clipper|keylog)\b"},
    {"name": "credential_keyword", "pattern": r"(?i)\b(credentials?|cookies?|passwords?|tokens?|wallet)\b"},
    {"name": "download_lure", "pattern": r"(?i)\b(release|download|installer|setup\.exe|\.zip|\.rar)\b"},
    {"name": "c2_link", "pattern": r"(?i)(discord\.gg/|t\.me/|telegram\.me/)"},
    {"name": "social_engineering", "pattern": r"(?i)\b(free|crack|bypass|undetect|fud|hack|cheat|exploit)\b"},
    {"name": "hyphen_insertion", "pattern": r"(?i)[-_][a-z]{3,}[-_][a-z]{3,}"},
]

_compiled = [(r, re.compile(r["pattern"])) for r in RULES]
DOWNLOAD_RE = re.compile(r"(?i)(release|download|\.exe|\.zip|\.rar|setup|installer)", re.I)
TYPOSQUAT_RE = re.compile(r"(?i)(typosquat_leet|version_lure|hyphen_insertion)")


def search_repos(tool_name: str, token: str | None) -> list:
    results = []
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "fake-tool-detector/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for page in range(1, 4):
        url = (
            f"https://api.github.com/search/repositories"
            f"?q={urllib.request.quote(tool_name)}&sort=updated&per_page=30&page={page}"
        )
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 403:
                sys.exit("Rate limit exceeded or auth failure. Provide --token or wait before retrying.")
            if e.code == 401:
                sys.exit("Invalid GitHub token. Check --token value.")
            sys.exit(f"GitHub API error {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            sys.exit(f"Network error: {e.reason}")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            sys.exit(f"Failed to parse GitHub API response: {e.msg}")
        items = data.get("items", [])
        if not items:
            break
        now = datetime.now(timezone.utc)
        for item in items:
            created_at = item.get("created_at") or ""
            try:
                created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                age_days = (now - created).days
            except (KeyError, ValueError, AttributeError):
                age_days = 0
            results.append({
                "name": item.get("name", ""),
                "full_name": item.get("full_name", ""),
                "description": item.get("description") or "",
                "homepage": item.get("homepage") or "",
                "topics": " ".join(item.get("topics") or []),
                "language": item.get("language") or "",
                "stars": item.get("stargazers_count", 0),
                "age_days": age_days,
                "url": item.get("html_url", ""),
            })
    return results


def score_repo(repo: dict, tool_name: str) -> tuple[int, list[str]]:
    blob = " ".join([repo["name"], repo["description"], repo["homepage"], repo["topics"]]).lower()
    tool_low = tool_name.lower()
    score = 0
    matched: list[str] = []

    if tool_low not in repo["name"].lower() and tool_low not in repo["full_name"].lower():
        return 0, []

    for rule, pattern in _compiled:
        if pattern.search(blob):
            matched.append(rule["name"])
            score += 1

    if repo["age_days"] < 14 and tool_low in repo["name"].lower():
        matched.append("new_repo_age")
        score += 2

    typosquat_hit = any(TYPOSQUAT_RE.search(m) for m in matched)
    download_hit = bool(DOWNLOAD_RE.search(blob))
    if typosquat_hit and download_hit:
        score += 2

    return min(score, 10), matched


def report_findings(repos: list, tool_name: str, min_score: int) -> bool:
    flagged = 0
    rule_hits: dict[str, int] = defaultdict(int)
    alerts = []

    for repo in repos:
        score, matched = score_repo(repo, tool_name)
        if score >= min_score:
            flagged += 1
            for r in matched:
                rule_hits[r] += 1
            desc = repo["description"][:120]
            alerts.append((score, matched, repo, desc))

    alerts.sort(key=lambda x: -x[0])
    for score, matched, repo, desc in alerts:
        rules_str = ",".join(matched)
        print(
            f"[SCORE {score:2d}] [{rules_str}] {repo['url']} "
            f"stars={repo['stars']} age={repo['age_days']}d | {desc}"
        )

    total = len(repos)
    print(f"\n--- Summary: scanned={total} flagged={flagged} tool={tool_name} min_score={min_score} ---")
    if rule_hits:
        print("Rule hit frequency:")
        for rule, count in sorted(rule_hits.items(), key=lambda x: -x[1]):
            print(f"  {count:3d}  {rule}")

    return flagged > 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Hunt GitHub for fake security tool repositories.")
    parser.add_argument("tool_name", help="Name of the legitimate security tool to hunt impersonators of")
    parser.add_argument("--token", default=None, help="GitHub personal access token (raises rate limit to 5000/hr)")
    parser.add_argument("--min-score", type=int, default=2, metavar="N", help="Minimum suspicion score 1-10 to emit alert (default 2)")
    args = parser.parse_args()

    if not 1 <= args.min_score <= 10:
        sys.exit("--min-score must be between 1 and 10")

    repos = search_repos(args.tool_name, args.token)
    if not repos:
        print(f"No repositories found for '{args.tool_name}'.")
        sys.exit(0)

    any_flagged = report_findings(repos, args.tool_name, args.min_score)
    sys.exit(1 if any_flagged else 0)


if __name__ == "__main__":
    main()