"""
fakegit_repo_threat_hunter.py - Scans CI/CD logs, bash history, git configs for FakeGit SmartLoader/StealC campaign indicators.

Usage:
    python fakegit_repo_threat_hunter.py pipeline.log
    python fakegit_repo_threat_hunter.py ~/.bash_history --min-score 60
    python fakegit_repo_threat_hunter.py ci_output.txt --iocs extra_iocs.json --min-score 40

Exit code 1 on any HIGH-severity finding.
"""

import argparse
import json
import re
import sys
from collections import defaultdict

AI_KEYWORDS = ["openai", "anthropic", "langchain", "mcp-server", "mcp_server", "claude", "copilot", "gpt", "ollama", "huggingface", "llamaindex"]

BASELINE_REPOS = [
    "openai/openai-python", "anthropics/anthropic-sdk-python", "langchain-ai/langchain",
    "modelcontextprotocol/servers", "microsoft/vscode-copilot", "ollama/ollama",
    "huggingface/transformers", "run-llama/llama_index", "openai/chatgpt-retrieval-plugin",
    "anthropics/claude-quickstarts", "openai/whisper", "facebookresearch/llama",
]

PAYLOAD_EXTS = re.compile(r"\.(ps1|bat|cmd|sh|bin)(\?|$|\s)", re.I)
CRADLE_PATTERNS = [
    re.compile(r"curl\s+.*\|\s*(bash|sh)", re.I),
    re.compile(r"iex\s*\(\s*iwr", re.I),
    re.compile(r"\.DownloadString\s*\(", re.I),
    re.compile(r"Invoke-Expression.*http", re.I),
]

SLUG_RE = re.compile(
    r"(?:github\.com/|raw\.githubusercontent\.com/|git clone\s+(?:https?://github\.com/|git@github\.com:))"
    r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
)
PIP_RE = re.compile(r"(?:pip install|npm install)\s+git\+https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)")


def bigrams(s):
    s = s.lower().replace("-", "").replace("_", "").replace("/", "")
    return set(s[i:i+2] for i in range(len(s)-1))


def bigram_similarity(a, b):
    ba, bb = bigrams(a), bigrams(b)
    if not ba or not bb:
        return 0.0
    return len(ba & bb) / len(ba | bb)


def load_iocs(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        print(f"[WARN] Could not load IOCs from {path}: {e}", file=sys.stderr)
        return {}


def extract_repos(path):
    try:
        with open(path, errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        print(f"[ERROR] Cannot read {path}: {e}", file=sys.stderr)
        sys.exit(2)
    seen = {}
    for lineno, line in enumerate(lines, 1):
        for m in SLUG_RE.finditer(line):
            slug = m.group(1).rstrip(".git")
            if slug not in seen:
                seen[slug] = {"line": lineno, "context": line.rstrip(), "raw_url": "raw.githubusercontent.com" in line}
        for m in PIP_RE.finditer(line):
            slug = m.group(1).rstrip(".git")
            if slug not in seen:
                seen[slug] = {"line": lineno, "context": line.rstrip(), "raw_url": False}
    return seen, lines


def score_repo(slug, meta, lines, ioc_slugs, ioc_paths):
    user, _, repo = slug.partition("/")
    score = 0
    hits = []

    combined = (user + "/" + repo).lower()
    for kw in AI_KEYWORDS:
        if kw in combined:
            score += 30
            hits.append(("AIKeywordImpersonation", "T1195.001"))
            break

    mcp_pat = re.compile(r"mcp[-_]?(?:server|tool|client|plugin|bridge)", re.I)
    if mcp_pat.search(combined):
        score += 20
        hits.append(("MCPNamePattern", "T1195.001"))

    best_sim, best_match = 0.0, ""
    for baseline in BASELINE_REPOS:
        sim = bigram_similarity(slug, baseline)
        if sim > best_sim:
            best_sim, best_match = sim, baseline
    if 0.65 <= best_sim < 1.0 and slug != best_match:
        score += int(best_sim * 35)
        hits.append(("TyposquatMatch", "T1195.001"))

    if slug in ioc_slugs:
        score += 50
        hits.append(("KnownBadSlug", "T1195.001"))

    ctx_line = meta["context"]
    if meta["raw_url"] or "raw.githubusercontent.com" in ctx_line:
        if PAYLOAD_EXTS.search(ctx_line):
            score += 30
            hits.append(("RawPayloadPath", "T1102.001"))
        for path_suffix in ioc_paths:
            if path_suffix in ctx_line:
                score += 20
                hits.append(("KnownBadRawPath", "T1102.001"))

    line_idx = meta["line"] - 1
    window = lines[max(0, line_idx-2):line_idx+3]
    for wline in window:
        for pat in CRADLE_PATTERNS:
            if pat.search(wline):
                score += 35
                hits.append(("SmartLoaderDelivery", "T1059.001"))
                break

    unique_hits = list(dict.fromkeys(hits))
    score = min(score, 100)

    delivery = any(h[0] == "SmartLoaderDelivery" for h in unique_hits)
    impersonation = any(h[0] in ("AIKeywordImpersonation", "MCPNamePattern", "TyposquatMatch", "KnownBadSlug") for h in unique_hits)
    if delivery and impersonation:
        severity = "HIGH"
    elif delivery or impersonation or score >= 50:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return score, severity, unique_hits, best_match if best_sim >= 0.65 else ""


def report_findings(results, min_score):
    tally = defaultdict(int)
    peak = "LOW"
    rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    has_high = False
    count = 0

    for slug, (score, severity, hits, baseline) in results.items():
        if score < min_score:
            continue
        count += 1
        if rank[severity] > rank[peak]:
            peak = severity
        if severity == "HIGH":
            has_high = True
        for h, _ in hits:
            tally[h] += 1
        techniques = " ".join(f"{t}" for _, t in hits)
        heuristics = " ".join(h for h, _ in hits)
        baseline_note = f" (closest: {baseline})" if baseline else ""
        print(f"[{severity}] {slug} score={score} heuristics=[{heuristics}]{baseline_note} techniques=[{techniques}]")

    print(f"\n--- Summary: {count} repos flagged, peak severity={peak} ---")
    for h, c in sorted(tally.items()):
        print(f"  {h}: {c} hit(s)")
    return has_high


def main():
    parser = argparse.ArgumentParser(description="FakeGit Repository Threat Hunter — detects SmartLoader/StealC campaign repos in CI/CD logs")
    parser.add_argument("input_file", help="Plain-text file with GitHub references (CI log, bash history, git config)")
    parser.add_argument("--min-score", type=int, default=40, metavar="N", help="Minimum suspicion score 0-100 to emit alert (default: 40)")
    parser.add_argument("--iocs", metavar="FILE", help="JSON file with additional known-bad slugs and raw-content path suffixes")
    args = parser.parse_args()

    if not 0 <= args.min_score <= 100:
        parser.error("--min-score must be between 0 and 100")

    ioc_slugs, ioc_paths = set(), []
    if args.iocs:
        raw_iocs = load_iocs(args.iocs)
        ioc_slugs = set(raw_iocs.get("slugs", []))
        ioc_paths = raw_iocs.get("raw_paths", [])

    repos, lines = extract_repos(args.input_file)
    print(f"[INFO] Extracted {len(repos)} unique GitHub slugs from {args.input_file}\n")

    results = {}
    for slug, meta in repos.items():
        score, severity, hits, baseline = score_repo(slug, meta, lines, ioc_slugs, ioc_paths)
        results[slug] = (score, severity, hits, baseline)

    has_high = report_findings(results, args.min_score)
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()