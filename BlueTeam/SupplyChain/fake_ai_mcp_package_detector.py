"""
Fake AI Tool & MCP Server Package Detector

Scans pip requirements files, npm package manifests, or plain-text install logs
for packages fraudulently impersonating AI tools or MCP servers.

Usage:
    python fake_ai_mcp_package_detector.py requirements.txt
    python fake_ai_mcp_package_detector.py package-lock.json --threshold 0.75
    python fake_ai_mcp_package_detector.py install.log --min-severity MEDIUM
"""

import argparse
import json
import re
import sys
from pathlib import Path

AI_BASELINE = [
    "openai", "openai-python", "openai-node", "openai-whisper",
    "anthropic", "anthropic-sdk", "anthropic-python",
    "langchain", "langchain-core", "langchain-community", "langchain-openai", "langchain-anthropic",
    "llamaindex", "llama-index", "llama-index-core",
    "mcp", "mcp-server", "mcp-client", "mcp-sdk",
    "copilot", "github-copilot", "gpt4", "gpt-4",
    "transformers", "huggingface-hub", "langsmith", "langgraph", "autogen", "crewai",
]

AI_KEYWORDS = {"openai", "anthropic", "langchain", "llamaindex", "claude", "copilot", "gpt", "llm"}
MCP_PAT = re.compile(r"mcp[-_]?(server|client|sdk|tool|hub|agent)", re.I)
FRESH_VER = re.compile(r"^0\.(0\.)?\d+(\.\d+)?$")
REQ_RE = re.compile(r"^([\w][\w.-]*)(?:\[[\w,]+\])?==([^\s;#]+)")
LOG_RE = re.compile(r"[Ii]nstalling\s+([\w][\w.-]*)-(\d[\w.]*)(?:\s|$)")
NPM_LOG_RE = re.compile(r"^\+\s+([\w@][\w./@-]*)@(\d[\w.]*)")

NORM = lambda s: re.sub(r"[-_.]", "", s.lower())


def bigrams(s):
    s = NORM(s)
    return set(s[i:i+2] for i in range(len(s) - 1)) if len(s) > 1 else set()


def similarity(a, b):
    ba, bb = bigrams(a), bigrams(b)
    return 2 * len(ba & bb) / (len(ba) + len(bb)) if ba and bb else 0.0


def parse_packages(path):
    text = path.read_text(errors="replace")
    pkgs = []
    if text.lstrip().startswith("{"):
        try:
            data = json.loads(text)
            for section in ("dependencies", "packages"):
                for name, info in data.get(section, {}).items():
                    if isinstance(info, dict) and "version" in info:
                        pkgs.append((re.sub(r"^node_modules/", "", name), info["version"], "npm"))
        except Exception:
            for m in re.finditer(r'"([\w@][\w./@-]*)"\s*:\s*\{[^{]{0,500}"version"\s*:\s*"([^"]+)"', text, re.S):
                pkgs.append((re.sub(r"^node_modules/", "", m.group(1)), m.group(2), "npm"))
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for pat, reg in ((REQ_RE, "pip"), (LOG_RE, "pip"), (NPM_LOG_RE, "npm")):
                m = pat.match(line)
                if m:
                    pkgs.append((m.group(1), m.group(2), reg))
                    break
    return pkgs


def score(name, version, threshold):
    low = name.lower()
    if any(NORM(b) == NORM(low) for b in AI_BASELINE):
        return []
    is_mcp = bool(MCP_PAT.search(low))
    is_ai = is_mcp or any(kw in low for kw in AI_KEYWORDS)
    is_fresh = bool(FRESH_VER.match(version)) if version else False
    best, bscore = None, 0.0
    for base in AI_BASELINE:
        s = similarity(name, base)
        if s > bscore:
            bscore, best = s, base
    is_typo = bscore >= threshold
    h_i = "Remove and verify from official registry; freshly-registered impersonator pattern."
    h_t = "Confirm correct package name against official AI-library registry entry."
    if is_ai and is_fresh:
        ft = "MCPFake" if is_mcp else "AIImpersonation"
        return [("HIGH", ft, best or "ai-keyword", h_i), ("HIGH", "NewlyPublished", f"version={version}", h_i)]
    if is_typo and is_fresh:
        return [("HIGH", "Typosquat", f"{best or 'low-similarity'} ({bscore:.2f})", h_t), ("HIGH", "NewlyPublished", f"version={version}", h_t)]
    if is_ai:
        ft = "MCPFake" if is_mcp else "AIImpersonation"
        return [("MEDIUM", ft, best or "ai-keyword", "Verify publisher on PyPI/npm; matches AI/MCP impersonation pattern.")]
    if is_typo:
        return [("MEDIUM", "Typosquat", f"{best or 'low-similarity'} ({bscore:.2f})", h_t)]
    if best is not None and bscore >= threshold - 0.1:
        return [("LOW", "Typosquat", f"{best} ({bscore:.2f})", "Near-threshold match; review manually before enabling as CI gate.")]
    return []


def main():
    ap = argparse.ArgumentParser(description="Detect fake AI/MCP packages in dependency manifests.")
    ap.add_argument("input_file", help="requirements.txt, package-lock.json, or install log")
    ap.add_argument("--threshold", type=float, default=0.72, help="Bigram similarity threshold 0.0-1.0 (default: 0.72)")
    ap.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH"], default="LOW")
    args = ap.parse_args()

    if not 0.0 <= args.threshold <= 1.0:
        print(f"Error: --threshold must be between 0.0 and 1.0, got {args.threshold}", file=sys.stderr)
        sys.exit(2)

    path = Path(args.input_file)
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(2)
    try:
        packages = parse_packages(path)
    except Exception as e:
        print(f"Error parsing {path}: {e}", file=sys.stderr)
        sys.exit(2)
    if not packages:
        print("No packages found in input.")
        sys.exit(0)

    rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    min_r = rank[args.min_severity]
    counts, peak, any_high = {}, 0, False

    for name, version, registry in packages:
        for sev, ftype, match, hint in score(name, version, args.threshold):
            if rank[sev] < min_r:
                continue
            counts[ftype] = counts.get(ftype, 0) + 1
            peak = max(peak, rank[sev])
            any_high = any_high or sev == "HIGH"
            print(f"[{sev}] {name}=={version} ({registry}) | {ftype} | match={match} | {hint}")

    print("\n--- Tally ---")
    for ftype, cnt in sorted(counts.items()):
        print(f"  {ftype}: {cnt}")
    print(f"  Peak severity: {({3: 'HIGH', 2: 'MEDIUM', 1: 'LOW'}.get(peak) or 'none')}")
    sys.exit(1 if any_high else 0)


if __name__ == "__main__":
    main()