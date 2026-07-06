"""
Marketplace Skill Risk Scanner - Static analyzer for AI agent skill/plugin files.

Usage:
    python marketplace_skill_risk_scanner.py skill.py
    python marketplace_skill_risk_scanner.py skill.py --threshold 50 --verbose
    python marketplace_skill_risk_scanner.py plugin.js --threshold 75
"""

import argparse
import re
import sys
from pathlib import Path

MAX_FILE_BYTES = 1 * 1024 * 1024  # 1 MB cap to prevent DoS via large crafted files

INDICATORS = {
    "prompt_injection": {
        "weight": 25,
        "patterns": [
            (r"ignore\s+(?:previous|prior|above|all)\s+(?:instructions?|prompts?|rules?)", 8),
            (r"(?:system\s*prompt|system\s*message)\s*(?:override|hijack|replace|inject)", 7),
            (r"<\s*(?:system|assistant|user)\s*>[^\n]{0,500}(?:ignore|disregard|forget)", 6),
            (r"jailbreak|prompt\s*inject|prompt\s*hack", 5),
            (r"new\s+persona|act\s+as\s+[^\n]{0,30}(?:ai|assistant|bot)", 4),
        ],
    },
    "exfiltration": {
        "weight": 30,
        "patterns": [
            (r"(?:requests?|urllib|http\.client)\.(?:get|post|put)\s*\([^\n]{0,500}(?:token|secret|key|password|api_key)", 9),
            (r"(?:webhook|exfil|c2|command.and.control|callback\s*url)", 8),
            (r"send\s*(?:data|payload|content)\s*(?:to|via)\s*(?:http|https|ftp|dns)", 7),
            (r"base64\.(?:encode|decode)\s*\([^\n]{0,500}(?:send|post|upload|transmit)", 6),
            (r"(?:data|content|result)\s*=[^\n]{0,500}requests?\.(?:get|post)\s*\(", 5),
        ],
    },
    "exec_abuse": {
        "weight": 20,
        "patterns": [
            (r"subprocess\.(?:run|call|Popen|check_output)\s*\([^\n]{0,500}shell\s*=\s*True", 9),
            (r"os\.(?:system|popen|execv|execve|spawnl)\s*\(", 8),
            (r"eval\s*\([^\n]{0,500}(?:input|request|user|param|arg)", 7),
            (r"exec\s*\([^\n]{0,500}(?:input|request|user|compile|__import__)", 7),
            (r"__import__\s*\(\s*['\"]os['\"]|importlib\.import_module", 5),
        ],
    },
    "credential_harvesting": {
        "weight": 15,
        "patterns": [
            (r"(?:api_key|secret|token|password|passwd|credential)\s*=\s*os\.(?:environ|getenv)", 7),
            (r"keyring\.(?:get_password|get_credential)|secretstorage", 6),
            (r"\.aws/(?:credentials|config)|\.ssh/id_rsa|\.netrc", 8),
            (r"(?:steal|harvest|dump|scrape)\s*(?:credentials?|passwords?|tokens?|secrets?)", 9),
            (r"input\s*\(\s*['\"][^\n]{0,200}(?:password|secret|token|key)", 5),
        ],
    },
    "obfuscation": {
        "weight": 10,
        "patterns": [
            (r"base64\.b64decode\s*\([^\n]{0,200}\)[^\n]{0,500}(?:exec|eval|compile)", 8),
            (r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){4,}", 6),
            (r"chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\(\s*\d+\s*\)", 5),
            (r"zlib\.(?:decompress|compress)[^\n]{0,500}(?:exec|eval)", 7),
            (r"(?:rot13|caesar|xor)\s*(?:cipher|encode|decode|encrypt)", 4),
        ],
    },
}

# Pre-compile all patterns at module load time; wrap each in a non-capturing group
# so re.findall always returns a flat list of full-match strings regardless of
# internal capturing groups in the pattern.
_COMPILED: dict = {}
for _cat, _cfg in INDICATORS.items():
    _COMPILED[_cat] = {
        "weight": _cfg["weight"],
        "patterns": [
            (re.compile(f"(?:{pat})", re.IGNORECASE), pat, pw)
            for pat, pw in _cfg["patterns"]
        ],
    }


def load_skill(path: str) -> str:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not p.is_file():
        raise ValueError(f"Not a file: {path}")
    try:
        # Read bytes first so the size check is applied to the data actually loaded
        # (avoids a TOCTOU window between stat() and read_text()).
        raw = p.read_bytes()
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError(
                f"File exceeds maximum allowed size ({MAX_FILE_BYTES // 1024} KB): {path}"
            )
        return raw.decode("utf-8", errors="replace").lower()
    except OSError as e:
        raise OSError(f"Cannot read file: {e}") from e


def score_content(text: str) -> dict:
    results = {}
    for category, config in _COMPILED.items():
        matched = []
        raw_score = 0
        for compiled_re, pattern_str, pattern_weight in config["patterns"]:
            hits = compiled_re.findall(text)
            if hits:
                raw_score += pattern_weight
                matched.append({"pattern": pattern_str, "weight": pattern_weight, "hits": len(hits)})
        max_raw = sum(pw for _, _, pw in config["patterns"])
        normalized = min(100, int((raw_score / max_raw) * 100)) if max_raw > 0 else 0
        results[category] = {
            "normalized_score": normalized,
            "category_weight": config["weight"],
            "matched": matched,
        }
    return results


def render_report(scores: dict, threshold: int, verbose: bool) -> int:
    # Accumulate as float and round once to avoid per-term truncation dropping low signals
    composite = round(sum(
        v["normalized_score"] * v["category_weight"] / 100
        for v in scores.values()
    ))
    composite = min(100, composite)

    if composite < 25:
        severity = "LOW"
    elif composite < 50:
        severity = "MEDIUM"
    elif composite < 75:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    verdict = "FAIL" if composite >= threshold else "PASS"

    print(f"{'='*50}")
    print(f"Marketplace Skill Risk Scanner")
    print(f"{'='*50}")
    print(f"Composite Risk Score : {composite}/100")
    print(f"Severity             : {severity}")
    print(f"Threshold            : {threshold}")
    print(f"Verdict              : {verdict}")
    print(f"{'='*50}")
    print("Category Breakdown:")

    for category, data in scores.items():
        matched_count = len(data["matched"])
        print(f"  {category:<25} score={data['normalized_score']:>3}/100  matches={matched_count}")
        if verbose and data["matched"]:
            for m in data["matched"]:
                print(f"      [w={m['weight']:>2}] hits={m['hits']} pattern: {m['pattern'][:60]}")

    print(f"{'='*50}")
    return composite


def main():
    parser = argparse.ArgumentParser(
        description="Statically analyze AI agent skill/plugin files for malicious behavioral indicators.",
        epilog="Example: python marketplace_skill_risk_scanner.py plugin.py --threshold 65 --verbose",
    )
    parser.add_argument("skill_file", help="Path to plain-text skill or plugin source file")
    parser.add_argument("--threshold", type=int, default=65, help="Risk score threshold (0-100) for FAIL verdict")
    parser.add_argument("--verbose", action="store_true", help="Print per-indicator regex match details")
    args = parser.parse_args()

    if not (0 <= args.threshold <= 100):
        parser.error("--threshold must be between 0 and 100")

    try:
        text = load_skill(args.skill_file)
    except (FileNotFoundError, ValueError, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    scores = score_content(text)
    composite = render_report(scores, args.threshold, args.verbose)
    sys.exit(1 if composite >= args.threshold else 0)


if __name__ == "__main__":
    main()