"""
AI Pipeline Prompt Injection Detector

Scans plain-text logs from AI-assisted malware analysis pipelines for adversarial
natural language payloads designed to hijack or corrupt the underlying LLM's behavior.

Usage:
    python prompt_injection_detector.py --file sandbox.log
    python prompt_injection_detector.py --file strings.txt --threshold 0.7 --json
    python prompt_injection_detector.py --file output.log --threshold 0.3

Exit codes: 0 = clean, 2 = findings present, 1 = error
"""

import argparse
import json
import re
import sys
from collections import namedtuple
from pathlib import Path

Finding = namedtuple("Finding", ["line_num", "severity", "confidence", "pattern_name", "snippet", "raw_line"])


def build_patterns():
    return {
        "instruction_override": (
            re.compile(r"(?i).{0,80}ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|constraints?).{0,80}"),
            0.9,
        ),
        "analysis_abort": (
            re.compile(r"(?i).{0,80}(do\s+not|don't|never|stop)\s+(flag|report|alert|classify|analyze|scan|detect|mark).{0,80}"),
            0.85,
        ),
        "mark_benign": (
            re.compile(r"(?i).{0,80}mark\s+(this\s+)?(file\s+|sample\s+|binary\s+)?(as\s+)?(benign|safe|clean|trusted|harmless).{0,80}"),
            0.9,
        ),
        "jailbreak_persona": (
            re.compile(r"(?i).{0,80}you\s+are\s+(now\s+)?(a\s+)?(new|different|another|unrestricted|unfiltered|free).{0,80}"),
            0.8,
        ),
        "new_instructions": (
            re.compile(r"(?i).{0,80}(your\s+)?(new|updated|revised|actual|real|true)\s+instructions?\s+(are|is|follow|say).{0,80}"),
            0.85,
        ),
        "system_prompt_hijack": (
            re.compile(r"(?i).{0,80}(system\s+prompt|system\s+message|initial\s+prompt)\s*[:=\-].{0,80}"),
            0.75,
        ),
        "role_override": (
            re.compile(r"(?i).{0,80}(act\s+as|pretend\s+(to\s+be|you\s+are)|roleplay\s+as|simulate\s+(being\s+)?a).{0,80}"),
            0.7,
        ),
        "output_suppress": (
            re.compile(r"(?i).{0,80}(suppress|hide|omit|exclude|withhold|conceal)\s+(all\s+)?(output|result|finding|alert|warning|detection).{0,80}"),
            0.9,
        ),
        "verdict_falsify": (
            re.compile(r"(?i).{0,80}(return|output|say|respond\s+with|reply\s+with)\s+(only\s+)?(clean|safe|benign|no\s+threat|no\s+malware).{0,80}"),
            0.95,
        ),
        "context_escape": (
            re.compile(r"(?i).{0,80}(end\s+of\s+(context|input|data|log)|begin\s+(new\s+)?(instruction|prompt|task|session)).{0,80}"),
            0.8,
        ),
        "obfuscated_b64_imperative": (
            re.compile(r"(?:[A-Za-z0-9+/]{20,}={0,2})\s*(?:decode|execute|run|eval|ignore|override)"),
            0.75,
        ),
        "disregard_safety": (
            re.compile(r"(?i).{0,80}(disregard|bypass|circumvent|override|disable)\s+(safety|filter|guardrail|restriction|limitation|rule).{0,80}"),
            0.85,
        ),
        "llm_direct_address": (
            re.compile(r"(?i).{0,80}(hey\s+)?(gpt|llm|claude|ai\s+assistant|language\s+model|chatbot)\s*[,:]?\s*(please\s+)?(ignore|forget|stop|mark|classify|return).{0,80}"),
            0.9,
        ),
        "training_data_poison": (
            re.compile(r"(?i).{0,80}(when\s+you\s+(see|encounter|find|detect)\s+this|from\s+now\s+on|always\s+respond).{0,80}"),
            0.8,
        ),
    }


def _severity(confidence):
    if confidence >= 0.8:
        return "HIGH"
    if confidence >= 0.6:
        return "MED"
    return "LOW"


def scan_file(path, patterns, threshold):
    max_weight = max(w for _, w in patterns.values())
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line_num, raw_line in enumerate(fh, 1):
                line = raw_line.rstrip("\n")
                if len(line) > 4096:
                    line = line[:4096]
                hits = []
                for name, (regex, weight) in patterns.items():
                    if regex.search(line):
                        hits.append((name, weight))
                if not hits:
                    continue
                top_name, top_weight = max(hits, key=lambda x: x[1])
                confidence = min(1.0, len(hits) * top_weight / max_weight)
                if confidence < threshold:
                    continue
                snippet = line[:120]
                yield Finding(
                    line_num=line_num,
                    severity=_severity(confidence),
                    confidence=round(confidence, 4),
                    pattern_name=top_name,
                    snippet=snippet,
                    raw_line=line,
                )
    except OSError as exc:
        print(f"ERROR: Cannot read file: {exc}", file=sys.stderr)
        sys.exit(1)


def report(findings, use_json):
    total_flagged = 0
    collected = findings if isinstance(findings, list) else list(findings)

    for finding in collected:
        total_flagged += 1
        if use_json:
            obj = {
                "line": finding.line_num,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "pattern": finding.pattern_name,
                "snippet": finding.snippet,
            }
            print(json.dumps(obj))
        else:
            print(f"[{finding.severity}] Line {finding.line_num} | confidence={finding.confidence} | pattern={finding.pattern_name}")
            print(f"  Snippet: {finding.snippet}")
            print()

    return total_flagged


def main():
    parser = argparse.ArgumentParser(
        description="Detect prompt-injection strings in AI malware analysis pipeline logs."
    )
    parser.add_argument("--file", required=True, metavar="PATH", help="Plain-text log or extracted-string file to scan")
    parser.add_argument("--threshold", type=float, default=0.5, metavar="FLOAT", help="Minimum confidence score 0.0-1.0 (default: 0.5)")
    parser.add_argument("--json", action="store_true", dest="use_json", help="Emit findings as newline-delimited JSON")
    args = parser.parse_args()

    if not (0.0 <= args.threshold <= 1.0):
        print("ERROR: --threshold must be between 0.0 and 1.0", file=sys.stderr)
        sys.exit(1)

    target = Path(args.file)
    if not target.exists():
        print(f"ERROR: File not found: {target}", file=sys.stderr)
        sys.exit(1)

    patterns = build_patterns()
    findings = list(scan_file(target, patterns, args.threshold))

    try:
        with open(target, "r", encoding="utf-8", errors="replace") as fh:
            total_lines = sum(1 for _ in fh)
    except OSError as exc:
        print(f"ERROR: Cannot read file: {exc}", file=sys.stderr)
        sys.exit(1)

    flagged = report(findings, args.use_json)

    summary = {"total_flagged": flagged, "total_scanned": total_lines}
    if args.use_json:
        print(json.dumps({"summary": summary}))
    else:
        print(f"Summary: {flagged} flagged / {total_lines} scanned")

    sys.exit(2 if flagged > 0 else 0)


if __name__ == "__main__":
    main()