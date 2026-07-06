"""
pwn_request_guard.py - Detect untrusted-input-to-privileged-context flows in GitHub Actions workflows.

Usage:
    python pwn_request_guard.py ./path/to/workflows
    python pwn_request_guard.py .github/workflows/ci.yml --severity high
    python pwn_request_guard.py ./workflows --output json
"""

import argparse
import json
import os
import re
import sys

UNTRUSTED_SOURCES = [
    (r"github\.event\.pull_request\.title", "PR title"),
    (r"github\.event\.pull_request\.body", "PR body"),
    (r"github\.event\.pull_request\.head\.ref", "PR head ref"),
    (r"github\.event\.pull_request\.head\.label", "PR head label"),
    (r"github\.head_ref", "head ref"),
    (r"github\.event\.issue\.title", "issue title"),
    (r"github\.event\.issue\.body", "issue body"),
    (r"github\.event\.comment\.body", "comment body"),
    (r"github\.event\.review\.body", "review body"),
    (r"github\.event\.discussion\.body", "discussion body"),
]

PRIVILEGED_SINK_PATTERNS = [
    (r"^\s{4,}run\s*:", "run block", "high"),
    (r"^\s+env\s*:", "env interpolation", "medium"),
    (r"^\s+if\s*:.*write", "if condition with write check", "medium"),
    (r"curl\s+.*\$\{\{", "curl with expression", "high"),
    (r"bash\s+-c\s+.*\$\{\{", "bash -c with expression", "high"),
]

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


def load_workflows(path):
    results = []
    if os.path.isfile(path):
        if path.endswith(".yml") or path.endswith(".yaml"):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    results.append((path, f.readlines()))
            except OSError as e:
                print(f"Warning: cannot read {path}: {e}", file=sys.stderr)
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for fname in files:
                if fname.endswith(".yml") or fname.endswith(".yaml"):
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                            results.append((fpath, f.readlines()))
                    except OSError as e:
                        print(f"Warning: cannot read {fpath}: {e}", file=sys.stderr)
    else:
        print(f"Error: {path} is not a file or directory", file=sys.stderr)
        sys.exit(1)
    return results


def _find_expression_sources(expr):
    found = []
    for pattern, label in UNTRUSTED_SOURCES:
        if re.search(pattern, expr):
            found.append(label)
    return found


def find_cordyceps(filepath, lines):
    findings = []
    text = "".join(lines)

    expressions = list(re.finditer(r"\$\{\{(.+?)\}\}", text))
    tainted_expressions = []
    for m in expressions:
        inner = m.group(1)
        sources = _find_expression_sources(inner)
        if sources:
            tainted_expressions.append((m.start(), m.end(), sources, inner.strip()))

    if not tainted_expressions:
        return findings

    line_offsets = []
    offset = 0
    for line in lines:
        line_offsets.append(offset)
        offset += len(line)

    def offset_to_lineno(off):
        lo, hi = 0, len(line_offsets) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_offsets[mid] <= off:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    for expr_start, expr_end, sources, raw in tainted_expressions:
        lineno = offset_to_lineno(expr_start)
        line_text = lines[lineno - 1] if lineno <= len(lines) else ""

        sink_label = None
        severity = "low"

        for sink_pat, slabel, ssev in PRIVILEGED_SINK_PATTERNS:
            if re.search(sink_pat, line_text, re.IGNORECASE):
                sink_label = slabel
                severity = ssev
                break

        if sink_label is None:
            context_start = max(0, lineno - 6)
            context_end = min(len(lines), lineno + 2)
            context = "".join(lines[context_start:context_end])
            for sink_pat, slabel, ssev in PRIVILEGED_SINK_PATTERNS:
                if re.search(sink_pat, context, re.IGNORECASE):
                    sink_label = slabel
                    severity = ssev
                    break

        if sink_label is None:
            sink_label = "expression context"
            severity = "low"

        source_str = ", ".join(sources)
        description = f"Untrusted input ({source_str}) flows into {sink_label} via '${{{{ {raw} }}}}'"
        findings.append({
            "file": filepath,
            "line": lineno,
            "severity": severity,
            "rule": "cordyceps-pattern",
            "description": description,
        })

    return findings


def report(findings, severity_floor, fmt):
    floor_rank = SEVERITY_RANK.get(severity_floor, 0)
    filtered = [f for f in findings if SEVERITY_RANK.get(f["severity"], 0) >= floor_rank]
    filtered.sort(key=lambda x: (x["file"], x["line"]))

    if fmt == "json":
        print(json.dumps(filtered, indent=2))
    else:
        for f in filtered:
            print(f"{f['file']}:{f['line']} [{f['severity'].upper()}] {f['rule']}: {f['description']}")

    return len(filtered)


def main():
    parser = argparse.ArgumentParser(
        description="Scan GitHub Actions workflows for pwn-request (Cordyceps) patterns.",
        epilog="Example: python pwn_request_guard.py .github/workflows --severity medium --output json",
    )
    parser.add_argument("path", help="Directory or single .yml/.yaml file to scan")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum severity to report (default: low)")
    parser.add_argument("--output", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
    args = parser.parse_args()

    workflows = load_workflows(args.path)
    if not workflows:
        print("No workflow files found.", file=sys.stderr)
        sys.exit(0)

    all_findings = []
    for filepath, lines in workflows:
        all_findings.extend(find_cordyceps(filepath, lines))

    count = report(all_findings, args.severity, args.output)
    sys.exit(1 if count > 0 else 0)


if __name__ == "__main__":
    main()