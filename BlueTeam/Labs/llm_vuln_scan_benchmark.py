"""
LLM vs Hybrid Vulnerability Scanner Benchmark

Scans a corpus of plain-text source files with two pipelines — a broad LLM-style
heuristic scanner and a hybrid pipeline that layers separation-logic-inspired context
filters on top — to benchmark false-positive rates between the two approaches.

Usage example:
    python llm_vuln_scan_benchmark.py ./corpus --ground-truth gt.txt --mode detailed
    python llm_vuln_scan_benchmark.py ./corpus
"""

import argparse
import os
import re
import sys
from collections import defaultdict

VULN_PATTERNS = [
    ("sql_injection", re.compile(r'(execute|query|cursor\.execute)\s*\(\s*["\']?\s*SELECT.*?\+', re.IGNORECASE)),
    ("sql_injection", re.compile(r'(execute|query)\s*\(\s*f["\'].*?WHERE', re.IGNORECASE)),
    ("os_command", re.compile(r'(os\.system|subprocess\.call|popen|shell=True)\s*\(', re.IGNORECASE)),
    ("os_command", re.compile(r'(exec|eval)\s*\(\s*[^)]*\binput\b', re.IGNORECASE)),
    ("hardcoded_secret", re.compile(r'(password|secret|api_key|token|passwd)\s*=\s*["\'][^"\']{4,}["\']', re.IGNORECASE)),
    ("hardcoded_secret", re.compile(r'(AWS_SECRET|PRIVATE_KEY|AUTH_TOKEN)\s*=\s*["\'][^"\']+["\']', re.IGNORECASE)),
    ("path_traversal", re.compile(r'open\s*\(\s*[^)]*\+', re.IGNORECASE)),
    ("path_traversal", re.compile(r'(os\.path\.join|open)\s*\([^)]*request\.(args|form|get)', re.IGNORECASE)),
    ("buffer_misuse", re.compile(r'(strcpy|strcat|gets|sprintf)\s*\(', re.IGNORECASE)),
    ("buffer_misuse", re.compile(r'\[\s*[a-zA-Z_]\w*\s*\]\s*=.*without.*bound', re.IGNORECASE)),
]

SANITIZERS = re.compile(
    r'(escape|sanitize|validate|quote|parameteriz|prepared|bindparam|htmlspecialchars|urlencode|strip_tags|bleach)',
    re.IGNORECASE
)
BOUND_CHECKS = re.compile(r'(if\s+\w+\s*[<>]=?\s*\w+|assert\s+\w+|len\s*\(|size\s*\(|bounds|check)', re.IGNORECASE)
COMMENT_OR_TEST = re.compile(r'^\s*(#|//|/\*|\*|\"\"\")', re.IGNORECASE)
TEST_BLOCK = re.compile(r'(def test_|class Test|unittest|pytest|mock)', re.IGNORECASE)


def scan_corpus(corpus_dir, mode, pipeline_label):
    findings = defaultdict(list)
    for root, _, files in os.walk(corpus_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, 1):
                for pname, pattern in VULN_PATTERNS:
                    m = pattern.search(line)
                    if m:
                        hit = (lineno, pname, m.group(0).strip()[:80])
                        findings[fpath].append(hit)
                        if mode == "detailed":
                            print(f"[{pipeline_label}] {fpath}:{lineno} [{pname}] {hit[2]}")
    return findings


def apply_hybrid_filter(raw_findings, corpus_dir):
    filtered = defaultdict(list)
    for fpath, hits in raw_findings.items():
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        for lineno, pname, matched in hits:
            window_start = max(0, lineno - 6)
            window_end = min(len(lines), lineno + 2)
            context = lines[window_start:window_end]
            context_text = "".join(context)
            line_text = lines[lineno - 1] if lineno - 1 < len(lines) else ""
            if COMMENT_OR_TEST.match(line_text):
                continue
            if TEST_BLOCK.search(context_text):
                continue
            if pname in ("sql_injection", "os_command", "path_traversal"):
                if SANITIZERS.search(context_text):
                    continue
            if pname == "buffer_misuse":
                if BOUND_CHECKS.search(context_text):
                    continue
            if pname == "hardcoded_secret":
                if any(re.search(r'(example|placeholder|dummy|test|fake|your_|<.*>)', line_text, re.IGNORECASE) for _ in [1]):
                    continue
            filtered[fpath].append((lineno, pname, matched))
    return filtered


def findings_to_set(findings):
    result = set()
    for fpath, hits in findings.items():
        for lineno, pname, _ in hits:
            result.add((os.path.normpath(fpath), lineno, pname))
    return result


def load_ground_truth(gt_path):
    gt = set()
    try:
        with open(gt_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 3:
                    fpath = os.path.normpath(parts[0])
                    try:
                        lineno = int(parts[1])
                    except ValueError:
                        continue
                    vtype = parts[2].strip()
                    gt.add((fpath, lineno, vtype))
    except OSError as e:
        print(f"Error reading ground truth: {e}", file=sys.stderr)
        sys.exit(1)
    return gt


def compute_benchmark(llm_set, hybrid_set, gt_set):
    def stats(pipeline_set, label):
        total = len(pipeline_set)
        if gt_set is not None:
            tp = len(pipeline_set & gt_set)
            fp = total - tp
            precision = tp / total if total > 0 else 0.0
            fpr = fp / total if total > 0 else 0.0
        else:
            tp = fp = None
            precision = fpr = None
        return {"label": label, "total": total, "tp": tp, "fp": fp, "precision": precision, "fpr": fpr}

    llm_stats = stats(llm_set, "LLM Heuristic")
    hyb_stats = stats(hybrid_set, "Hybrid Filter")
    overlap = len(llm_set & hybrid_set)
    overlap_ratio = overlap / len(llm_set) if llm_set else 0.0

    print("\n" + "=" * 70)
    print(f"{'Pipeline':<20} {'Total':>7} {'TP':>7} {'FP':>7} {'Precision':>11} {'FP Rate':>9}")
    print("-" * 70)
    for s in (llm_stats, hyb_stats):
        tp_str = str(s["tp"]) if s["tp"] is not None else "N/A"
        fp_str = str(s["fp"]) if s["fp"] is not None else "N/A"
        prec_str = f"{s['precision']:.3f}" if s["precision"] is not None else "N/A"
        fpr_str = f"{s['fpr']:.3f}" if s["fpr"] is not None else "N/A"
        print(f"{s['label']:<20} {s['total']:>7} {tp_str:>7} {fp_str:>7} {prec_str:>11} {fpr_str:>9}")
    print("=" * 70)
    print(f"Overlap (findings in both pipelines): {overlap}  |  Overlap ratio: {overlap_ratio:.3f}")
    if llm_stats["fp"] is not None and hyb_stats["fp"] is not None:
        reduction = llm_stats["fp"] - hyb_stats["fp"]
        print(f"Net FP reduction from hybrid filter: {reduction}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark LLM-style vs hybrid separation-logic-filtered vulnerability scanning."
    )
    parser.add_argument("corpus_dir", help="Path to directory of plain-text source files to scan.")
    parser.add_argument("--ground-truth", dest="ground_truth", help="Path to ground-truth file (file:line:type per line).")
    parser.add_argument("--mode", choices=["summary", "detailed"], default="summary", help="Output verbosity (default: summary).")
    args = parser.parse_args()

    if not os.path.isdir(args.corpus_dir):
        print(f"Error: corpus_dir '{args.corpus_dir}' is not a valid directory.", file=sys.stderr)
        sys.exit(1)

    gt_set = load_ground_truth(args.ground_truth) if args.ground_truth else None

    llm_raw = scan_corpus(args.corpus_dir, args.mode, "LLM")
    hybrid_raw = apply_hybrid_filter(llm_raw, args.corpus_dir)

    if args.mode == "detailed":
        for fpath, hits in hybrid_raw.items():
            for lineno, pname, matched in hits:
                print(f"[Hybrid] {fpath}:{lineno} [{pname}] {matched}")

    llm_set = findings_to_set(llm_raw)
    hybrid_set = findings_to_set(hybrid_raw)
    compute_benchmark(llm_set, hybrid_set, gt_set)


if __name__ == "__main__":
    main()