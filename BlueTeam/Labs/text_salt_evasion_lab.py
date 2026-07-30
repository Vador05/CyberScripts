"""Text-Salted Phishing Evasion & AI Filter Benchmark Lab.

Benchmarks simulated AI email filter rules against clean and text-salted phishing
templates to measure per-technique evasion rates and outputs detection countermeasures.

Usage:
    python text_salt_evasion_lab.py templates.txt
    python text_salt_evasion_lab.py templates.txt --salt-level heavy --min-detect-rate 80
"""
import argparse, re, sys
from pathlib import Path

KEYWORDS = ["password","account","verify","urgent","click","login","billing","confirm","update","credentials"]
GLYPHS   = {'a':'\u0430','c':'\u0441','e':'\u0435','o':'\u043e','p':'\u0440','s':'\u0455','x':'\u0445','y':'\u0443','i':'\u0456','B':'\u0412'}
RULES = [
    ("urgency_act_now",     re.compile(r"act\s+now", re.I)),
    ("urgency_verify_imm",  re.compile(r"verify\s+immediately", re.I)),
    ("cred_password",       re.compile(r"enter\s+your\s+password", re.I)),
    ("cred_account",        re.compile(r"confirm\s+your\s+account", re.I)),
    ("brand_impersonation", re.compile(r"\b(?:PayPal|Microsoft|Amazon|Apple)\b", re.I)),
    ("cta_click_here",      re.compile(r"click\s+here", re.I)),
    ("cta_billing",         re.compile(r"(?:login\s+link|update\s+billing)", re.I)),
]
DET_RULES = {
    "zero_width": (r"[\u200b\ufeff\u200c\u200d]",                    "Strip zero-width chars before matching to neutralize invisible insertion evasion."),
    "homoglyph":  ("unicodedata.normalize('NFC') + confusable map",  "Normalize Unicode and apply confusable-character mapping before rule evaluation."),
    "heavy_mix":  (r"[\u202e\u202d\u200f\u200e\u200b\ufeff]",        "Remove bidi override and zero-width marks then normalize Unicode before matching."),
}

def _zwsp(text):
    for kw in KEYWORDS:
        text = re.sub(re.escape(kw), "\u200b".join(kw), text, flags=re.I)
    return text

def _glyph(text):
    return "".join(GLYPHS.get(c, c) for c in text)

def _heavy(text):
    words = _glyph(_zwsp(text)).split()
    return " ".join(w + ("\u202e\u202d" if i % 5 == 4 else "") for i, w in enumerate(words))

SALTERS = {"zero_width": _zwsp, "homoglyph": _glyph, "heavy_mix": _heavy}
LEVELS  = {"light": ["zero_width"], "medium": ["zero_width", "homoglyph"], "heavy": ["zero_width", "homoglyph", "heavy_mix"]}

def parse_templates(path):
    try:
        raw = Path(path).read_text(errors="replace")
    except OSError as e:
        sys.exit(f"ERROR: {e}")
    blocks, cur = [], []
    for line in raw.splitlines():
        if line.strip():
            cur.append(line)
        elif cur:
            blocks.append("\n".join(cur)); cur = []
    if cur:
        blocks.append("\n".join(cur))
    valid = [b for b in blocks if any(l.lower().startswith("subject") for l in b.splitlines()) and len(b.splitlines()) >= 2]
    if not valid:
        sys.exit("ERROR: no valid template blocks found (each block needs a Subject line + body).")
    return valid

def generate_samples(templates, level):
    return [{"technique": t, "clean": tmpl, "salted": SALTERS[t](tmpl)} for tmpl in templates for t in LEVELS[level]]

def run_benchmark(samples):
    stats = {}
    for s in samples:
        t = s["technique"]
        if t not in stats:
            stats[t] = {"clean": 0, "salted": 0, "total": 0, "missed": []}
        stats[t]["total"] += 1
        ch = any(r.search(s["clean"]) for _, r in RULES)
        sh = any(r.search(s["salted"]) for _, r in RULES)
        if ch: stats[t]["clean"] += 1
        if sh:
            stats[t]["salted"] += 1
        elif ch:
            bypassed = [n for n, r in RULES if r.search(s["clean"]) and not r.search(s["salted"])]
            stats[t]["missed"].append((t, bypassed, s["clean"][:80]))
    return stats

def report_results(stats, min_rate):
    print(f"\n{'Technique':<14}{'Clean Det%':>11}{'Salted Det%':>12}{'Evasion \u0394':>10}")
    print("-" * 50)
    tot_s = tot_n = 0
    for t, d in stats.items():
        n, ch, sh = d["total"], d["clean"], d["salted"]
        cr, sr = (100 * ch / n if n else 0), (100 * sh / n if n else 0)
        print(f"{t:<14}{cr:>10.1f}%{sr:>11.1f}%{cr - sr:>+9.1f}%")
        tot_s += sh; tot_n += n
    overall = 100 * tot_s / tot_n if tot_n else 0
    print(f"\n{'OVERALL':<14}{'':<11}{overall:>11.1f}%")

    print("\n--- EVASION-GAP SAMPLES ---")
    any_miss = False
    for d in stats.values():
        for tech, bypassed, preview in d["missed"]:
            any_miss = True
            print(f"[{tech}] bypassed: {bypassed or 'all rules'}")
            print(f"  preview: {preview!r}")
    if not any_miss:
        print("  (none)")

    print("\n--- DETECTION RULES ---")
    for tech, (pat, rat) in DET_RULES.items():
        if tech in stats:
            print(f"[{tech}]\n  strip/normalize: {pat}\n  rationale: {rat}")

    any_fail = any(100 * d["salted"] / d["total"] < min_rate for d in stats.values() if d["total"])
    verdict = "FAIL" if any_fail else "PASS"
    print(f"\nLAB {verdict}: overall salted detection {overall:.1f}% vs threshold {min_rate}%")
    if any_fail:
        sys.exit(1)

def main():
    ap = argparse.ArgumentParser(description="Text-Salted Phishing Evasion & AI Filter Benchmark Lab")
    ap.add_argument("templates_file", help="Path to phishing templates file (blank-line delimited blocks)")
    ap.add_argument("--salt-level", choices=["light", "medium", "heavy"], default="medium")
    ap.add_argument("--min-detect-rate", type=int, default=70, metavar="0-100")
    args = ap.parse_args()
    if not 0 <= args.min_detect_rate <= 100:
        ap.error("--min-detect-rate must be between 0 and 100")
    report_results(
        run_benchmark(generate_samples(parse_templates(args.templates_file), args.salt_level)),
        args.min_detect_rate,
    )

if __name__ == "__main__":
    main()