"""AI-Generated Code CWE Pattern Scanner.

Scans plain-text source code files for vulnerability patterns that AI code
generators most commonly introduce, mapping each finding to its CWE class
with a bundled before/after fix example to support developer remediation.

Usage:
    python ai_cwe_scanner.py source.py
    python ai_cwe_scanner.py app.js --cwe CWE-78,CWE-89 --severity high
"""
import argparse, re, sys
from collections import defaultdict
from pathlib import Path

RULES = [
    {
        "cwe": "CWE-78", "class": "OS Command Injection", "severity": "critical",
        "pattern": re.compile(r"subprocess\.(call|run|Popen).*shell\s*=\s*True|os\.system\s*\(|os\.popen\s*\("),
        "before": 'os.system("ping " + user_input)',
        "after":  'subprocess.run(["ping", user_input], shell=False)',
        "explanation": "User-controlled data passed to a shell enables arbitrary command execution.",
    },
    {
        "cwe": "CWE-89", "class": "SQL Injection", "severity": "critical",
        "pattern": re.compile(r'(execute|query)\s*\(\s*[f"\'](SELECT|INSERT|UPDATE|DELETE|DROP)', re.I),
        "before": 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
        "after":  'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))',
        "explanation": "String-formatted SQL literals allow injection; use parameterised queries.",
    },
    {
        "cwe": "CWE-89", "class": "SQL Injection", "severity": "critical",
        "pattern": re.compile(r'(execute|query)\s*\(\s*"[^"]*"\s*%\s*\w|\+\s*\w+\s*\+.*WHERE', re.I),
        "before": 'cursor.execute("SELECT * FROM t WHERE id=" + uid)',
        "after":  'cursor.execute("SELECT * FROM t WHERE id=%s", (uid,))',
        "explanation": "Concatenated SQL string allows injection; use parameterised queries.",
    },
    {
        "cwe": "CWE-798", "class": "Hard-coded Credentials", "severity": "high",
        "pattern": re.compile(r'(password|passwd|secret|api_key|apikey|token|auth_token)\s*=\s*["\'][^"\']{4,}["\']', re.I),
        "before": 'password = "Sup3rS3cr3t!"',
        "after":  'password = os.environ["APP_PASSWORD"]',
        "explanation": "Hard-coded credentials can be extracted from source control or binaries.",
    },
    {
        "cwe": "CWE-327", "class": "Broken Cryptographic Algorithm", "severity": "high",
        "pattern": re.compile(r'hashlib\.(md5|sha1)\s*\(|MD5\s*\(|SHA1\s*\(|Cipher.*DES|rc4|arcfour', re.I),
        "before": 'digest = hashlib.md5(data).hexdigest()',
        "after":  'digest = hashlib.sha256(data).hexdigest()',
        "explanation": "MD5/SHA-1/DES/RC4 are cryptographically broken; use SHA-256+ or AES-GCM.",
    },
    {
        "cwe": "CWE-502", "class": "Unsafe Deserialization", "severity": "critical",
        "pattern": re.compile(r'pickle\.loads?\s*\(|yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)', re.I),
        "before": 'obj = pickle.loads(request.body)',
        "after":  'obj = json.loads(request.body)',
        "explanation": "Deserializing untrusted data with pickle/yaml.load enables remote code execution.",
    },
    {
        "cwe": "CWE-22", "class": "Path Traversal", "severity": "high",
        "pattern": re.compile(r'open\s*\(\s*[^)]*\+|open\s*\(\s*f["\'].*\{'),
        "before": 'open(base_dir + user_path)',
        "after":  'open(Path(base_dir) / Path(user_path).name)',
        "explanation": "Unsanitised path concatenation allows directory traversal outside the intended root.",
    },
]

SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def parse_args():
    p = argparse.ArgumentParser(description="AI-Generated Code CWE Pattern Scanner")
    p.add_argument("input_file", help="Path to source file to scan")
    p.add_argument("--cwe", help="Comma-separated CWE IDs to restrict scanning (e.g. CWE-78,CWE-89)")
    p.add_argument("--severity", choices=["low", "medium", "high", "critical"], default="low",
                   help="Minimum severity level to emit (default: low)")
    return p.parse_args()


def load_rules(cwe_filter, min_severity):
    allowed_cwes = {c.strip().upper() for c in cwe_filter.split(",")} if cwe_filter else None
    min_sev = SEV_ORDER[min_severity]
    return [r for r in RULES
            if (allowed_cwes is None or r["cwe"] in allowed_cwes)
            and SEV_ORDER[r["severity"]] >= min_sev]


def parse_source(path):
    try:
        lines = Path(path).read_text(errors="replace").splitlines()
    except OSError as e:
        sys.exit(f"ERROR reading file: {e}")
    return list(enumerate(lines, start=1))


def scan_cwe_patterns(indexed_lines, active_rules):
    findings = []
    for lineno, text in indexed_lines:
        for rule in active_rules:
            if rule["pattern"].search(text):
                findings.append({
                    "cwe": rule["cwe"],
                    "class": rule["class"],
                    "severity": rule["severity"],
                    "lineno": lineno,
                    "line": text.strip(),
                    "before": rule["before"],
                    "after": rule["after"],
                    "explanation": rule["explanation"],
                })
    return findings


def report_findings(findings, source_path):
    if not findings:
        print(f"[OK] No findings in {source_path}")
        return 0

    cwe_counts = defaultdict(int)
    rule_trigger_counts = defaultdict(int)
    has_critical = False

    for f in findings:
        label = f"{f['cwe']} {f['class']}"
        cwe_counts[label] += 1
        rule_trigger_counts[f["cwe"]] += 1
        if f["severity"] == "critical":
            has_critical = True

        sev_tag = f"[{f['severity'].upper()}]"
        print(f"\n{'='*60}")
        print(f"{sev_tag} {f['cwe']} — {f['class']}")
        print(f"  Line {f['lineno']}: {f['line']}")
        print(f"  BEFORE: {f['before']}")
        print(f"    AFTER: {f['after']}")
        print(f"  WHY: {f['explanation']}")

    most_frequent = max(rule_trigger_counts, key=rule_trigger_counts.get)
    print(f"\n{'='*60}")
    print("SUMMARY — per-CWE hit counts:")
    for label, count in sorted(cwe_counts.items()):
        print(f"  {label}: {count}")
    print(f"  Most-triggered rule: {most_frequent} ({rule_trigger_counts[most_frequent]} hit(s))")

    if any(k.startswith("CWE-798") for k in cwe_counts) or any(k.startswith("CWE-327") for k in cwe_counts):
        print("\nDEV NOTE: Hard-coded credentials (CWE-798) — rotate any exposed secrets immediately.")
        print("DEV NOTE: Broken crypto (CWE-327) — migrate to SHA-256/AES-GCM before deployment.")

    if has_critical:
        print("\nBUILD GATE: critical finding(s) present — failing.")
        return 1
    return 0


def main():
    args = parse_args()
    active_rules = load_rules(args.cwe, args.severity)
    if not active_rules:
        sys.exit("ERROR: No rules match the supplied --cwe / --severity filters.")
    indexed_lines = parse_source(args.input_file)
    findings = scan_cwe_patterns(indexed_lines, active_rules)
    sys.exit(report_findings(findings, args.input_file))


if __name__ == "__main__":
    main()