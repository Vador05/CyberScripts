#!/usr/bin/env python3
"""ClickFix Loader Detector — scans EDR/PowerShell/audit logs for ClickFix loader indicators.

Usage:
    python clickfix_loader_detector.py audit.log
    python clickfix_loader_detector.py edr_export.txt --min-severity medium
    python clickfix_loader_detector.py transcript.log --iocs extra_iocs.json --min-severity high
"""

import argparse
import json
import re
import sys
from pathlib import Path

RULES = {
    "Lure": [
        (r"(?i)press\s+windows\s*\+\s*r|win\s*\+\s*r\b", "WindowsRunPrompt", "medium"),
        (r"(?i)paste\s+(in|into)\s+(the\s+)?run", "PasteInRun", "medium"),
        (r"(?i)i\s+am\s+not\s+a\s+robot.{0,40}verif", "FakeCaptcha", "medium"),
        (r"(?i)verification\s+steps|human\s+verification", "FakeVerification", "medium"),
        (r"(?i)(browser.fix|fix.*browser|update.*required.*paste|press.*run.*dialog)", "FakeBrowserFix", "medium"),
        (r"(?i)mshta\s+https?://", "MshtaLure", "high"),
        (r"(?i)(clipboard|ctrl\s*\+\s*v).{0,60}https?://", "ClipboardURL", "medium"),
    ],
    "Fetch": [
        (r"(?i)msiexec\s+(/[qi]\s+){1,2}https?://", "MsiexecRemoteFetch", "high"),
        (r"(?i)msiexec.+https?://.+\.(msi|exe|ps1)", "MsiexecPayload", "high"),
        (r"(?i)certutil\s+(-urlcache\s+-f|-f\s+-urlcache)\s+https?://", "CertutilDownload", "high"),
        (r"(?i)(curl|wget)\s+.+https?://.+\.(exe|ps1|bat|vbs|dll)", "CurlWgetPayload", "high"),
        (r"(?i)regsvr32.+scrobj\.dll", "Regsvr32Scrobj", "high"),
        (r"(?i)bitsadmin\s+/transfer\s+\S+\s+https?://", "BitsadminDownload", "high"),
    ],
    "Execute": [
        (r"(?i)powershell.+-[Ee]nc(odedcommand)?[\s=]+[A-Za-z0-9+/]{20}", "PSEncodedCommand", "high"),
        (r"(?i)powershell.+-[Ww]indow[Ss]tyle\s+[Hh]idden", "PSHidden", "medium"),
        (r"(?i)(wscript|cscript)\s+.+https?://", "ScriptRemoteExec", "high"),
        (r"(?i)rundll32.+https?://", "Rundll32Remote", "high"),
        (r"(?i)rundll32.+\\[Tt]emp\\.+\.dll", "Rundll32TempDLL", "high"),
        (r"(?i)powershell.+\bIEX\b.+[Nn]et\.?[Ww]eb[Cc]lient", "PSIEXDownload", "high"),
        (r"(?i)invoke-expression.+https?://", "InvokeExpressionURL", "high"),
    ],
}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def load_rules(iocs_path):
    compiled = {stage: [(re.compile(p), name, sev) for p, name, sev in entries]
                for stage, entries in RULES.items()}
    if not iocs_path:
        return compiled
    try:
        with open(iocs_path, encoding="utf-8") as fh:
            extra = json.load(fh)
        if not isinstance(extra, dict):
            raise TypeError(f"expected top-level JSON object, got {type(extra).__name__}")
        extra_compiled = {}
        for stage, entries in extra.items():
            stage_rules = []
            for entry in entries:
                if not isinstance(entry, dict):
                    raise TypeError(f"IOC entry must be a dict, got {type(entry).__name__}")
                stage_rules.append((
                    re.compile(entry["pattern"], re.IGNORECASE),
                    entry["name"],
                    entry.get("severity", "medium"),
                ))
            extra_compiled[stage] = stage_rules
        for stage, rules in extra_compiled.items():
            compiled.setdefault(stage, []).extend(rules)
    except (OSError, json.JSONDecodeError, KeyError, AttributeError, TypeError, re.error) as exc:
        print(f"[WARN] Could not load IOCs from {iocs_path}: {exc}", file=sys.stderr)
    return compiled


def parse_log(log_path):
    path = Path(log_path)
    try:
        try:
            text = path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            text = path.read_text(encoding="latin-1")
    except OSError as exc:
        print(f"[ERROR] Cannot open log file: {exc}", file=sys.stderr)
        sys.exit(2)
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.strip() and len(line) <= 4096:
            yield lineno, line


def scan(lines, compiled_rules):
    findings = []
    for lineno, line in lines:
        for stage, rules in compiled_rules.items():
            for pattern, name, sev in rules:
                if pattern.search(line):
                    findings.append({
                        "lineno": lineno,
                        "stage": stage,
                        "rule": name,
                        "severity": sev,
                        "snippet": line.strip()[:120],
                    })
    return findings


def escalate(findings):
    has_lure = any(f["stage"] == "Lure" for f in findings)
    has_action = any(f["stage"] in ("Fetch", "Execute") for f in findings)
    if not (has_lure and has_action):
        return findings
    return [
        dict(f, severity="high") if f["stage"] == "Lure" and f["severity"] != "high" else f
        for f in findings
    ]


def report(findings, min_sev):
    min_ord = SEVERITY_ORDER[min_sev]
    visible = [f for f in findings if SEVERITY_ORDER[f["severity"]] >= min_ord]
    stage_counts = {s: 0 for s in RULES}
    peak = "low"
    for f in visible:
        sev = f["severity"]
        print(f"[{sev.upper():6}] Line {f['lineno']:>6} | Stage:{f['stage']:<8} | "
              f"Rule:{f['rule']:<30} | {f['snippet']}")
        stage_counts[f["stage"]] = stage_counts.get(f["stage"], 0) + 1
        if SEVERITY_ORDER[sev] > SEVERITY_ORDER[peak]:
            peak = sev
    print("\n--- Summary ---")
    for stage in ("Lure", "Fetch", "Execute"):
        print(f"  {stage:<8}: {stage_counts.get(stage, 0)} hit(s)")
    print(f"  Peak severity : {peak.upper()}")
    print(f"  Total emitted : {len(visible)}")
    return 1 if peak == "high" else 0


def main():
    parser = argparse.ArgumentParser(
        description="Detect ClickFix social-engineering loader indicators in plaintext log exports."
    )
    parser.add_argument("log_path", help="Path to log file (.txt or .log)")
    parser.add_argument(
        "--min-severity", choices=["low", "medium", "high"], default="low",
        help="Lowest severity level to emit (default: low)"
    )
    parser.add_argument(
        "--iocs", metavar="IOCS_JSON",
        help="Supplemental JSON file with extra ClickFix C2 signatures to merge"
    )
    args = parser.parse_args()

    compiled_rules = load_rules(args.iocs)
    lines = list(parse_log(args.log_path))
    findings = escalate(scan(lines, compiled_rules))
    sys.exit(report(findings, args.min_severity))


if __name__ == "__main__":
    main()