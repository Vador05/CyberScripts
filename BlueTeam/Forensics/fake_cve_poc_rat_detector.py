"""
Fake CVE PoC RAT Scanner - Detects ChocoPoC-style RAT delivery in fake CVE repos.

Usage:
    python fake_cve_poc_rat_detector.py /path/to/cloned/repo
    python fake_cve_poc_rat_detector.py /path/to/cloned/repo --severity high
    python fake_cve_poc_rat_detector.py /path/to/cloned/repo --iocs extra_iocs.json
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Generator, Optional

MAX_FILE_SIZE = 512 * 1024
SCAN_EXTENSIONS = {".yml", ".yaml", ".py", ".ps1", ".sh", ".bat", ".md", ".txt"}
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

BUNDLED_RULES = [
    {"stage": "Lure", "severity": "medium", "name": "FakeCVEIdentifier",
     "pattern": r"CVE-\d{4}-\d{4,7}"},
    {"stage": "Lure", "severity": "medium", "name": "DownloadLureLink",
     "pattern": r"(?:https?://\S+(?:\.exe|\.zip|\.ps1|\.sh|/download)\S*)"},
    {"stage": "Lure", "severity": "low", "name": "PoCImpersonationKeyword",
     "pattern": r"(?i)\b(?:proof.of.concept|exploit|poc|rce|lpe|bypass)\b"},
    {"stage": "Staging", "severity": "high", "name": "WorkflowCurlFetch",
     "pattern": r"(?i)(?:curl|wget|Invoke-WebRequest)\s+\S+\.(?:exe|ps1|sh|bat|zip)"},
    {"stage": "Staging", "severity": "high", "name": "WorkflowImmediateExec",
     "pattern": r"(?i)(?:start-process|\.\/|bash\s+|powershell\s+-|cmd\s+/c)\s*\S+\.(?:exe|ps1|sh|bat)"},
    {"stage": "Staging", "severity": "medium", "name": "ActionsSecretExfil",
     "pattern": r"(?i)\$\{\{\s*secrets\.\w+\s*\}\}"},
    {"stage": "RAT", "severity": "high", "name": "Base64DecodeExec",
     "pattern": r"(?i)(?:base64\s*-d|FromBase64String|b64decode)\s*.{0,80}(?:exec|eval|invoke|shell|system|popen)"},
    {"stage": "RAT", "severity": "high", "name": "DiscordWebhookC2",
     "pattern": r"(?i)discord(?:app)?\.com/api/webhooks/\d+/[\w-]+"},
    {"stage": "RAT", "severity": "high", "name": "TelegramC2",
     "pattern": r"(?i)api\.telegram\.org/bot[\w:]+/send"},
    {"stage": "RAT", "severity": "high", "name": "RegistryRunKeyPersist",
     "pattern": r"(?i)(?:HKCU|HKLM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
    {"stage": "RAT", "severity": "high", "name": "CronPersistence",
     "pattern": r"(?i)(?:crontab\s+-[el]|/etc/cron\.|@reboot)"},
    {"stage": "RAT", "severity": "high", "name": "StartupFolderPersist",
     "pattern": r"(?i)(?:Startup|start\s*menu\\programs\\startup|\.config/autostart)"},
    {"stage": "RAT", "severity": "high", "name": "CtypesUrllibCombo",
     "pattern": r"(?i)(?:import\s+ctypes[\s\S]{0,200}import\s+urllib|import\s+urllib[\s\S]{0,200}import\s+ctypes)"},
    {"stage": "RAT", "severity": "medium", "name": "SuspiciousBase64Blob",
     "pattern": r"(?:[A-Za-z0-9+/]{60,}={0,2})"},
    {"stage": "RAT", "severity": "medium", "name": "ShellcodeAlloc",
     "pattern": r"(?i)(?:VirtualAlloc|mmap\s*\(|ctypes\.windll\.kernel32\.Virtual)"},
]


@dataclass
class Finding:
    severity: str
    rel_path: str
    stage: str
    technique: str
    snippet: str


@dataclass
class ScanState:
    has_lure: bool = False
    has_rat: bool = False
    findings: list = field(default_factory=list)


def load_supplemental_iocs(iocs_path: str) -> list:
    try:
        with open(iocs_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        rules = []
        for domain in data.get("c2_domains", []):
            rules.append({"stage": "RAT", "severity": "high", "name": "SupplementalC2Domain",
                          "pattern": re.escape(domain)})
        for obs in data.get("obfuscation_strings", []):
            rules.append({"stage": "RAT", "severity": "medium", "name": "SupplementalObfuscation",
                          "pattern": re.escape(obs)})
        return rules
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"[WARN] Could not load supplemental IOCs: {exc}", file=sys.stderr)
        return []


def scan_repo(repo_path: str) -> Generator[tuple, None, None]:
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SCAN_EXTENSIONS:
                continue
            full_path = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(full_path) > MAX_FILE_SIZE:
                    continue
                with open(full_path, "r", encoding="utf-8", errors="strict") as fh:
                    content = fh.read()
                rel_path = os.path.relpath(full_path, repo_path)
                yield rel_path, content
            except (OSError, UnicodeDecodeError):
                continue


def match_indicators(rel_path: str, content: str, rules: list, min_severity: str, state: ScanState) -> list:
    findings = []
    min_lvl = SEVERITY_ORDER[min_severity]
    for rule in rules:
        if SEVERITY_ORDER[rule["severity"]] < min_lvl:
            continue
        try:
            matches = list(re.finditer(rule["pattern"], content, re.MULTILINE))
        except re.error:
            continue
        for m in matches:
            snippet = m.group(0)[:120]
            sev = rule["severity"]
            stage = rule["stage"]
            if stage == "Lure":
                state.has_lure = True
            if stage == "RAT" and sev == "high":
                state.has_rat = True
            finding = Finding(severity=sev, rel_path=rel_path, stage=stage,
                              technique=rule["name"], snippet=snippet)
            findings.append(finding)
    return findings


def escalate_severity(findings: list, state: ScanState) -> list:
    if not (state.has_lure and state.has_rat):
        return findings
    escalated = []
    for f in findings:
        if f.stage == "Lure" and f.severity == "medium":
            escalated.append(Finding("high", f.rel_path, f.stage, f.technique, f.snippet))
        else:
            escalated.append(f)
    return escalated


def report_findings(all_findings: list, min_severity: str) -> int:
    min_lvl = SEVERITY_ORDER[min_severity]
    stage_counts = {"Lure": 0, "Staging": 0, "RAT": 0}
    peak_sev = "low"
    peak_lvl = 0
    visible = [f for f in all_findings if SEVERITY_ORDER[f.severity] >= min_lvl]
    for f in visible:
        print(f"[{f.severity.upper():6}] {f.rel_path} | {f.stage} | {f.technique} | {f.snippet}")
        stage_counts[f.stage] = stage_counts.get(f.stage, 0) + 1
        if SEVERITY_ORDER[f.severity] > peak_lvl:
            peak_lvl = SEVERITY_ORDER[f.severity]
            peak_sev = f.severity
    print("\n--- Summary ---")
    for stage, count in stage_counts.items():
        print(f"  {stage}: {count} hit(s)")
    print(f"  Peak severity: {peak_sev.upper()}")
    return 1 if peak_sev == "high" else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Fake CVE PoC RAT Scanner")
    parser.add_argument("repo_path", help="Local path to cloned repository")
    parser.add_argument("--iocs", help="Path to supplemental JSON IOC file")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum alert severity to emit (default: low)")
    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"[ERROR] Not a directory: {args.repo_path}", file=sys.stderr)
        return 2

    rules = list(BUNDLED_RULES)
    if args.iocs:
        rules.extend(load_supplemental_iocs(args.iocs))

    compiled_rules = []
    for rule in rules:
        try:
            re.compile(rule["pattern"], re.MULTILINE)
            compiled_rules.append(rule)
        except re.error as exc:
            print(f"[WARN] Skipping invalid pattern {rule['name']}: {exc}", file=sys.stderr)

    state = ScanState()
    all_findings = []
    for rel_path, content in scan_repo(args.repo_path):
        findings = match_indicators(rel_path, content, compiled_rules, args.severity, state)
        all_findings.extend(findings)

    all_findings = escalate_severity(all_findings, state)
    return report_findings(all_findings, args.severity)


if __name__ == "__main__":
    sys.exit(main())