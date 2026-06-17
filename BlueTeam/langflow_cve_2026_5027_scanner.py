"""
Langflow CVE-2026-5027 Triage Scanner

Detects exploitation attempts and post-exploitation artifacts of the Langflow
unauthenticated file-write RCE vulnerability (CVE-2026-5027).

Usage:
    python langflow_cve_2026_5027_scanner.py --log /var/log/langflow/access.log --output detail
    python langflow_cve_2026_5027_scanner.py --log /var/log/langflow/app.log --artifacts /tmp/langflow --output summary
    python langflow_cve_2026_5027_scanner.py --artifacts /opt/langflow/uploads --output detail
    python langflow_cve_2026_5027_scanner.py --log access.log --harden
"""

import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Finding:
    source: str
    location: str
    rule: str
    matched: str
    severity: str
    recommendation: str


LOG_RULES = [
    (
        "ENDPOINT_ABUSE",
        re.compile(r'(?:POST|GET)\s+/api/v\d+/(?:upload|files?|save|write|custom[_-]?component)', re.I),
        "HIGH",
        "Unauthenticated file-write endpoint access matching CVE-2026-5027 attack surface",
    ),
    (
        "PATH_TRAVERSAL",
        re.compile(r'(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)', re.I),
        "CRITICAL",
        "Path traversal sequence in request — likely directory escape attempt",
    ),
    (
        "WEBSHELL_UPLOAD",
        re.compile(r'filename=["\']?[^"\'>\s]*\.(php|jsp|jspx|aspx?|cgi|py|sh|bash|pl|rb|lua)["\']?', re.I),
        "CRITICAL",
        "Executable file extension in upload parameter — probable webshell drop",
    ),
    (
        "CODE_INJECTION_PAYLOAD",
        re.compile(r'(?:__import__|exec\(|eval\(|os\.system|subprocess|base64\.b64decode|importlib)', re.I),
        "CRITICAL",
        "Python code injection payload detected in log line",
    ),
    (
        "UNAUTH_API_KEY_BYPASS",
        re.compile(r'(?:x-api-key:\s*(?:null|none|undefined|"")|Authorization:\s*(?:null|none|undefined|""))', re.I),
        "HIGH",
        "Null or empty authentication header — authentication bypass attempt",
    ),
    (
        "REVERSE_SHELL_PATTERN",
        re.compile(r'(?:bash\s+-i|nc\s+-e|/dev/tcp/|python\s+-c.*socket|ncat\s+--exec)', re.I),
        "CRITICAL",
        "Reverse shell command sequence detected in log",
    ),
    (
        "COMPONENT_WRITE_ABUSE",
        re.compile(r'/api/v\d+/(?:flows?|components?)/[^/\s]+\s+(?:PUT|PATCH|POST)', re.I),
        "MEDIUM",
        "Flow or component write operation — review for malicious payload injection",
    ),
    (
        "CREDENTIAL_EXFIL_PATTERN",
        re.compile(r'(?:/etc/passwd|/etc/shadow|\.env|id_rsa|\.aws/credentials|secrets\.ya?ml)', re.I),
        "CRITICAL",
        "Sensitive credential file path referenced — possible exfiltration attempt",
    ),
    (
        "OOB_CALLBACK_INTERACTSH",
        re.compile(r'[a-z0-9\-]+\.oast\.(?:fun|pro|me|live|online|site)', re.I),
        "CRITICAL",
        "Out-of-band Interactsh callback domain — confirms blind SSRF/RCE exploitation",
    ),
    (
        "OOB_CALLBACK_BURPCOLLAB",
        re.compile(r'[a-z0-9\-]+\.burpcollaborator\.net', re.I),
        "CRITICAL",
        "Out-of-band Burp Collaborator callback domain — confirms blind SSRF/RCE exploitation",
    ),
    (
        "OOB_CALLBACK_INTERACTSH_ALT",
        re.compile(r'[a-z0-9\-]+\.interact\.sh', re.I),
        "CRITICAL",
        "Out-of-band Interact.sh callback domain — confirms blind SSRF/RCE exploitation",
    ),
]

ARTIFACT_EXTENSIONS = {
    ".php", ".jsp", ".jspx", ".aspx", ".cgi", ".sh", ".bash",
    ".pl", ".rb", ".lua", ".py3",
}

ARTIFACT_FILENAMES = re.compile(
    r'(?:shell|webshell|cmd|backdoor|c99|r57|b374k|wso|meterpreter|revshell|payload|dropper)',
    re.I,
)

ARTIFACT_CONTENT_PATTERNS = [
    (re.compile(r'(?:import\s+os|import\s+subprocess|__import__)', re.I), "CRITICAL", "Python execution primitive in artifact"),
    (re.compile(r'(?:system\s*\(|passthru\s*\(|shell_exec\s*\(|popen\s*\()', re.I), "CRITICAL", "Shell execution function in artifact"),
    (re.compile(r'(?:bash\s+-i|/dev/tcp/|nc\s+-e|ncat)', re.I), "CRITICAL", "Reverse shell pattern in artifact"),
]

HARDENING_CONTROLS = [
    "Set LANGFLOW_AUTO_LOGIN=false and configure explicit user credentials.",
    "Bind Langflow to 127.0.0.1 and expose only via authenticated reverse proxy (nginx/Caddy).",
    "Mount application directories read-only; only allow writes to designated data volumes.",
    "Pin Langflow to a patched release >= 1.3.3 and validate with 'pip show langflow'.",
    "Enable structured audit logging and forward to a SIEM or centralized log store.",
    "Apply network segmentation: block outbound DNS and HTTP from the Langflow process.",
    "Rotate all API keys, tokens, and DB credentials present on the host after any exposure.",
    "Scan deployed custom_components/ for injected .py files and verify file hashes.",
    "Review /tmp and /etc for unexpected files written during the exposure window.",
    "Enable OS-level file integrity monitoring (auditd/inotify) on sensitive directories.",
]


def scan_log(log_path: str) -> list[Finding]:
    findings = []
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.rstrip()
                for rule_id, pattern, severity, recommendation in LOG_RULES:
                    m = pattern.search(line)
                    if m:
                        findings.append(Finding(
                            source="log",
                            location=f"{log_path}:{lineno}",
                            rule=rule_id,
                            matched=line[:200],
                            severity=severity,
                            recommendation=recommendation,
                        ))
    except OSError as exc:
        print(f"[ERROR] Cannot read log file '{log_path}': {exc}", file=sys.stderr)
    return findings


def _check_artifact_content(filepath: str) -> list[tuple[str, str]]:
    hits = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read(8192)
        for pattern, severity, desc in ARTIFACT_CONTENT_PATTERNS:
            if pattern.search(content):
                hits.append((severity, desc))
    except OSError:
        pass
    return hits


def scan_artifacts(dir_path: str) -> list[Finding]:
    findings = []
    try:
        for root, _dirs, files in os.walk(dir_path):
            for fname in files:
                fpath = os.path.join(root, fname)
                _, ext = os.path.splitext(fname)
                if ext.lower() in ARTIFACT_EXTENSIONS:
                    findings.append(Finding(
                        source="artifact",
                        location=fpath,
                        rule="SUSPICIOUS_EXTENSION",
                        matched=fname,
                        severity="HIGH",
                        recommendation="Executable file extension in artifact directory — inspect and remove if unauthorized",
                    ))
                if ARTIFACT_FILENAMES.search(fname):
                    findings.append(Finding(
                        source="artifact",
                        location=fpath,
                        rule="SUSPICIOUS_FILENAME",
                        matched=fname,
                        severity="CRITICAL",
                        recommendation="Filename matches known webshell/backdoor pattern — treat as IOC",
                    ))
                for severity, desc in _check_artifact_content(fpath):
                    findings.append(Finding(
                        source="artifact",
                        location=fpath,
                        rule="MALICIOUS_CONTENT",
                        matched=desc,
                        severity=severity,
                        recommendation="File content contains execution primitives — isolate and forensicate",
                    ))
    except OSError as exc:
        print(f"[ERROR] Cannot walk artifact directory '{dir_path}': {exc}", file=sys.stderr)
    return findings


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def report(findings: list[Finding], mode: str) -> None:
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"{'='*70}")
    print(f"  Langflow CVE-2026-5027 Triage Scanner — {ts}")
    print(f"{'='*70}")

    if not findings:
        print("\n[RESULT] No indicators of compromise detected.\n")
        print("TRIAGE: No immediate action required. Continue routine monitoring.")
        print(f"{'='*70}\n")
        return

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.source, f.location))
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"\n[RESULT] {len(findings)} indicator(s) found.\n")
    print("SEVERITY SUMMARY:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in counts:
            print(f"  {sev:<10} {counts[sev]}")

    highest = min(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 9)).severity
    print(f"\nOVERALL SEVERITY: {highest}")

    if highest == "CRITICAL":
        print("TRIAGE: IMMEDIATE ESCALATION REQUIRED — isolate host, preserve logs, notify IR team.")
    elif highest == "HIGH":
        print("TRIAGE: Escalate to security team within 1 hour. Preserve evidence before remediation.")
    else:
        print("TRIAGE: Review findings manually. Schedule investigation with security team.")

    if mode == "detail":
        print(f"\n{'─'*70}")
        print("DETAILED FINDINGS:")
        for i, f in enumerate(findings, 1):
            print(f"\n  [{i}] {f.severity} — {f.rule}")
            print(f"      Source   : {f.source.upper()}")
            print(f"      Location : {f.location}")
            print(f"      Matched  : {f.matched}")
            print(f"      Action   : {f.recommendation}")

    print(f"\n{'='*70}\n")


def print_hardening() -> None:
    print("\n" + "=" * 72)
    print("HARDENING CHECKLIST — CVE-2026-5027 (Langflow Unauthenticated File-Write)")
    print("=" * 72)
    for i, control in enumerate(HARDENING_CONTROLS, 1):
        print(f"  {i:>2}. {control}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Triage Langflow server logs and host artifact paths for CVE-2026-5027 exploitation evidence.",
        epilog="Example: %(prog)s --log /var/log/langflow/access.log --artifacts /tmp/langflow --output detail",
    )
    parser.add_argument("--log", metavar="PATH", help="Plain-text log file to scan (access or app log)")
    parser.add_argument("--artifacts", metavar="PATH", help="Directory to check for post-exploitation file artifacts")
    parser.add_argument("--output", choices=["summary", "detail"], default="summary", help="Verbosity level (default: summary)")
    parser.add_argument("--harden", action="store_true", help="Print hardening checklist after scan results")
    args = parser.parse_args()

    if not args.log and not args.artifacts:
        parser.error("At least one of --log or --artifacts must be specified.")

    all_findings: list[Finding] = []

    if args.log:
        all_findings.extend(scan_log(args.log))

    if args.artifacts:
        all_findings.extend(scan_artifacts(args.artifacts))

    report(all_findings, args.output)

    if args.harden:
        print_hardening()

    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()
