"""
VS Code Task Lifecycle Infostealer Detector

Scans plain-text endpoint logs for supply-chain campaigns that plant .vscode/tasks.json
inside hijacked npm/Go packages to bypass postinstall-script restrictions and drop a
Python infostealer.

Usage:
    python vscode_task_infostealer_detector.py /var/log/endpoint.log
    python vscode_task_infostealer_detector.py /var/log/endpoint.log --severity high
    python vscode_task_infostealer_detector.py /var/log/endpoint.log --iocs extra_iocs.json
    python vscode_task_infostealer_detector.py /var/log/endpoint.log --severity medium --iocs campaign.json

Example supplemental IOC file (--iocs):
    {
        "exfil_domains": ["evil.example.com", "c2.attacker.net"],
        "credential_paths": ["/home/.aws/credentials", "AppData/Custom/secrets"]
    }
"""

import argparse
import json
import re
import sys
from typing import Any

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

EXFIL_DOMAINS = [
    "pastebin.com", "transfer.sh", "ngrok.io", "ngrok-free.app",
    "webhook.site", "pipedream.net", "requestbin.com", "canarytokens.com",
    "0x0.st", "file.io", "gofile.io", "anonfiles.com", "temp.sh",
]

CREDENTIAL_PATHS = [
    ".aws/credentials", ".ssh/id_rsa", ".ssh/id_ed25519",
    "Library/Keychains", "Login Data", "Cookies", "wallet.dat",
    ".gnupg/secring", "AppData/Roaming/Microsoft/Credentials",
    ".netrc", "keychain", ".vault-token", "gcloud/credentials.db",
    ".docker/config.json", "npm_token", ".npmrc", "pip/pip.conf",
]

LOG_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r".*?(?:proc(?:ess)?=(?P<process>[^\s,\"]+)|image=(?P<image>[^\s,\"]+))?"
    r".*?(?:parent(?:_proc(?:ess)?)?=(?P<parent>[^\s,\"]+)|ppid_name=(?P<ppid_name>[^\s,\"]+))?"
    r".*?(?:cmd(?:line)?=(?P<cmdline>[^\n\"]{0,512})|command=(?P<command>[^\n\"]{0,512}))?",
    re.IGNORECASE,
)

SIMPLE_TS_PATTERN = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
)


def parse_log_entry(line: str) -> dict[str, Any]:
    entry: dict[str, Any] = {"raw": line.rstrip(), "timestamp": "", "process": "", "parent": "", "cmdline": ""}
    m = LOG_PATTERN.match(line)
    if m:
        entry["timestamp"] = m.group("timestamp") or ""
        entry["process"] = (m.group("process") or m.group("image") or "").lower()
        entry["parent"] = (m.group("parent") or m.group("ppid_name") or "").lower()
        entry["cmdline"] = (m.group("cmdline") or m.group("command") or "").lower()
    if not entry["timestamp"]:
        ts_m = SIMPLE_TS_PATTERN.search(line)
        if ts_m:
            entry["timestamp"] = ts_m.group(1)
    if not entry["cmdline"]:
        entry["cmdline"] = line.lower()
    return entry


def match_rules(entry: dict[str, Any], exfil_domains: list[str], credential_paths: list[str]) -> list[dict[str, Any]]:
    hits = []
    raw_lower = entry["raw"].lower()
    cmdline = entry["cmdline"]
    process = entry["process"]
    parent = entry["parent"]

    npm_parents = {"npm", "npm.cmd", "node", "npx", "npx.cmd"}
    vscode_procs = {"code", "code-server", "code-insiders", "electron"}
    parent_tokens = set(re.split(r"[\\/\s]", parent))

    if any(p in parent_tokens for p in npm_parents) and any(v in process or v in cmdline for v in vscode_procs):
        hits.append({"stage": "Delivery", "severity": "high", "rule": "NpmSpawnsVSCode",
                     "detail": "npm/node spawned VS Code process during package lifecycle"})

    if any(p in parent_tokens for p in npm_parents):
        if re.search(r"tasks\.json|\.vscode", raw_lower):
            hits.append({"stage": "Delivery", "severity": "medium", "rule": "VscodeTasksJsonWriteDuringInstall",
                         "detail": ".vscode/tasks.json activity during npm install"})

    vscode_parent_tokens = set(re.split(r"[\\/\s]", parent))
    if any(v in vscode_parent_tokens for v in vscode_procs) or any(v in parent for v in vscode_procs):
        if "python" in process or "python3" in process or "python" in cmdline[:30]:
            hits.append({"stage": "Execution", "severity": "high", "rule": "VscodeTaskSpawnsPython",
                         "detail": "VS Code task spawned python process"})
            for cred_path in credential_paths:
                if cred_path.lower() in cmdline or cred_path.lower() in raw_lower:
                    hits.append({"stage": "Execution", "severity": "high", "rule": "PythonAccessesCredentialStore",
                                 "detail": f"Python targeting credential path: {cred_path}"})
                    break

    if not hits:
        for cred_path in credential_paths:
            if cred_path.lower() in raw_lower:
                if "python" in process or "python" in cmdline[:40]:
                    hits.append({"stage": "Execution", "severity": "medium", "rule": "PythonCredentialStoreAccess",
                                 "detail": f"Python process near credential path: {cred_path}"})
                    break

    for domain in exfil_domains:
        if domain.lower() in raw_lower:
            hits.append({"stage": "Exfiltration", "severity": "high", "rule": "OutboundExfilDomain",
                         "detail": f"Connection to known exfiltration domain: {domain}"})

    return hits


def load_supplemental_iocs(path: str) -> tuple[list[str], list[str]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[ERROR] Failed to load IOC file '{path}': {e}", file=sys.stderr)
        sys.exit(1)
    domains = data.get("exfil_domains", [])
    creds = data.get("credential_paths", [])
    if not isinstance(domains, list) or not isinstance(creds, list):
        print("[ERROR] IOC file must have 'exfil_domains' and 'credential_paths' as arrays.", file=sys.stderr)
        sys.exit(1)
    return domains, creds


def report_findings(log_path: str, min_severity: str, exfil_domains: list[str], credential_paths: list[str]) -> int:
    stage_counts: dict[str, int] = {"Delivery": 0, "Execution": 0, "Exfiltration": 0}
    peak_severity = -1
    min_sev_val = SEVERITY_ORDER[min_severity]
    total_hits = 0

    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip():
                    continue
                entry = parse_log_entry(line)
                hits = match_rules(entry, exfil_domains, credential_paths)
                for hit in hits:
                    sev_val = SEVERITY_ORDER.get(hit["severity"], 0)
                    if sev_val < min_sev_val:
                        continue
                    ts = entry["timestamp"] or "UNKNOWN_TIME"
                    print(f"[{ts}] [{hit['stage'].upper()}] [{hit['severity'].upper()}] "
                          f"Rule={hit['rule']} | {entry['raw'][:200]}")
                    stage_counts[hit["stage"]] = stage_counts.get(hit["stage"], 0) + 1
                    if sev_val > peak_severity:
                        peak_severity = sev_val
                    total_hits += 1
    except OSError as e:
        print(f"[ERROR] Cannot read log file '{log_path}': {e}", file=sys.stderr)
        sys.exit(1)

    peak_label = next((k for k, v in SEVERITY_ORDER.items() if v == peak_severity), "none")
    print("\n--- Summary ---")
    print(f"Total alerts: {total_hits}")
    for stage, count in stage_counts.items():
        print(f"  {stage}: {count}")
    print(f"Peak severity: {peak_label.upper()}")
    return 1 if peak_severity >= SEVERITY_ORDER["high"] else 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect VS Code task-based infostealer campaigns in endpoint logs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("log_file", help="Path to plain-text endpoint or SIEM log export")
    parser.add_argument("--iocs", metavar="FILE", help="Supplemental JSON file with extra exfil domains and credential paths")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum alert severity to emit (default: low)")
    args = parser.parse_args()

    exfil_domains = list(EXFIL_DOMAINS)
    credential_paths = list(CREDENTIAL_PATHS)

    if args.iocs:
        extra_domains, extra_creds = load_supplemental_iocs(args.iocs)
        exfil_domains = list(set(exfil_domains + extra_domains))
        credential_paths = list(set(credential_paths + extra_creds))

    exit_code = report_findings(args.log_file, args.severity, exfil_domains, credential_paths)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()