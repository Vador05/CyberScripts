"""
veildrop_ttp_detector.py - Scans proxy/endpoint logs for Veil#Drop campaign TTPs.

Usage:
    python veildrop_ttp_detector.py proxy.log
    python veildrop_ttp_detector.py endpoint.log --iocs extra_iocs.json --severity high
    python veildrop_ttp_detector.py squid.log --severity medium

Exit code 1 if any high-severity finding is detected.
"""

import argparse
import json
import re
import signal
import sys
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone

RULES = {
    "Delivery": [
        {"name": "blogspot_executable_staging", "severity": "high",
         "technique": "T1583.006/T1102",
         "pattern": r"https?://[a-z0-9\-]+\.blogspot\.[a-z.]+/.*\.(ps1|exe|dll|bin)(\?|$|#|\s)",
         "fields": ["uri", "cmdline", "command"]},
        {"name": "blogspot_staging_path", "severity": "medium",
         "technique": "T1583.006/T1102",
         "pattern": r"https?://[a-z0-9\-]+\.blogspot\.[a-z.]+/(stage[2-9]?|payload|drop|loader|stager|update[_\-]?check)/",
         "fields": ["uri", "cmdline", "command"]},
    ],
    "Execution": [
        {"name": "powershell_iex_downloadstring", "severity": "high",
         "technique": "T1059.001",
         "pattern": r"(?i)(IEX|Invoke-Expression)\s*[\(\[].*(DownloadString|WebClient|Net\.WebClient)",
         "fields": ["cmdline", "command", "uri", "url", "request"]},
        {"name": "powershell_invoke_webrequest_cradle", "severity": "high",
         "technique": "T1059.001",
         "pattern": r"(?i)Invoke-WebRequest\b.*(http[s]?://|OutFile|-o\s)",
         "fields": ["cmdline", "command", "uri", "url", "request"]},
        {"name": "powershell_encoded_command", "severity": "high",
         "technique": "T1059.001",
         "pattern": r"(?i)powershell(\.exe)?\s+.*(-EncodedCommand|-enc\s+)[A-Za-z0-9+/=]{20,}",
         "fields": ["cmdline", "command", "uri", "url", "request"]},
        {"name": "powershell_obfuscation_flags", "severity": "high",
         "technique": "T1059.001",
         "pattern": r"(?i)powershell(\.exe)?\s+.*((-nop|-noni).*(-w\s+hidden|-sta)|(-w\s+hidden|-sta).*(-nop|-noni))",
         "fields": ["cmdline", "command", "uri", "url", "request"]},
    ],
    "Collection": [
        {"name": "purelog_process_name", "severity": "high",
         "technique": "T1003",
         "pattern": r"(?i)\b(purelog|purelogger|pure_log|PureInject)\b",
         "fields": ["cmdline", "command", "process", "uri"]},
        {"name": "dpapi_credential_access", "severity": "high",
         "technique": "T1003",
         "pattern": r"(?i)(AppData\\Roaming\\Microsoft\\(Credentials|Protect|Vault)|dpapi\\masterkeys|vaultcmd|credential manager)",
         "fields": ["cmdline", "command", "uri", "path"]},
        {"name": "browser_profile_harvesting", "severity": "medium",
         "technique": "T1082",
         "pattern": r"(?i)(AppData\\(Local|Roaming)\\(Google\\Chrome|Mozilla\\Firefox|Microsoft\\Edge)\\User Data\\Default\\(Login Data|Cookies|Web Data|History))",
         "fields": ["cmdline", "command", "uri", "path"]},
        {"name": "keylogger_api_strings", "severity": "medium",
         "technique": "T1082",
         "pattern": r"(?i)\b(GetAsyncKeyState|SetWindowsHookEx|GetForegroundWindow|keylog|keystroke.capture)\b",
         "fields": ["cmdline", "command", "uri"]},
    ],
}

# Pre-compile all bundled rule patterns at import time.
for _stage_rules in RULES.values():
    for _rule in _stage_rules:
        _rule["_compiled"] = re.compile(_rule["pattern"])

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

_EPOCH_RE = re.compile(r'^\d+(\.\d+)?$')
_ISO_FORMATS = (
    '%Y-%m-%dT%H:%M:%S.%f',
    '%Y-%m-%dT%H:%M:%S',
    '%Y-%m-%d %H:%M:%S.%f',
    '%Y-%m-%d %H:%M:%S',
    '%Y-%m-%d %H:%M',
)

# SIGALRM and setitimer are POSIX-only; not available on Windows.
_SIGALRM_AVAILABLE = hasattr(signal, 'SIGALRM') and hasattr(signal, 'setitimer')

def _parse_timestamp_to_epoch(ts_raw):
    """Return timestamp as float Unix epoch seconds; 0.0 on failure."""
    if not ts_raw:
        return 0.0
    ts = ts_raw.strip()
    if _EPOCH_RE.match(ts):
        return float(ts)
    ts_clean = ts.rstrip('Z')
    for fmt in _ISO_FORMATS:
        try:
            dt = datetime.strptime(ts_clean, fmt)
            return dt.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return 0.0

def _safe_regex_search(compiled_pattern, value, timeout=2.0):
    """Run compiled_pattern.search(value) with a SIGALRM timeout to prevent ReDoS."""
    if not _SIGALRM_AVAILABLE:
        return compiled_pattern.search(value)
    try:
        def _alarm_handler(signum, frame):
            raise TimeoutError("regex match timed out")

        old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
        signal.setitimer(signal.ITIMER_REAL, timeout)
        try:
            return compiled_pattern.search(value)
        except TimeoutError:
            return None
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_handler)
    except (ValueError, AttributeError):
        # Gracefully degrade if POSIX timer APIs are unavailable.
        return compiled_pattern.search(value)

def parse_log_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    entry = {"raw": line, "timestamp": "", "src_ip": "", "uri": "", "method": "", "status": "", "useragent": "", "cmdline": ""}
    squid = re.match(r"^(\d+\.\d+)\s+\d+\s+([\d.]+)\s+\w+/(\d+)\s+\d+\s+(\w+)\s+(https?://\S+)\s+-\s+\w+/[\d.]+\s+(\S+)", line)
    if squid:
        entry.update({"timestamp": squid.group(1), "src_ip": squid.group(2), "status": squid.group(3), "method": squid.group(4), "uri": urllib.parse.unquote(squid.group(5)), "useragent": squid.group(6)})
        return entry
    bc = re.match(r"^(\d{4}-\d{2}-\d{2}\s+[\d:]+)\s+([\d.]+)\s+(\w+)\s+(https?://\S+)\s+(\d+)\s+.*?\"([^\"]+)\"", line)
    if bc:
        entry.update({"timestamp": bc.group(1), "src_ip": bc.group(2), "method": bc.group(3), "uri": urllib.parse.unquote(bc.group(4)), "status": bc.group(5), "useragent": bc.group(6)})
        return entry
    ep = re.match(r"^(\d{4}-\d{2}-\d{2}[T\s][\d:\.]+Z?)\s+([\d.]+|\w[\w\-\.]+)\s+(.*)", line)
    if ep:
        entry.update({"timestamp": ep.group(1), "src_ip": ep.group(2), "cmdline": ep.group(3), "command": ep.group(3)})
        return entry
    entry["cmdline"] = line
    entry["command"] = line
    return entry

def load_iocs(path):
    with open(path) as f:
        data = json.load(f)
    for stage, additions in data.items():
        if stage not in RULES:
            continue
        for rule in additions:
            if "name" in rule and "pattern" in rule and "technique" in rule and "severity" in rule:
                try:
                    compiled = re.compile(rule["pattern"])
                except re.error as e:
                    raise ValueError(f"Invalid regex pattern in rule {rule['name']}: {e}")
                rule["_compiled"] = compiled
                rule.setdefault("fields", ["uri", "cmdline", "command"])
                RULES[stage].append(rule)

def match_rules(entry):
    hits = []
    for stage, rules in RULES.items():
        for rule in rules:
            for field in rule["fields"]:
                value = entry.get(field, "")
                if value:
                    if _safe_regex_search(rule["_compiled"], value):
                        hits.append({"stage": stage, "technique": rule["technique"], "severity": rule["severity"], "rule": rule["name"]})
                        break
    return hits

def main():
    parser = argparse.ArgumentParser(description="Veil#Drop TTP Detector - scan proxy/endpoint logs for campaign indicators.")
    parser.add_argument("log_file", help="Path to proxy or endpoint log file")
    parser.add_argument("--iocs", help="JSON file with supplemental IOC patterns")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low", help="Minimum severity to emit (default: low)")
    args = parser.parse_args()

    if args.iocs:
        try:
            load_iocs(args.iocs)
        except (OSError, json.JSONDecodeError, ValueError) as e:
            print(f"[ERROR] Failed to load IOCs: {e}", file=sys.stderr)
            sys.exit(2)

    min_sev = SEVERITY_ORDER[args.severity]
    stage_counts = defaultdict(int)
    techniques_seen = set()
    peak_severity = "low"
    dedup = defaultdict(dict)
    any_high = False

    try:
        with open(args.log_file) as f:
            for line in f:
                entry = parse_log_line(line)
                if not entry:
                    continue
                for hit in match_rules(entry):
                    if SEVERITY_ORDER[hit["severity"]] < min_sev:
                        continue
                    key = (entry.get("src_ip", ""), hit["rule"])
                    ts_epoch = _parse_timestamp_to_epoch(entry.get("timestamp", ""))
                    last = dedup[key].get("ts", 0.0)
                    if ts_epoch and last and abs(ts_epoch - last) < 60:
                        continue
                    dedup[key]["ts"] = ts_epoch
                    stage_counts[hit["stage"]] += 1
                    techniques_seen.add(hit["technique"])
                    if SEVERITY_ORDER[hit["severity"]] > SEVERITY_ORDER[peak_severity]:
                        peak_severity = hit["severity"]
                    if hit["severity"] == "high":
                        any_high = True
                    print(f"[{entry.get('timestamp','?')}] STAGE={hit['stage']} TECHNIQUE={hit['technique']} SEV={hit['severity'].upper()} RULE={hit['rule']} SRC={entry.get('src_ip','?')} LINE={entry['raw'][:200]}")
    except OSError as e:
        print(f"[ERROR] Cannot read log file: {e}", file=sys.stderr)
        sys.exit(2)

    print("\n--- Veil#Drop Detection Summary ---")
    for stage in ("Delivery", "Execution", "Collection"):
        print(f"  {stage}: {stage_counts.get(stage, 0)} hit(s)")
    print(f"  ATT&CK Techniques Observed: {', '.join(sorted(techniques_seen)) or 'none'}")
    print(f"  Peak Severity: {peak_severity.upper()}")
    print("-----------------------------------")

    sys.exit(1 if any_high else 0)

if __name__ == "__main__":
    main()