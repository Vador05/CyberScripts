"""ClickFix CAPTCHA Lure & ACR Stealer Kill Chain Detection Lab.

Parses plain-text endpoint log exports for behavioral indicators of ClickFix
CAPTCHA lure attacks across three kill-chain stages used by UAC-0145.

Usage:
    python clickfix_captcha_lab.py endpoint.log
    python clickfix_captcha_lab.py endpoint.log --patterns extra_iocs.json --severity medium
"""
import argparse, json, re, sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

SEV = {"low": 0, "medium": 1, "high": 2}

SIMPLE_RULES = [
    ("LureExposure","high","ClickFixLureURL",re.compile(r"verify-human|captcha-check|robot-check|human-verify|not-a-robot",re.I),"url","Block CAPTCHA-lure URL patterns at web proxy; enable alerting on CAPTCHA-themed path segments."),
    ("LureExposure","medium","MalspamReferrer",re.compile(r"cdn-delivery\d+|update-required|confirm-identity|press-win|winupdate",re.I),"url","Enable email gateway scanning for SEO-poisoned delivery domains used as lure referrers."),
    ("ClipboardExecution","high","EncodedPowerShell",re.compile(r"-[Ee]nc(?:oded[Cc]ommand)?\s+[A-Za-z0-9+/]{40,}",re.I),"cmdline","Block -EncodedCommand via PowerShell constrained language mode or AMSI policy enforcement."),
    ("PayloadDelivery","high","DownloadCradle",re.compile(r"curl\b|certutil.*-decode|Invoke-WebRequest|Start-BitsTransfer|wget\b",re.I),"cmdline","Block outbound downloads from user-context processes; deploy TLS inspection and strict proxy allowlists."),
    ("PayloadDelivery","high","ACRStealerDropped",re.compile(r"(?:\\AppData\\|\\Temp\\|%APPDATA%|%TEMP%).*\.(exe|dll|bat|ps1)\b",re.I),"path","Restrict write/execute in %APPDATA% and %TEMP% via GPO; alert on new executables in user writable dirs."),
    ("PayloadDelivery","high","ACRC2Domain",re.compile(r"acr-?\d+\.|stealer\.|grabber\.|credentials?-?\d+\.|exfil\.",re.I),"url","Sinkhole ACR Stealer C2 naming conventions at DNS layer; rotate all credentials on any confirmed hit."),
    ("PayloadDelivery","medium","ACRStealerProcess",re.compile(r"\b(acr_?stealer|msedge_?proxy|chromium_?helper|wallet_?grab|passview)\b",re.I),"process","Terminate process immediately, isolate host, and rotate all browser-stored and cached credentials."),
]

_EXPLORER_RE         = re.compile(r"(?:^|\\)explorer\.exe$", re.I)
_CMD_PS_RE           = re.compile(r"(?:^|\\)(?:cmd|powershell|pwsh)\.exe$", re.I)
_MSHTA_RE            = re.compile(r"(?:^|\\)mshta\.exe$", re.I)
_RUNDLL32_RE         = re.compile(r"(?:^|\\)rundll32\.exe$", re.I)
_RUNMRU_RE           = re.compile(r"RunMRU|HKCU.*\\Run\b", re.I)
_INTERACTIVE_PARENTS = re.compile(r"(?:^|\\)(?:explorer|cmd|powershell|pwsh|wscript|cscript)\.exe$", re.I)

FIELD_RE = re.compile(r'(\w+)\s*[=|]\s*([^\t|]+)')
URL_RE   = re.compile(r'https?://[^\s"\'<>]+', re.I)


def _parse_ts(ts_str):
    if not ts_str:
        return None
    m = re.match(r'(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})', ts_str)
    if m:
        try:
            return datetime(*map(int, m.groups())).timestamp()
        except (ValueError, OverflowError):
            pass
    try:
        return float(ts_str)
    except (ValueError, TypeError):
        return None


def parse_log_entries(path):
    entries = []
    try: lines = Path(path).read_text(errors="replace").splitlines()
    except OSError as e: sys.exit(f"ERROR reading log: {e}")
    for raw in lines:
        line = raw.strip()
        if not line: continue
        try: obj = json.loads(line)
        except json.JSONDecodeError: obj = dict(FIELD_RE.findall(line))
        def g(*keys): return str(next((obj[k] for k in keys if k in obj), "")).strip()
        url_m = URL_RE.search(line)
        entries.append({
            "ts":      g("timestamp","time","Timestamp","EventTime"),
            "user":    g("user","username","User","UserName","SubjectUserName"),
            "etype":   g("event_type","EventType","EventId","event_id"),
            "process": g("process","Image","ProcessName","process_name"),
            "parent":  g("parent","ParentImage","ParentProcessName","parent_process"),
            "cmdline": g("cmdline","CommandLine","command_line","CommandArgs") or line,
            "path":    g("path","TargetFilename","FilePath","file_path"),
            "url":     url_m.group(0) if url_m else g("url","URL","DestinationHostname","DestUrl"),
            "_raw":    line,
        })
    return entries


def _match_clipboard_behavioral(entries):
    findings = []

    for e in entries:
        parent  = e.get("parent", "")
        process = e.get("process", "")
        cmdline = e.get("cmdline", "")
        if _EXPLORER_RE.search(parent) and _CMD_PS_RE.search(process) and len(cmdline) > 200:
            label = e.get("user") or process or "?"
            findings.append(("high", "ClipboardExecution", "LongCmdFromShell", label, cmdline,
                             "Alert on shells spawned by explorer.exe with command lines over 200 chars; enforce AppLocker/WDAC."))

    for e in entries:
        process = e.get("process", "")
        parent  = e.get("parent", "")
        if _MSHTA_RE.search(process) and (_INTERACTIVE_PARENTS.search(parent) or not parent.strip()):
            label = e.get("user") or process or "?"
            findings.append(("medium", "ClipboardExecution", "MshtaInvocation", label,
                             e.get("cmdline") or process,
                             "Deny mshta.exe via application control; alert on parentless or explorer-spawned mshta instances."))

    for e in entries:
        process = e.get("process", "")
        parent  = e.get("parent", "")
        if _RUNDLL32_RE.search(process) and (_INTERACTIVE_PARENTS.search(parent) or not parent.strip()):
            label = e.get("user") or process or "?"
            findings.append(("medium", "ClipboardExecution", "Rundll32Invocation", label,
                             e.get("cmdline") or process,
                             "Restrict rundll32.exe via WDAC rules; alert when spawned from interactive shells without a file-backed parent."))

    runmru_times = []
    for e in entries:
        ts = _parse_ts(e.get("ts", ""))
        if ts is not None and _RUNMRU_RE.search(e.get("cmdline", "") + e.get("_raw", "")):
            runmru_times.append(ts)

    if runmru_times:
        for e in entries:
            spawn_ts = _parse_ts(e.get("ts", ""))
            if spawn_ts is None or not e.get("process"):
                continue
            if any(0 < spawn_ts - mru_ts <= 30 for mru_ts in runmru_times):
                label = e.get("user") or e.get("process") or "?"
                findings.append(("medium", "ClipboardExecution", "RunDialogAbuse", label,
                                 e.get("cmdline") or e.get("process") or "?",
                                 "Monitor RunMRU registry writes correlated with rapid process spawns as Run-dialog paste indicators."))

    return findings


def match_rules(entries, extra_rules):
    findings = []
    for e in entries:
        for stage, sev, name, pat, field, mitigation in SIMPLE_RULES + extra_rules:
            if "," in field:
                target = "|".join(str(e.get(f, "")) for f in field.split(","))
            else:
                target = e.get(field, "") or e["_raw"]
            if pat.search(target):
                label = e.get("user") or e.get("process") or "?"
                findings.append((sev, stage, name, label, target, mitigation))
    findings += _match_clipboard_behavioral(entries)
    return findings


def load_extra_patterns(path):
    extra = []
    try: data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as e: sys.exit(f"ERROR loading patterns: {e}")
    if not isinstance(data, dict): sys.exit("ERROR loading patterns: expected JSON object at root")
    for item in data.get("rules", []):
        try:
            extra.append((item["stage"], item["severity"], item["name"],
                          re.compile(item["pattern"], re.I), item["field"], item["mitigation"]))
        except (KeyError, re.error): continue
    return extra


def report_findings(findings, min_sev):
    counts = defaultdict(int)
    peak = 0
    payload_hit = False
    min_level = SEV.get(min_sev, 0)
    for sev, stage, name, label, indicator, mitigation in findings:
        level = SEV.get(sev, 0)
        if level < min_level: continue
        counts[stage] += 1
        peak = max(peak, level)
        if stage == "PayloadDelivery": payload_hit = True
        ind = (indicator[:117] + "...") if len(indicator) > 120 else indicator
        print(f"[{sev.upper():6}] [{stage}] {name} | user/proc={label} | {ind}")
        print(f"         MITIGATE: {mitigation}")
    print("\n--- Summary ---")
    for stage in ("LureExposure", "ClipboardExecution", "PayloadDelivery"):
        print(f"  {stage}: {counts[stage]} hit(s)")
    peak_label = next((k for k, v in SEV.items() if v == peak), "none")
    print(f"  Peak severity: {peak_label.upper()}")
    if payload_hit:
        print("  *** CREDENTIAL ROTATION REQUIRED — PayloadDelivery stage indicators detected ***")
    return peak


def main():
    ap = argparse.ArgumentParser(description="ClickFix CAPTCHA lure & ACR Stealer kill-chain detection lab.")
    ap.add_argument("log_file", help="Path to plain-text endpoint event log export")
    ap.add_argument("--patterns", metavar="FILE", help="Supplemental JSON file with additional IOC rules")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum alert severity to emit (default: low)")
    args = ap.parse_args()
    extra    = load_extra_patterns(args.patterns) if args.patterns else []
    entries  = parse_log_entries(args.log_file)
    findings = match_rules(entries, extra)
    peak     = report_findings(findings, args.severity)
    sys.exit(1 if peak >= SEV["high"] else 0)


if __name__ == "__main__":
    main()