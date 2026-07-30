"""TELEPUZ ClickFix Terminal-Paste & C2 Beacon Cadence Detector.

Parses plain-text endpoint and proxy log exports for behavioral indicators of
TELEPUZ's ClickFix delivery chain, detecting terminal-paste execution patterns
and periodic C2 beacon cadence matching Elastic-documented timing windows.

Usage:
    python telepuz_clickfix_detector.py endpoint.log
    python telepuz_clickfix_detector.py endpoint.log --iocs extra.json --severity medium
"""
import argparse, json, re, sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

SEV = {"low": 0, "medium": 1, "high": 2}

TELEPUZ_C2_DOMAINS = re.compile(
    r"(?:telep(?:uz|us)|t3lepuz|tlpz|upd8-cdn|cdn-upd8|verify-session|"
    r"session-token\d+|loaderz?\d*|payload-cdn|update-cdn\d+)\.",
    re.I,
)
TELEPUZ_C2_IPS = [
    re.compile(r"^185\.220\.101\.", re.I),
    re.compile(r"^45\.142\.212\.", re.I),
    re.compile(r"^194\.165\.16\.", re.I),
]
BEACON_BASE_MIN, BEACON_BASE_MAX, BEACON_JITTER = 60, 300, 15
BROWSER_PROCS = re.compile(
    r"(?:^|\\)(?:chrome|msedge|firefox|brave|opera|iexplore|vivaldi)\.exe$", re.I
)
TERMINAL_PROCS = re.compile(r"(?:^|\\)(?:wt|WindowsTerminal|cmd|powershell|pwsh)\.exe$", re.I)
EXPLORER_RE = re.compile(r"(?:^|\\)explorer\.exe$", re.I)
ENCODED_CMD_RE = re.compile(r"-[Ee]nc(?:oded[Cc]ommand)?\s+[A-Za-z0-9+/]{40,}", re.I)
IEX_RE = re.compile(r"\bIEX\b|\bInvoke-Expression\b", re.I)
MSHTA_RE = re.compile(r"(?:^|\\)mshta\.exe$", re.I)
RUNDLL32_RE = re.compile(r"(?:^|\\)rundll32\.exe$", re.I)
FIELD_RE = re.compile(r"(\w+)\s*[=:]\s*([^\t|]+)")
TS_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})")

TERMINAL_PASTE_RULES = [
    ("T1204.002", "high", "TerminalSpawnedByBrowserOrExplorer",
     "Isolate host; review clipboard history and browser lure page visited before execution."),
    ("T1059.001", "high", "EncodedOrIEXCommandInPastedLine",
     "Block -EncodedCommand via PowerShell CLM/AMSI; enable ScriptBlock logging."),
    ("T1218", "medium", "LOLBinLaunchedWithoutFileBacking",
     "Restrict mshta/rundll32 via AppLocker or WDAC; alert on suspicious parent lineage."),
]
C2_BEACON_RULES = [
    ("T1071.001", "high", "TELEPUZAttributedC2Domain",
     "Block domain at DNS/proxy; rotate credentials; isolate host immediately."),
    ("T1071.001", "high", "PeriodicBeaconCadenceDetected",
     "Capture PCAP; block destination; engage IR; review all outbound from host."),
    ("T1132", "medium", "UniformLowByteHeartbeatDetected",
     "Inspect payload encoding; add decoding rules to proxy DLP policy."),
]


def _parse_ts(s):
    if not s:
        return None
    m = TS_RE.search(s)
    if m:
        try:
            return datetime(*map(int, m.groups())).timestamp()
        except (ValueError, OverflowError):
            pass
    try:
        return float(s)
    except (ValueError, TypeError):
        return None


def parse_log_entries(path):
    entries = []
    try:
        lines = Path(path).read_text(errors="replace").splitlines()
    except OSError as e:
        print(f"[ERROR] Cannot read log file: {e}", file=sys.stderr)
        sys.exit(2)
    for line in lines:
        if not line.strip():
            continue
        rec = {}
        for k, v in FIELD_RE.findall(line):
            rec[k.lower().strip()] = v.strip()
        if not rec:
            parts = re.split(r"[\t|]", line)
            keys = ["timestamp", "event_type", "process", "parent", "cmdline", "dst_host", "port", "bytes"]
            for i, p in enumerate(parts):
                if i < len(keys):
                    rec[keys[i]] = p.strip()
        rec.setdefault("_raw", line)
        rec["_ts"] = _parse_ts(rec.get("timestamp") or rec.get("ts") or rec.get("time"))
        entries.append(rec)
    return entries


def _is_c2_match(host, extra_domains, extra_ips):
    if TELEPUZ_C2_DOMAINS.search(host):
        return True
    for pat in TELEPUZ_C2_IPS + extra_ips:
        if pat.search(host):
            return True
    for d in extra_domains:
        if d.lower() in host.lower():
            return True
    return False


def match_rules(entries, extra_iocs, min_sev):
    findings = []
    net_events = defaultdict(list)
    for rec in entries:
        proc = rec.get("process", rec.get("image", rec.get("proc", "")))
        parent = rec.get("parent", rec.get("parent_image", rec.get("parentproc", "")))
        cmdline = rec.get("cmdline", rec.get("commandline", rec.get("cmd", "")))
        dst = rec.get("dst_host", rec.get("dst", rec.get("destination", rec.get("host", ""))))
        port = rec.get("port", rec.get("dst_port", ""))
        nbytes = rec.get("bytes", rec.get("bytes_sent", ""))

        if TERMINAL_PROCS.search(proc):
            is_browser_parent = BROWSER_PROCS.search(parent) if parent else False
            is_explorer_parent = EXPLORER_RE.search(parent) if parent else False
            if (is_browser_parent or is_explorer_parent) and len(cmdline) > 200:
                rule = TERMINAL_PASTE_RULES[0]
                if SEV[rule[1]] >= SEV[min_sev]:
                    findings.append(("TerminalPaste", rule[0], rule[1], rule[2],
                                     (proc + " " + cmdline)[:120], rule[3], rec.get("_ts")))
            if ENCODED_CMD_RE.search(cmdline) or IEX_RE.search(cmdline):
                rule = TERMINAL_PASTE_RULES[1]
                if SEV[rule[1]] >= SEV[min_sev]:
                    findings.append(("TerminalPaste", rule[0], rule[1], rule[2],
                                     cmdline[:120], rule[3], rec.get("_ts")))

        if (MSHTA_RE.search(proc) or RUNDLL32_RE.search(proc)):
            has_file_parent = bool(parent and re.search(r"\.(exe|com)$", parent, re.I))
            if not has_file_parent or (parent and BROWSER_PROCS.search(parent)):
                rule = TERMINAL_PASTE_RULES[2]
                if SEV[rule[1]] >= SEV[min_sev]:
                    findings.append(("TerminalPaste", rule[0], rule[1], rule[2],
                                     (proc + " " + cmdline)[:120], rule[3], rec.get("_ts")))

        if dst and _is_c2_match(dst, extra_iocs.get("domains", []), extra_iocs.get("ip_patterns", [])):
            rule = C2_BEACON_RULES[0]
            if SEV[rule[1]] >= SEV[min_sev]:
                findings.append(("C2Beacon", rule[0], rule[1], rule[2],
                                 dst[:120], rule[3], rec.get("_ts")))

        if dst and rec.get("_ts"):
            try:
                nb = int(str(nbytes).strip()) if nbytes else None
            except ValueError:
                nb = None
            net_events[dst].append((rec["_ts"], nb))

    seen_beacon_hosts = set()
    for host, events in net_events.items():
        if len(events) < 3:
            continue
        events.sort(key=lambda x: x[0])
        ts_list = [e[0] for e in events]
        intervals = [ts_list[i+1] - ts_list[i] for i in range(len(ts_list)-1)]
        for base in range(BEACON_BASE_MIN, BEACON_BASE_MAX+1, 10):
            matches = [iv for iv in intervals if abs(iv - base) <= BEACON_JITTER]
            if len(matches) >= 2 and host not in seen_beacon_hosts:
                rule = C2_BEACON_RULES[1]
                if SEV[rule[1]] >= SEV[min_sev]:
                    seen_beacon_hosts.add(host)
                    findings.append(("C2Beacon", rule[0], rule[1], rule[2],
                                     f"{host} interval~{base}s"[:120], rule[3], None))
                break
        byte_vals = [e[1] for e in events if e[1] is not None]
        if len(byte_vals) >= 3 and max(byte_vals) < 512 and (max(byte_vals) - min(byte_vals)) < 64:
            rule = C2_BEACON_RULES[2]
            if SEV[rule[1]] >= SEV[min_sev]:
                findings.append(("C2Beacon", rule[0], rule[1], rule[2],
                                 f"{host} bytes={byte_vals[0]}"[:120], rule[3], None))

    return findings


def report_findings(findings):
    phase_counts = defaultdict(int)
    phase_sev = defaultdict(lambda: "low")
    peak_sev = "low"
    any_high_c2 = False
    seen = set()
    for phase, tech, sev, rule, indicator, mitigation, ts in findings:
        dedup_key = (phase, rule, indicator[:60])
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        phase_counts[phase] += 1
        if SEV[sev] > SEV[phase_sev[phase]]:
            phase_sev[phase] = sev
        if SEV[sev] > SEV[peak_sev]:
            peak_sev = sev
        if phase == "C2Beacon" and sev == "high":
            any_high_c2 = True
        print(f"[{phase}] {tech} | sev={sev} | rule={rule} | indicator={indicator} | mitigation={mitigation}")

    print("\n--- Summary ---")
    for phase, count in phase_counts.items():
        techs = set(f[1] for f in findings if f[0] == phase)
        print(f"  {phase}: {count} hit(s), peak_sev={phase_sev[phase]}, ATT&CK={','.join(sorted(techs))}")
    print(f"  Peak severity overall: {peak_sev}")
    if any_high_c2:
        print("\n[ACTION REQUIRED] High-severity C2 beacon detected.")
        print("  -> Block destination hosts at perimeter firewall and DNS resolver.")
        print("  -> Isolate affected endpoints immediately and engage incident response.")
    return peak_sev


def load_iocs(path):
    extra = {"domains": [], "ip_patterns": [], "processes": [], "beacon_intervals": []}
    if not path:
        return extra
    try:
        data = json.loads(Path(path).read_text(errors="replace"))
        extra["domains"] = data.get("domains", [])
        extra["ip_patterns"] = [re.compile(p, re.I) for p in data.get("ip_ranges", [])]
        extra["processes"] = data.get("processes", [])
        extra["beacon_intervals"] = data.get("beacon_intervals", [])
    except (OSError, json.JSONDecodeError) as e:
        print(f"[WARN] Could not load --iocs file: {e}", file=sys.stderr)
    return extra


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log_file", help="Path to plain-text endpoint event log export")
    ap.add_argument("--iocs", help="JSON file with supplemental TELEPUZ IOCs")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum alert level to emit (default: low)")
    args = ap.parse_args()

    extra_iocs = load_iocs(args.iocs)
    entries = parse_log_entries(args.log_file)
    if not entries:
        print("[INFO] No log entries parsed.", file=sys.stderr)
        sys.exit(0)

    findings = match_rules(entries, extra_iocs, args.severity)
    if not findings:
        print("[INFO] No findings above specified severity threshold.")
        sys.exit(0)

    peak = report_findings(findings)
    sys.exit(1 if peak == "high" else 0)


if __name__ == "__main__":
    main()