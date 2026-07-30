#!/usr/bin/env python3
"""
GigaWiper Destructive Mode Pre-Execution Detector
Scans auditd, Sysmon CSV, or EDR text logs for GigaWiper operator mode-selection activity.
Usage:
    python gigawiper_mode_selector_detector.py audit.log
    python gigawiper_mode_selector_detector.py sysmon.csv --severity medium --iocs extra.json
IOC JSON: {"binary_names":["gw2"],"beacon_destinations":["evil.net"],"staging_paths":["/tmp/.gw"]}
"""
import argparse, csv, io, json, re, sys
from collections import defaultdict
from statistics import mean, stdev

SEV = {"low": 0, "medium": 1, "high": 2}
RAW_DISK = re.compile(r"/dev/sd[a-z]|/dev/nvme\d+n\d+|PhysicalDrive\d", re.I)
RANSOM_NOTE = re.compile(r"(README_DECRYPT|HOW_TO_RECOVER|!!!RESTORE_FILES)[.\w]*\.(txt|html|hta)", re.I)
DGA = re.compile(r"\b[a-z0-9]{8,20}\.(xyz|top|tk|pw|cc|ru|su)\b", re.I)
CRED_PATH = re.compile(r"Login Data|\.ssh/id_rsa|credentials\.db|\.kdbx|wallet\.dat|keychain", re.I)
DFLT_BINS = {"dd", "gigawiper", "gw_mbr", "mbr_wipe", "diskwipe", "wiper"}
DFLT_STAGE = {"/tmp/.gw", "/var/tmp/.gw_stage", "C:\\Users\\Public\\Temp\\gw"}

# Sysmon CSV fallback column indices (0-based) used when no header row is detected.
# Matches Sysmon v13+ ProcessCreate/FileCreate export schema.
# Column order varies across Sysmon versions and export tools; parse_entry() reads the
# header row (built by main()) and overrides these defaults with name-based lookup.
SYSMON_DEFAULT_COLS = {"UtcTime": 0, "Image": 1, "TargetFilename": 2, "ProcessId": 3,
                       "CommandLine": 4, "DestinationIp": 5, "EventID": 6}

def parse_entry(line, sysmon_cols=None):
    """Parse one log line into a structured event dict.

    sysmon_cols: name→index map built from the CSV header row; None or empty
    falls back to SYSMON_DEFAULT_COLS indices.
    """
    e = {"raw": line.rstrip(), "pid": "", "proc": "", "path": "", "ts": "", "syscall": ""}
    if "type=SYSCALL" in line or "type=PATH" in line or "type=OPENAT" in line:
        kv = dict(re.findall(r'(\w+)=(".*?"|\S+)', line))
        e.update({k: kv.get(k, "").strip('"') for k in ("pid", "uid", "syscall")})
        e["proc"] = kv.get("exe", kv.get("comm", "")).strip('"')
        e["path"] = kv.get("name", kv.get("nametype", "")).strip('"')
        m = re.search(r'msg=audit\(([^)]+)\)', line)
        if m: e["ts"] = m.group(1)
    elif re.search(r'^\S[^,]*,[^,]*,', line):
        try:
            row = next(csv.reader(io.StringIO(line)))

            def col(name, fallback_idx):
                if sysmon_cols:
                    idx = sysmon_cols.get(name)
                    return row[idx] if idx is not None and idx < len(row) else ""
                return row[fallback_idx] if len(row) > fallback_idx else ""

            e["ts"] = col("UtcTime", SYSMON_DEFAULT_COLS["UtcTime"])
            e["proc"] = col("Image", SYSMON_DEFAULT_COLS["Image"])
            e["path"] = col("TargetFilename", SYSMON_DEFAULT_COLS["TargetFilename"])
            e["pid"] = col("ProcessId", SYSMON_DEFAULT_COLS["ProcessId"])
            cmd = col("CommandLine", SYSMON_DEFAULT_COLS["CommandLine"])
            if cmd:
                e["raw"] = e["raw"] + " " + cmd
        except Exception: pass
    else:
        for pat, key in [(r'pid[=: ]+(\d+)', "pid"), (r'(?:exe|image)[=: ]+(\S+)', "proc"),
                         (r'(?:path|file)[=: ]+(\S+)', "path"), (r'(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)', "ts")]:
            m = re.search(pat, line, re.I)
            if m: e[key] = m.group(1)
    return e

def build_iocs(path):
    iocs = {"binary_names": set(DFLT_BINS), "beacon_destinations": set(), "staging_paths": set(DFLT_STAGE)}
    if path:
        try:
            with open(path) as f: extra = json.load(f)
            for k in ("binary_names", "beacon_destinations", "staging_paths"):
                iocs[k].update(extra.get(k, []))
        except Exception as ex: print(f"[WARN] IOC file: {ex}", file=sys.stderr)
    return iocs

def ts_to_seconds(ts_str):
    """Convert timestamp string to seconds since epoch for interval calculations."""
    if not ts_str: return None
    try:
        if '/' in ts_str:
            return int(float(ts_str.split('/')[0]))
        return int(float(ts_str))
    except (ValueError, AttributeError):
        return None

def _is_outbound_event(line, iocs):
    return (bool(DGA.search(line)) or
            any(d in line for d in iocs["beacon_destinations"]) or
            bool(re.search(r'\b(GET|POST)\b', line)))

RULES = [
    ("MBRWipe", "RAW_DISK_OPEN", "high",
     lambda e, _: bool(RAW_DISK.search(e["raw"])) and e["syscall"] in {"open", "openat", "write", "pwrite64", ""}),
    ("MBRWipe", "WIPER_BINARY_EXEC", "high",
     lambda e, i: any(b in e["proc"].lower() for b in i["binary_names"]) and (RAW_DISK.search(e["raw"]) or "if=/dev" in e["raw"] or "of=/dev" in e["raw"])),
    ("MBRWipe", "DD_WIPE_ARGS", "high",
     lambda e, _: bool(re.search(r'\bdd\b', e["proc"], re.I)) and bool(re.search(r'(if|of)=/dev/', e["raw"]))),
    ("RansomNoteDrop", "RANSOM_NOTE_CREATE", "medium",
     lambda e, _: bool(RANSOM_NOTE.search(e["path"] + " " + e["raw"]))),
    ("RansomNoteDrop", "STAGING_PATH_WRITE", "medium",
     lambda e, i: any(s in e["raw"] for s in i["staging_paths"])),
    ("RansomNoteDrop", "MASS_FILE_CREATE_BURST", "low",
     lambda e, _: e.get("_burst", 0) >= 5 and not RAW_DISK.search(e["raw"])),
    # _cnt holds interval count; 5 samples → 4 intervals, so _cnt >= 4 matches spec "five or more samples".
    ("SpywareBeacon", "BEACON_INTERVAL_REGULAR", "high",
     lambda e, i: _is_outbound_event(e["raw"], i) and e.get("_cv", 1.0) < 0.15 and e.get("_cnt", 0) >= 4),
    ("SpywareBeacon", "DGA_WITH_CRED_ACCESS", "high",
     lambda e, i: (bool(DGA.search(e["raw"])) or any(d in e["raw"] for d in i["beacon_destinations"])) and bool(CRED_PATH.search(e["raw"]))),
    ("SpywareBeacon", "C2_CHECKIN_SEQUENCE", "medium",
     lambda e, i: any(d in e["raw"] for d in i["beacon_destinations"]) and bool(re.search(r'\b(GET|POST)\b', e["raw"]))),
]

def main():
    ap = argparse.ArgumentParser(description="GigaWiper mode-selection pre-execution detector")
    ap.add_argument("log_file")
    ap.add_argument("--iocs")
    ap.add_argument("--severity", default="low", choices=list(SEV))
    args = ap.parse_args()
    iocs = build_iocs(args.iocs)
    min_sev = SEV[args.severity]
    dedup = defaultdict(set)
    hits = defaultdict(lambda: {"pids": set(), "peak": "low", "count": 0})
    exit_code = 0
    pid_modes = defaultdict(set)
    pid_burst_window = defaultdict(list)
    pid_beacon_ts = defaultdict(list)
    pid_window_start = defaultdict(lambda: None)
    pid_window_entries = defaultdict(list)
    sysmon_cols = {}  # populated from CSV header row if detected

    try:
        fh = open(args.log_file, errors="replace")
    except OSError as ex:
        print(f"[ERROR] Cannot open log: {ex}", file=sys.stderr)
        sys.exit(2)

    with fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip(): continue

            # Detect Sysmon CSV header row and build name→index map for dynamic column lookup.
            if lineno == 1 and re.search(r'\b(EventID|UtcTime|Image|TargetFilename)\b', line, re.I) and ',' in line:
                try:
                    headers = next(csv.reader(io.StringIO(line)))
                    sysmon_cols = {h.strip(): i for i, h in enumerate(headers)}
                except Exception:
                    pass
                continue

            e = parse_entry(line, sysmon_cols)
            pid = e["pid"] or "?"
            ts_sec = ts_to_seconds(e["ts"])

            if ts_sec is not None:
                if pid_window_start[pid] is None or ts_sec - pid_window_start[pid] > 30:
                    pid_window_start[pid] = ts_sec
                    pid_window_entries[pid] = []
                pid_window_entries[pid].append(e)

            if e["syscall"] in {"creat", "openat", "write"} or re.search(r'FileCreate|EventID.*?11\b', line, re.I):
                if ts_sec is not None:
                    pid_burst_window[pid].append(ts_sec)
                    cutoff = ts_sec - 30
                    pid_burst_window[pid] = [t for t in pid_burst_window[pid] if t >= cutoff]
            e["_burst"] = len(pid_burst_window[pid])

            if _is_outbound_event(line, iocs) and ts_sec is not None:
                pid_beacon_ts[pid].append(ts_sec)
                if len(pid_beacon_ts[pid]) > 20:
                    pid_beacon_ts[pid] = pid_beacon_ts[pid][-20:]

                beacon_samples = pid_beacon_ts[pid]
                if len(beacon_samples) >= 5:
                    intervals = [beacon_samples[j + 1] - beacon_samples[j]
                                 for j in range(len(beacon_samples) - 1)]
                    pos_intervals = [iv for iv in intervals if iv > 0]
                    if len(pos_intervals) >= 4:
                        try:
                            mu = mean(pos_intervals)
                            if mu > 0:
                                e["_cv"] = stdev(pos_intervals) / mu
                                e["_cnt"] = len(pos_intervals)
                        except Exception:
                            pass

            for mode, name, sev, fn in RULES:
                if SEV[sev] < min_sev: continue
                try: matched = fn(e, iocs)
                except Exception: matched = False
                if not matched: continue
                key = (pid, name)
                prev = dedup[key]
                if prev and (lineno - max(prev)) < 60: continue
                prev.add(lineno)
                pid_modes[pid].add(mode)
                hits[mode]["pids"].add(pid)
                hits[mode]["count"] += 1
                if SEV[sev] > SEV[hits[mode]["peak"]]: hits[mode]["peak"] = sev

                final_sev = "high" if len(pid_modes[pid]) >= 2 else sev
                if SEV[final_sev] == SEV["high"]:
                    exit_code = 1

                ts = e["ts"] or str(lineno)
                print(f"[{ts:>22}] {mode:<18} {final_sev:<6} {name:<28} pid={pid:<6} path={e['path'][:28]:<28} | {e['raw'][:140]}")

    print("\n--- GigaWiper Detection Summary ---")
    print(f"{'Mode':<20} {'Hits':>5} {'Unique PIDs':>12} {'Peak Sev':>10}")
    for mode, d in sorted(hits.items()):
        print(f"{mode:<20} {d['count']:>5} {len(d['pids']):>12} {d['peak']:>10}")
    if not hits: print("No matches found above minimum severity threshold.")
    sys.exit(exit_code)

if __name__ == "__main__":
    main()