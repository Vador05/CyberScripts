"""
Spirals Ransomware Kill Chain Detector (Sub-24h Pre-Encryption)

Scans plain-text Windows event log text exports or SIEM key-value exports for
behavioral indicators of the Spirals ransomware sub-24-hour kill chain across
three pre-encryption stages: InitialAccess, LateralMovement, and Staging.

Usage:
    python spirals_killchain_detector.py security.log
    python spirals_killchain_detector.py security.log --iocs iocs.json --severity high
"""

import argparse, json, re, sys
from collections import defaultdict, deque

RULES = {
    "InitialAccess": [
        ("BruteForceSuccess", "high", r"EventID[=:\s]+4624"),
        ("FailedLogon", "medium", r"EventID[=:\s]+4625"),
        ("ScheduledTaskCreation", "high", r"EventID[=:\s]+4698"),
        ("ServiceInstall", "high", r"EventID[=:\s]+7045"),
        ("PhishingDrop", "high", r"(?i)(\\temp\\|\\appdata\\)[^\s]*\.(exe|bat|ps1|vbs|js)"),
    ],
    "LateralMovement": [
        ("SMBAdminShare", "high", r"(?i)EventID[=:\s]+5140.{0,80}(ADMIN\$|IPC\$|C\$)"),
        ("PsExecArtifact", "high", r"(?i)PSEXESVC"),
        ("WMIRemote", "medium", r"(?i)(wmic|wmiprvse).{0,40}(create|process|call)"),
        ("NTLMIndicator", "medium", r"(?i)NtLmSsp.{0,30}(NTLM|relay|pass)"),
    ],
    "Staging": [
        ("ShadowDelete", "high", r"(?i)vssadmin.{0,30}delete.{0,20}shadows"),
        ("BCDEditRecover", "high", r"(?i)bcdedit.{0,20}/set.{0,20}recoveryenabled.{0,10}no"),
        ("AVTermination", "high", r"(?i)(taskkill|net\s+stop).{0,30}(defender|avast|kaspersky|mcafee|symantec|sophos|eset|malwarebytes|crowdstrike|cylance|carbonblack|sentinelone)"),
        ("BulkFileEnum", "medium", r"(?i)(robocopy|xcopy|dir\s+/s).{0,60}\.(doc|xls|pdf|jpg|db)"),
    ],
}

SEV = {"low": 0, "medium": 1, "high": 2}
WIN = 30


def parse_entry(line):
    e = {"raw": line.rstrip()}
    m = re.search(r"(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})", line)
    e["ts"] = m.group(1) if m else "no-ts"
    m = re.search(r"(?:SourceIP|IpAddress|WorkstationName|Computer)[=:\s]+([^\s,;\"]+)", line, re.I)
    e["src"] = m.group(1) if m else "unknown"
    return e


def load_iocs(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    extra = defaultdict(list)
    for item in data.get("indicators", []):
        if not isinstance(item, str):
            continue
        pat = item[3:] if item.startswith("re:") else re.escape(item)
        if not pat:
            continue
        try:
            re.compile(pat)
        except re.error:
            continue
        for stage in RULES:
            extra[stage].append(("IOCMatch", "high", pat))
    return extra


def check_rules(entry, window, extra, seen, ia_sources):
    hits = []
    src = entry["src"]

    # Build the set of keys that have already fired within the current window.
    # seen[src] is a deque(maxlen=WIN) of sets — one set per log entry processed
    # for this source — so eviction mirrors the sliding entry window exactly.
    fired_in_window = set()
    for entry_fired in seen[src]:
        fired_in_window.update(entry_fired)

    this_entry_fired = set()

    for stage, rules in RULES.items():
        for name, sev, pat in (rules + extra.get(stage, [])):
            # 1. Pattern must match the raw line.
            if not re.search(pat, entry["raw"]):
                continue
            # 2. Sequence validation before dedup so a valid new sequence is
            #    never suppressed by an earlier window hit on the same rule.
            if name == "BruteForceSuccess":
                fails = sum(1 for e in window if re.search(r"EventID[=:\s]+4625", e["raw"]) and e["src"] == src)
                if fails < 3:
                    continue
            # 3. Dedup: suppress if this rule already fired within the window.
            key = (stage, name)
            if key in fired_in_window:
                continue
            if stage == "InitialAccess":
                ia_sources.add(src)
            esev = "high" if (stage != "InitialAccess" and src in ia_sources) else sev
            hits.append((stage, esev, name, src, entry))
            this_entry_fired.add(key)
            # Prevent the same rule firing twice on the same log entry.
            fired_in_window.add(key)

    # Advance the per-source seen window by one entry regardless of hits so
    # the deque stays synchronised with windows[src].
    seen[src].append(this_entry_fired)
    return hits


def emit(stage, sev, name, src, entry):
    print(f"[{entry['ts']}] {stage} | {sev.upper()} | {name} | src={src} | {entry['raw'][:140]}")


def main():
    ap = argparse.ArgumentParser(description="Spirals Ransomware Kill Chain Detector")
    ap.add_argument("log_file", help="Path to plain-text Windows event log or SIEM export")
    ap.add_argument("--iocs", help="JSON file with supplemental Spirals IOCs")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low")
    args = ap.parse_args()

    extra = defaultdict(list)
    if args.iocs:
        try:
            extra = load_iocs(args.iocs)
        except (OSError, json.JSONDecodeError, KeyError) as e:
            print(f"[WARN] IOC load failed: {e}", file=sys.stderr)

    try:
        fh = open(args.log_file, encoding="utf-8", errors="replace")
    except OSError as e:
        sys.exit(f"[ERROR] {e}")

    windows = defaultdict(lambda: deque(maxlen=WIN))
    # Each element is a set of (stage, name) keys that fired for that log entry.
    # maxlen=WIN ensures the deque evicts in lockstep with the entry window.
    seen = defaultdict(lambda: deque(maxlen=WIN))
    ia_sources = set()
    counts, sources, peak = defaultdict(int), defaultdict(set), {}
    has_high = False
    min_sev = SEV[args.severity]

    with fh:
        for line in fh:
            if not line.strip():
                continue
            entry = parse_entry(line)
            src = entry["src"]
            windows[src].append(entry)
            for stage, sev, name, esrc, ent in check_rules(entry, windows[src], extra, seen, ia_sources):
                if SEV[sev] < min_sev:
                    continue
                emit(stage, sev, name, esrc, ent)
                counts[stage] += 1
                sources[stage].add(esrc)
                if SEV[sev] > SEV[peak.get(stage, "low")]:
                    peak[stage] = sev
                if sev == "high":
                    has_high = True

    print("\n--- Kill Chain Summary ---")
    for stage in ("InitialAccess", "LateralMovement", "Staging"):
        if counts[stage]:
            print(f"  {stage}: {counts[stage]} hit(s), {len(sources[stage])} unique src(s), peak={peak.get(stage,'low').upper()}")
    print("--------------------------")
    if has_high:
        sys.exit(1)


if __name__ == "__main__":
    main()