#!/usr/bin/env python3
"""
encforge_langflow_ransomware_detector — detect ENCFORGE/JADEPUFFER kill chain in Langflow logs.

Usage:
    python encforge_langflow_ransomware_detector.py /var/log/langflow/app.log
    python encforge_langflow_ransomware_detector.py access.log --iocs extra_iocs.json --severity high
"""
import argparse, json, re, sys
from collections import defaultdict
from datetime import datetime

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

RCE_KEYWORDS = re.compile(r'subprocess|os\.system|eval\(|exec\(|__import__|`[^`]+`|\$\([^)]+\)')
RCE_ENDPOINTS = re.compile(r'/api/v\d+/(process|run|predict|flow)', re.I)
RCE_COMPONENTS = re.compile(r'PythonREPL|BashTool|CodeExecutor|code_input|run_code', re.I)
AI_EXT = re.compile(r'\.(pt|pth|ckpt|safetensors|bin|faiss|index)$', re.I)
ENC_EXT = re.compile(r'\.(enc|locked|encforge|jdp)$', re.I)
STAGING_DIR = re.compile(r'^(/tmp/|/var/tmp/|/dev/shm/)[a-z0-9]{6,}', re.I)
GUNICORN_RE = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)[^"]*"(?P<method>\w+)\s+(?P<path>\S+)[^"]*"\s+(?P<code>\d+)')
AUDIT_RE = re.compile(r'pid=(?P<pid>\d+).*?(?:name|path)="(?P<path>[^"]+)".*?syscall=(?P<sc>\w+)', re.I)


def parse_ts(s):
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%d/%b/%Y:%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def parse_line(line):
    entry = {"raw": line, "ts": None, "ip": None, "pid": None,
             "method": "", "path": "", "code": None, "payload": line}
    m = GUNICORN_RE.search(line)
    if m:
        entry.update(ip=m.group("ip"), method=m.group("method"),
                     path=m.group("path"), code=int(m.group("code")))
        ts_m = re.search(r'\[(\d+/\w+/\d+:\d+:\d+:\d+)', line)
        if ts_m:
            entry["ts"] = parse_ts(ts_m.group(1))
        return entry
    m = AUDIT_RE.search(line)
    if m:
        entry.update(pid=m.group("pid"), path=m.group("path"), method=m.group("sc").upper())
        ts_m = re.search(r'msg=audit\((\d+\.\d+)', line)
        if ts_m:
            try:
                entry["ts"] = datetime.fromtimestamp(float(ts_m.group(1)))
            except (ValueError, OSError):
                pass
        return entry
    try:
        obj = json.loads(line)
        entry["ts"] = parse_ts(str(obj.get("timestamp", "")))
        entry.update(ip=obj.get("ip") or obj.get("client_ip"),
                     pid=str(obj.get("pid", "") or ""),
                     path=obj.get("component") or obj.get("path") or obj.get("flow_id") or "",
                     method=obj.get("method", ""), payload=json.dumps(obj))
        return entry
    except json.JSONDecodeError:
        pass
    ts_m = re.search(r'"timestamp"\s*:\s*"([^"]+)"', line)
    if ts_m:
        entry["ts"] = parse_ts(ts_m.group(1))
    return entry


def validate_ioc_lists(extra_iocs):
    for key in ("rce_endpoints", "enc_extensions", "staging_dirs"):
        val = extra_iocs.get(key)
        if val is not None and not isinstance(val, list):
            print(f"[WARN] IOC field '{key}' must be a list, got {type(val).__name__}", file=sys.stderr)
            extra_iocs[key] = []


def classify_entry(entry, extra_iocs):
    raw = entry["payload"]
    path = entry["path"]
    method = entry["method"]
    code = entry["code"]

    raw_xep = extra_iocs.get("rce_endpoints", [])
    raw_xee = extra_iocs.get("enc_extensions", [])
    raw_xsd = extra_iocs.get("staging_dirs", [])
    xep = raw_xep if isinstance(raw_xep, list) else []
    xee = raw_xee if isinstance(raw_xee, list) else []
    xsd = raw_xsd if isinstance(raw_xsd, list) else []

    if (RCE_ENDPOINTS.search(path) or any(p in path for p in xep) or RCE_COMPONENTS.search(raw)) \
            and method in ("POST", ""):
        if RCE_KEYWORDS.search(raw) or code in (200, 500):
            return "InitialAccess", "high", "LangflowRCEEndpointAbuse"
    if RCE_COMPONENTS.search(path) and code == 500:
        return "InitialAccess", "medium", "PythonREPLNodeException"
    if STAGING_DIR.search(path) or any(path.startswith(d) for d in xsd):
        if AI_EXT.search(path):
            return "Staging", "high", "JADEPUFFERStagingDirectory"
        return "Staging", "medium", "SuspiciousTempDirectory"
    if AI_EXT.search(path) and method in ("READ", "OPEN", ""):
        return "Staging", "low", "AIAssetBulkRead"
    if ENC_EXT.search(path) or any(path.endswith(e) for e in xee):
        base = re.sub(r'\.[a-z0-9]+$', '', path, flags=re.I)
        if AI_EXT.search(base):
            return "PreEncryption", "high", "ENCFORGEDoubleExtensionRename"
        return "PreEncryption", "medium", "SuspiciousEncryptedFile"
    if method in ("RENAME", "UNLINK") and AI_EXT.search(path):
        rule = "VectorIndexTampering" if re.search(r'faiss|\.index', path, re.I) else "ModelCheckpointTampering"
        return "PreEncryption", "high", rule
    return None, None, None


def main():
    ap = argparse.ArgumentParser(description="Detect ENCFORGE/JADEPUFFER kill chain in Langflow logs.")
    ap.add_argument("log_file", help="Path to Langflow execution or access log")
    ap.add_argument("--iocs", help="JSON file with supplemental IOC patterns")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low")
    args = ap.parse_args()

    extra_iocs = {}
    if args.iocs:
        try:
            with open(args.iocs) as f:
                loaded = json.load(f)
            if not isinstance(loaded, dict):
                print(f"[WARN] --iocs JSON root must be an object, got {type(loaded).__name__}; ignoring", file=sys.stderr)
            else:
                extra_iocs = loaded
        except (OSError, json.JSONDecodeError) as e:
            print(f"[WARN] Could not load --iocs: {e}", file=sys.stderr)

    validate_ioc_lists(extra_iocs)

    min_sev = SEVERITY_RANK[args.severity]
    phase_counts = defaultdict(int)
    source_ids, asset_paths = set(), set()
    peak_sev, has_high = "low", False
    initial_access_times = {}
    recent = []

    try:
        with open(args.log_file) as f:
            lines = f.readlines()
    except OSError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(2)

    for line in lines:
        line = line.rstrip()
        if not line:
            continue
        entry = parse_line(line)
        phase, sev, rule = classify_entry(entry, extra_iocs)
        if not phase or SEVERITY_RANK[sev] < min_sev:
            continue

        src = entry.get("ip") or entry.get("pid") or "unknown"
        path = entry["path"]
        ts = entry["ts"]
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S") if ts else "no-timestamp"

        burst_key = (src, rule)
        recent.append(burst_key)
        if len(recent) > 20:
            recent.pop(0)
        if recent.count(burst_key) > 3:
            continue

        if src != "unknown":
            if phase in ("Staging", "PreEncryption"):
                initial_access_ts = initial_access_times.get(src)
                if initial_access_ts and ts and abs((ts - initial_access_ts).total_seconds()) <= 300:
                    sev = "high"
            elif phase == "InitialAccess" and ts:
                initial_access_times[src] = ts

        phase_counts[phase] += 1
        source_ids.add(src)
        if AI_EXT.search(path):
            asset_paths.add(path)
        if SEVERITY_RANK[sev] > SEVERITY_RANK[peak_sev]:
            peak_sev = sev
        if sev == "high":
            has_high = True

        print(f"[{ts_str}] [{phase}] [{sev.upper()}] {rule} src={src} path={path!r} | {line[:140]}")

    print("\n--- Kill-Chain Detection Summary ---")
    for phase in ("InitialAccess", "Staging", "PreEncryption"):
        print(f"  {phase}: {phase_counts[phase]} hit(s)")
    print(f"  Unique sources flagged : {len(source_ids)}")
    print(f"  Distinct AI asset paths: {len(asset_paths)}")
    print(f"  Peak severity          : {peak_sev.upper()}")
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()