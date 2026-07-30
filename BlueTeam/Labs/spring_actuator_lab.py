"""
Spring Boot Actuator Exposure & Heap Dump Credential Lab

Scans access logs for Spring Boot actuator endpoint reconnaissance and
analyzes strings-extracted heap dump files for embedded credentials.

Usage:
    python spring_actuator_lab.py <input_file> [--mode auto] [--severity low]

Example:
    python spring_actuator_lab.py /var/log/nginx/access.log --severity medium
    python spring_actuator_lab.py strings_dump.txt --mode dump --severity high
"""
import argparse, re, sys
from collections import defaultdict
from datetime import datetime

LOG_RE = re.compile(r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)[^"]*"\s+(\d{3})')
TS_FMTS = ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S")
ACTUATOR_RE = re.compile(r'/actuator(/|$|/\w+)|/manage(/|$)|/metrics(/|$)|/health(/|$|\?showDetails)', re.I)
HEAPDUMP_RE = re.compile(r'/actuator/heapdump', re.I)
CRED_PATTERNS = [
    (re.compile(r'(?i)password\s*[=:]\s*(\S+)'), 'CredentialLeak'),
    (re.compile(r'(?i)(?<![a-z])secret\s*[=:]\s*(\S+)'), 'SecretPattern'),
    (re.compile(r'(?i)(?<![a-z])token\s*[=:]\s*(\S+)'), 'SecretPattern'),
    (re.compile(r'(?i)Authorization:\s*Bearer\s+(\S+)'), 'CredentialLeak'),
    (re.compile(r'(?i)api[_-]key\s*[=:]\s*(\S+)'), 'SecretPattern'),
    (re.compile(r'(?i)aws_secret_access_key\s*[=:]\s*(\S+)'), 'SecretPattern'),
    (re.compile(r'(?i)(jdbc://\S+)'), 'CredentialLeak'),
    (re.compile(r'(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)'), 'CredentialLeak'),
]
SEV_RANK = {"low": 0, "medium": 1, "high": 2}


def parse_ts(raw):
    for fmt in TS_FMTS:
        try:
            return datetime.strptime(raw.strip(), fmt).replace(tzinfo=None)
        except ValueError:
            pass
    return datetime.utcnow()


def detect_mode(path):
    method_re = re.compile(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s')
    with open(path, encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if i >= 20: break
            if method_re.search(line) and re.search(r'\s[1-5]\d{2}[\s"]', line):
                return "log"
    return "dump"


def redact(val):
    return val[:4] + "*" * max(0, len(val) - 4)


def parse_log(path):
    records, dropped = [], 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = LOG_RE.search(line.strip())
            if m:
                records.append((parse_ts(m.group(2)), m.group(1), m.group(3), m.group(4), int(m.group(5))))
            elif line.strip():
                dropped += 1
    return records, dropped


def analyze_log(records, min_sev):
    findings, counts, dedup, ips = [], defaultdict(int), defaultdict(dict), set()
    for ts, ip, method, path, status in records:
        if not ACTUATOR_RE.search(path): continue
        is_hd = bool(HEAPDUMP_RE.search(path)) and status == 200
        ftype = "HeapdumpDownload" if is_hd else "ActuatorProbe"
        sev, tech = ("high", "T1005") if is_hd else ("medium", "T1046")
        if ftype == "ActuatorProbe":
            last = dedup[ip].get(path)
            if last and (ts - last).total_seconds() < 30: continue
            dedup[ip][path] = ts
        counts[ftype] += 1; ips.add(ip)
        if SEV_RANK[sev] >= SEV_RANK[min_sev]:
            findings.append((ts, "LogScan", sev, ftype, path, tech, ip))
    return findings, counts, ips


def analyze_dump(path, min_sev):
    findings, counts = [], defaultdict(int)
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip()
            if not line: continue
            for pat, ftype in CRED_PATTERNS:
                m = pat.search(line)
                if not m: continue
                val = m.group(1) if m.lastindex else m.group(0)
                start = max(0, m.start() - 30)
                ctx = line[start:start + 90].replace(val, redact(val))
                counts[ftype] += 1
                if SEV_RANK["high"] >= SEV_RANK[min_sev]:
                    findings.append((datetime.utcnow(), "DumpScan", "high", ftype, ctx, "T1552", None))
    return findings, counts


def main():
    ap = argparse.ArgumentParser(description="Spring Boot Actuator Exposure & Heap Dump Credential Lab")
    ap.add_argument("input_file")
    ap.add_argument("--mode", choices=["log", "dump", "auto"], default="auto")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low")
    args = ap.parse_args()
    try:
        mode = args.mode if args.mode != "auto" else detect_mode(args.input_file)
    except OSError as e:
        sys.exit(f"Error: {e}")
    high_found, peak_sev, techniques, all_counts = False, "low", set(), defaultdict(int)
    if mode == "log":
        try:
            records, dropped = parse_log(args.input_file)
        except OSError as e:
            sys.exit(f"Error: {e}")
        findings, counts, ips = analyze_log(records, args.severity)
        for ts, sm, sev, ftype, path, tech, ip in findings:
            print(f"[{sm}] [{sev.upper()}] {ftype} src={ip} path={path} technique={tech} ts={ts.isoformat()}")
            techniques.add(tech)
            if SEV_RANK[sev] > SEV_RANK[peak_sev]: peak_sev = sev
            if sev == "high": high_found = True
        all_counts.update(counts)
        print(f"\n--- Summary (LogScan) | dropped={dropped} unique_ips={len(ips)} ---")
    else:
        try:
            findings, counts = analyze_dump(args.input_file, args.severity)
        except OSError as e:
            sys.exit(f"Error: {e}")
        pclasses = set()
        for ts, sm, sev, ftype, ctx, tech, _ in findings:
            print(f"[{sm}] [{sev.upper()}] {ftype} context={ctx!r} technique={tech} ts={ts.isoformat()}")
            techniques.add(tech); pclasses.add(ftype); peak_sev = "high"; high_found = True
        all_counts.update(counts)
        print(f"\n--- Summary (DumpScan) | unique_pattern_classes={len(pclasses)} ---")
    for ftype, cnt in sorted(all_counts.items()):
        print(f"  {ftype}: {cnt}")
    print(f"MITRE: {', '.join(sorted(techniques)) or 'none'} | peak_severity={peak_sev.upper()}")
    sys.exit(1 if high_found else 0)


if __name__ == "__main__":
    main()