"""
gRPC C2 Beacon & HTTP/2 Streaming Anomaly Detector (MODBEACON)

Analyzes TLS-inspecting HTTP proxy access logs for gRPC-based C2 activity
matching MODBEACON behavioral signatures.

Usage:
    python grpc_c2_stream_detector.py access.log
    python grpc_c2_stream_detector.py access.log --allowlist grpc_allowlist.json --min-duration 30
"""

import argparse
import ipaddress
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

GRPC_CT_RE = re.compile(r'application/grpc(?:\+proto|-web)?', re.I)

PROXY_LOG_RE = re.compile(
    r'(?P<ts>\d+(?:\.\d+)?)\s+'
    r'(?P<duration>\d+(?:\.\d+)?)\s+'
    r'(?P<src_ip>\S+)\s+\S+/(?P<code>\d+)\s+(?P<bytes>\d+)\s+\S+\s+'
    r'(?P<user>[^@\s]+@)?(?P<dest_host>[^\s:/]+)(?::(?P<dest_port>\d+))?\S*\s+'
    r'\S+/(?P<proto>HTTP/[\d.]+|-)\s+(?P<content_type>\S+)'
    r'(?:.*?"(?P<ua>[^"]*)")?',
    re.I
)

COMBINED_LOG_RE = re.compile(
    r'(?P<src_ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"[A-Z]+\s+(?:https?://)?(?P<dest_host>[^\s:/]+)(?::(?P<dest_port>\d+))?[^\s"]*\s+(?P<proto>HTTP/[\d.]+)"\s+'
    r'(?P<code>\d+)\s+(?P<bytes>\d+)\s+"[^"]*"\s+"(?P<ua>[^"]*)"\s*'
    r'(?:.*?content-type[=: ]+(?P<content_type>application/grpc\S*))?'
    r'(?:.*?duration[=: ]+(?P<duration>\d+(?:\.\d+)?))?',
    re.I
)

KNOWN_GRPC_UAS = re.compile(r'grpc-(?:go|python|java|node|c\+\+|csharp|dart|objc|ruby|php)/\d', re.I)
SUSPICIOUS_UAS = re.compile(r'^(?:python-requests|curl|Go-http-client(?!/grpc)|wget|libwww-perl|okhttp)', re.I)
CANONICAL_GRPC_PORTS = {443, 50051}


def load_allowlist(path):
    if not path:
        return frozenset(), frozenset()
    try:
        with open(path) as f:
            data = json.load(f)
        domains = frozenset(d.lower() for d in data.get("domains", []))
        prefixes = []
        for p in data.get("ip_prefixes", []):
            try:
                prefixes.append(ipaddress.ip_network(p, strict=False))
            except ValueError:
                pass
        return domains, tuple(prefixes)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[WARN] Could not load allowlist: {e}", file=sys.stderr)
        return frozenset(), tuple()


def is_allowed(host, port, domains, ip_prefixes):
    host = host.lower()
    for suffix in domains:
        if host == suffix or host.endswith("." + suffix):
            return True
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in ip_prefixes)
    except ValueError:
        pass
    return False


def parse_duration(raw):
    if raw is None:
        return None
    try:
        val = float(raw)
        return val / 1000.0 if val > 10000 else val
    except ValueError:
        return None


def parse_entries(log_file):
    dropped = 0
    try:
        with open(log_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = PROXY_LOG_RE.match(line) or COMBINED_LOG_RE.match(line)
                if not m:
                    dropped += 1
                    continue
                groups = m.groupdict()
                ct = (groups.get("content_type") or "").strip()
                if not GRPC_CT_RE.search(ct):
                    dropped += 1
                    continue
                raw_ts = groups.get("ts", "")
                ts = None
                try:
                    ts = datetime.utcfromtimestamp(float(raw_ts)).isoformat() + "Z"
                except (ValueError, TypeError, OSError):
                    try:
                        dt = datetime.strptime(raw_ts.strip(), "%d/%b/%Y:%H:%M:%S %z")
                        ts = dt.astimezone(timezone.utc).isoformat().replace("+00:00", "") + "Z"
                    except (ValueError, AttributeError):
                        try:
                            dt = datetime.strptime(raw_ts.strip(), "%d/%b/%Y:%H:%M:%S")
                            ts = dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "") + "Z"
                        except (ValueError, AttributeError):
                            ts = raw_ts
                duration = parse_duration(groups.get("duration"))
                try:
                    dest_port = int(groups.get("dest_port") or 443)
                except (ValueError, TypeError):
                    dest_port = 443
                try:
                    sbytes = int(groups.get("bytes") or 0)
                except (ValueError, TypeError):
                    sbytes = 0
                yield {
                    "ts": ts,
                    "src_ip": groups.get("src_ip", ""),
                    "dest_host": (groups.get("dest_host") or "").lower().rstrip("."),
                    "dest_port": dest_port,
                    "proto": groups.get("proto", ""),
                    "content_type": ct,
                    "duration": duration,
                    "bytes": sbytes,
                    "ua": (groups.get("ua") or "").strip(),
                }
    except OSError as e:
        print(f"[ERROR] Cannot read log file: {e}", file=sys.stderr)
        sys.exit(2)
    if dropped:
        print(f"[INFO] Skipped {dropped} non-gRPC or malformed lines", file=sys.stderr)


def is_bare_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def detect_signals(entries, domains, ip_prefixes, min_duration):
    for e in entries:
        host, port, ct, ua, dur, ts = (
            e["dest_host"], e["dest_port"], e["content_type"],
            e["ua"], e["duration"], e["ts"]
        )
        allowed = is_allowed(host, port, domains, ip_prefixes)
        non_canonical_port = port not in CANONICAL_GRPC_PORTS
        non_std_host = not allowed and is_bare_ip(host)
        if non_canonical_port or non_std_host:
            yield ("NonStandardGRPCEndpoint", "T1071.002", "high", e)
        if dur is not None and dur >= min_duration:
            yield ("LongLivedGRPCStream", "T1071.002/T1095", "high", e)
        if not ua or SUSPICIOUS_UAS.match(ua) or (not KNOWN_GRPC_UAS.search(ua) and "grpc" not in ua.lower()):
            yield ("AnomalousGRPCInitiator", "T1573.002", "medium", e)


def report_findings(signals):
    counts = defaultdict(int)
    dest_hosts = set()
    mitre_ids = set()
    total_bytes = 0
    dedup = {}
    found_high = False

    for sig_class, mitre, severity, e in signals:
        key = (sig_class, e["src_ip"], e["dest_host"])
        if sig_class == "NonStandardGRPCEndpoint":
            try:
                ts_epoch = datetime.fromisoformat(e["ts"].rstrip("Z")).timestamp()
            except (ValueError, AttributeError):
                ts_epoch = None

            if ts_epoch is not None:
                last = dedup.get(key, -999)
                if ts_epoch - last < 120:
                    continue
                dedup[key] = ts_epoch

        counts[sig_class] += 1
        dest_hosts.add(e["dest_host"])
        mitre_ids.add(mitre)
        total_bytes += e["bytes"]
        if severity == "high":
            found_high = True

        dur_str = f" duration={e['duration']:.1f}s" if e["duration"] is not None else ""
        print(
            f"[{e['ts']}] ALERT sig={sig_class} mitre={mitre} severity={severity}"
            f" src={e['src_ip']} dst={e['dest_host']}:{e['dest_port']}"
            f" ct={e['content_type']}{dur_str} ua={e['ua'] or '<none>'}"
        )

    print("\n--- Summary ---")
    for sig, cnt in counts.items():
        print(f"  {sig}: {cnt}")
    print(f"  unique_flagged_destinations: {len(dest_hosts)}")
    print(f"  mitre_techniques: {', '.join(sorted(mitre_ids)) or 'none'}")
    print(f"  peak_severity: {'high' if found_high else 'medium' if counts else 'none'}")
    print(f"  total_suspicious_bytes: {total_bytes}")

    return found_high


def main():
    parser = argparse.ArgumentParser(description="gRPC C2 Beacon & HTTP/2 Streaming Anomaly Detector (MODBEACON)")
    parser.add_argument("log_file", help="Path to TLS-inspecting proxy access log")
    parser.add_argument("--allowlist", help="JSON file with known-good gRPC domain suffixes and IP prefixes")
    parser.add_argument("--min-duration", type=float, default=30.0, dest="min_duration",
                        help="Minimum gRPC stream duration in seconds to flag (default: 30)")
    args = parser.parse_args()

    domains, ip_prefixes = load_allowlist(args.allowlist)
    entries = parse_entries(args.log_file)
    signals = detect_signals(entries, domains, ip_prefixes, args.min_duration)
    found_high = report_findings(signals)
    sys.exit(1 if found_high else 0)


if __name__ == "__main__":
    main()