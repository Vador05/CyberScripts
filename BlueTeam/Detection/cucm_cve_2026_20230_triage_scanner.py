"""
CUCM CVE-2026-20230 Triage Scanner

Parses Cisco Unified Communications Manager audit/access logs for SSRF trigger
patterns and privilege-escalation sequences linked to CVE-2026-20230.

Usage:
    python cucm_cve_2026_20230_triage_scanner.py /var/log/cucm/ccm0001.log
    python cucm_cve_2026_20230_triage_scanner.py audit.log --severity HIGH --verbose
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime

LOG_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r".*?(?:src|client|from)[=: ]+(?P<src_ip>[\d\.]+)"
    r".*?(?P<method>GET|POST|PUT|DELETE|SOAP)?\s*(?P<path>/[^\s\"']*)"
    r"(?:.*?user[=: ]+(?P<user>\S+))?",
    re.IGNORECASE,
)

# HIGH patterns precede MEDIUM so break-on-first-match always emits the highest severity
SSRF_PATTERNS = [
    (re.compile(r"(?:%2F|/)(?:169\.254\.\d+\.\d+)", re.IGNORECASE), "HIGH", "SSRF-001", "metadata endpoint probe (169.254.x.x)"),
    (re.compile(r"(?:%2F|/)(?:127\.0\.0\.1|localhost|0\.0\.0\.0)", re.IGNORECASE), "HIGH", "SSRF-002", "loopback destination in outbound request"),
    (re.compile(r"url=(?:https?%3A|https?:)(?:%2F%2F|//)(?:10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.|127\.|169\.254\.)", re.IGNORECASE), "HIGH", "SSRF-004", "URL-encoded internal target in url= parameter"),
    (re.compile(r"(?:serviceURL|redirectURL|nextURL|callbackUrl)=(?:[^&\s]*(?:localhost|127\.0\.0\.1|169\.254\.|10\.|192\.168\.))", re.IGNORECASE), "HIGH", "SSRF-005", "SSRF via CUCM redirect/callback parameter"),
    (re.compile(r"(?:%2F|/)(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)", re.IGNORECASE), "MEDIUM", "SSRF-003", "RFC-1918 internal target in CUCM HTTP parameter"),
]

PRIVESC_PATTERNS = [
    (re.compile(r"/axl/.*?(?:addUser|updateUser|addAppUser|updateAppUser)", re.IGNORECASE), "HIGH", "PRIV-001", "AXL SOAP API user creation/modification"),
    (re.compile(r"/axl/.*?(?:addUserGroup|updateUserGroup|addUserToGroup)", re.IGNORECASE), "HIGH", "PRIV-002", "AXL SOAP API group membership modification"),
    (re.compile(r"CCMAdministrator|Standard\s+CCM\s+Admin|Standard\s+AXL\s+API\s+Access", re.IGNORECASE), "HIGH", "PRIV-003", "CCMAdministrator or AXL admin role reference"),
    (re.compile(r"/ccmadmin/.*?(?:userGroupRoleMap|roleList|privilege)", re.IGNORECASE), "MEDIUM", "PRIV-004", "Admin UI role/privilege manipulation"),
    (re.compile(r"/axl/.*?(?:executeSQLUpdate|executeSQLQuery).*?(?:enduser|applicationuser|role|privilege)", re.IGNORECASE), "HIGH", "PRIV-005", "AXL direct SQL manipulation of user/role tables"),
]

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _sanitize(s, maxlen=200):
    """Strip terminal control/escape characters before printing analyst-visible output."""
    return _CTRL_RE.sub("?", s)[:maxlen]


def parse_log(path):
    entries = []
    warn_count = 0
    try:
        with open(path, "r", errors="replace") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.rstrip()
                m = LOG_RE.search(line)
                if not m:
                    warn_count += 1
                    continue
                ts_str = m.group("ts").replace(" ", "T")
                try:
                    ts = datetime.fromisoformat(ts_str)
                except ValueError:
                    warn_count += 1
                    continue
                entries.append({
                    "ts": ts,
                    "src_ip": m.group("src_ip") or "unknown",
                    "method": m.group("method") or "-",
                    "path": m.group("path") or "-",
                    "user": m.group("user") or "-",
                    "raw": line,
                    "lineno": lineno,
                })
    except OSError as exc:
        sys.exit(f"[ERROR] Cannot open log file: {exc}")
    if warn_count:
        print(f"[WARN] {warn_count} lines skipped (unparseable)", file=sys.stderr)
    return entries


def detect_ssrf(entries):
    findings = []
    for e in entries:
        target = e["path"] + " " + e["raw"]
        for pattern, sev, rule_id, note in SSRF_PATTERNS:
            m = pattern.search(target)
            if m:
                findings.append({**e, "severity": sev, "rule_id": rule_id,
                                  "matched_field": _sanitize(m.group(0), 120), "note": note})
                break
    return findings


def detect_privesc(entries, window_seconds=300):
    findings = []
    ssrf_hits = defaultdict(list)
    for e in entries:
        for pattern, _, _, _ in SSRF_PATTERNS:
            if pattern.search(e["path"] + " " + e["raw"]):
                ssrf_hits[e["src_ip"]].append(e["ts"])
                break
    for e in entries:
        for pattern, sev, rule_id, note in PRIVESC_PATTERNS:
            m = pattern.search(e["path"] + " " + e["raw"])
            if m:
                ip = e["src_ip"]
                preceded_by_ssrf = any(
                    abs((e["ts"] - t).total_seconds()) <= window_seconds
                    for t in ssrf_hits.get(ip, [])
                )
                effective_sev = sev if preceded_by_ssrf else "MEDIUM" if sev == "HIGH" else "LOW"
                findings.append({**e, "severity": effective_sev, "rule_id": rule_id,
                                  "matched_field": _sanitize(m.group(0), 120),
                                  "note": note + (" [SSRF-correlated]" if preceded_by_ssrf else "")})
                break
    return findings


def emit(findings, min_severity, verbose):
    counts = defaultdict(int)
    min_ord = SEVERITY_ORDER[min_severity]
    for f in sorted(findings, key=lambda x: x["ts"]):
        if SEVERITY_ORDER[f["severity"]] < min_ord:
            continue
        counts[f["rule_id"][:4]] += 1
        ts = f["ts"].strftime("%Y-%m-%dT%H:%M:%S")
        print(f"{ts} | {f['severity']:<6} | {f['rule_id']} | {f['src_ip']:<15} | {f['matched_field']} | {f['note']}")
        if verbose:
            print(f"  line {f['lineno']}: {_sanitize(f['raw'])}")
    print(f"\n--- Summary ---")
    print(f"  SSRF findings : {counts.get('SSRF', 0)}")
    print(f"  PRIV findings : {counts.get('PRIV', 0)}")
    print(f"  Total emitted : {sum(counts.values())}")


def main():
    parser = argparse.ArgumentParser(
        description="CUCM CVE-2026-20230 Triage Scanner — detects SSRF and privilege-escalation IoCs in CUCM logs."
    )
    parser.add_argument("log_file", help="Path to CUCM plain-text audit or ccm*.log file")
    parser.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH"], default="LOW",
                        help="Minimum finding severity to emit (default: LOW)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print full matched log line alongside each finding")
    parser.add_argument("--window", type=int, default=300, metavar="SECONDS",
                        help="Time window in seconds for SSRF\u2192privesc correlation (default: 300)")
    args = parser.parse_args()

    entries = parse_log(args.log_file)
    if not entries:
        sys.exit("[ERROR] No parseable log entries found.")

    findings = detect_ssrf(entries) + detect_privesc(entries, window_seconds=args.window)
    emit(findings, args.severity, args.verbose)


if __name__ == "__main__":
    main()