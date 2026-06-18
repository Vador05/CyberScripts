"""
WebLogic CVE-2024-21182 Hunt Rule Generator

Parses plain-text HTTP/WebLogic access and server logs to detect exploitation
patterns matching CVE-2024-21182 (JNDI/T3 deserialization abuse) as tracked
in active KEV campaigns. Outputs structured Sigma-style detection hits.

Usage:
    python weblogic_cve2024_21182_hunter.py /var/log/weblogic/access.log
    python weblogic_cve2024_21182_hunter.py server.log --threshold 3
    python weblogic_cve2024_21182_hunter.py access.log --since 2024-01-15
    python weblogic_cve2024_21182_hunter.py access.log --threshold 2 --since 2024-03-01

Output format:
    ALERT | <timestamp> | src=<ip> | pattern=<rule_name> | line=<log_excerpt>
    SUMMARY | <n> alerts | <m> unique IPs | rules triggered: <list>
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import date, datetime


def load_rules() -> dict:
    return {
        "T3_IIOP_PROTO": re.compile(
            r"(?:t3s?://|iiop://|/wls-wsat/|/uddiexplorer/|/bea_wls_internal/)",
            re.IGNORECASE,
        ),
        "JNDI_LOOKUP": re.compile(
            r"\$\{jndi:(?:ldap|rmi|dns|corba|iiop|nis|nds|http)s?://",
            re.IGNORECASE,
        ),
        "CLASSPATH_XML": re.compile(
            r"ClassPathXmlApplicationContext|FileSystemXmlApplicationContext",
            re.IGNORECASE,
        ),
        "WLS_SERVLET_ABUSE": re.compile(
            r"/wls-wsat/CoordinatorPortType|/async/AsyncResponseService|/wls-wsat/RegistrationRequesterPortType",
            re.IGNORECASE,
        ),
        "DESER_GADGET": re.compile(
            r"(?:aced0005|java\.rmi\.server\.UnicastRef|weblogic\.cluster\.singleton|org\.springframework\.context)",
            re.IGNORECASE,
        ),
        "T3_HEADER_ABUSE": re.compile(
            r"(?:T3|HELO)\s+\d+\.\d+\.\d+|weblogic\.security\.acl|weblogic\.rjvm",
            re.IGNORECASE,
        ),
        "LDAP_CALLBACK": re.compile(
            r"(?:ldap|rmi|corba)://[0-9a-zA-Z._-]+:\d+/[^\s\"'<>]{1,200}",
            re.IGNORECASE,
        ),
        "WLS_MGMT_PATH": re.compile(
            r"/console/(?:portal|framework)|/management/tenant-monitoring|/em/faces/",
            re.IGNORECASE,
        ),
        "ENCODED_JNDI": re.compile(
            r"%24%7bjndi%3a|%24%7Bjndi%3A|\$\{[jJ][nN][dD][iI]:|\\u0024\\u007bjndi",
            re.IGNORECASE,
        ),
        "EXPLOIT_USERAGENT": re.compile(
            r'(?:"|\s)(?:python-requests/|Go-http-client/|curl/\d|zgrab|Nuclei|Exploit)',
            re.IGNORECASE,
        ),
    }


def _extract_ip(line: str) -> str:
    match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
    return match.group(1) if match else "unknown"


def _extract_timestamp(line: str) -> str:
    patterns = [
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}",
        r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}",
        r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
    ]
    for pat in patterns:
        m = re.search(pat, line)
        if m:
            return m.group(0)
    return "no-timestamp"


def _parse_line_date(line: str) -> date | None:
    patterns = [
        ("%Y-%m-%dT%H:%M:%S", r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),
        ("%Y-%m-%d %H:%M:%S", r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"),
        ("%d/%b/%Y:%H:%M:%S", r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}"),
    ]
    for fmt, pat in patterns:
        m = re.search(pat, line)
        if m:
            try:
                return datetime.strptime(m.group(0), fmt).date()
            except ValueError:
                continue
    return None


def scan_log(
    log_path: str,
    rules: dict,
    threshold: int,
    since: date | None,
) -> list[dict]:
    hits_per_ip: dict[str, int] = defaultdict(int)
    raw_findings: list[dict] = []

    try:
        with open(log_path, "r", errors="replace") as fh:
            for line in fh:
                line = line.rstrip()
                if not line:
                    continue
                if since is not None:
                    line_date = _parse_line_date(line)
                    if line_date is not None and line_date < since:
                        continue
                for rule_name, pattern in rules.items():
                    if pattern.search(line):
                        ip = _extract_ip(line)
                        ts = _extract_timestamp(line)
                        excerpt = line[:200]
                        hits_per_ip[ip] += 1
                        raw_findings.append(
                            {
                                "timestamp": ts,
                                "ip": ip,
                                "rule": rule_name,
                                "excerpt": excerpt,
                            }
                        )
    except FileNotFoundError:
        print(f"ERROR: log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"ERROR: permission denied reading: {log_path}", file=sys.stderr)
        sys.exit(1)

    return [f for f in raw_findings if hits_per_ip[f["ip"]] >= threshold]


def emit_findings(findings: list[dict]) -> None:
    triggered_rules: set[str] = set()
    unique_ips: set[str] = set()

    for f in findings:
        triggered_rules.add(f["rule"])
        unique_ips.add(f["ip"])
        print(
            f"ALERT | {f['timestamp']} | src={f['ip']} | pattern={f['rule']} | line={f['excerpt']}"
        )

    rules_list = ", ".join(sorted(triggered_rules)) if triggered_rules else "none"
    print(
        f"SUMMARY | {len(findings)} alerts | {len(unique_ips)} unique IPs | rules triggered: {rules_list}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect CVE-2024-21182 exploitation patterns in WebLogic logs."
    )
    parser.add_argument("log_file", help="Path to plain-text WebLogic access or server log")
    parser.add_argument(
        "--threshold",
        type=int,
        default=1,
        help="Minimum hits per IP before flagging (default: 1)",
    )
    parser.add_argument(
        "--since",
        default=None,
        help="Ignore log entries before this ISO date (YYYY-MM-DD)",
    )
    args = parser.parse_args()

    since_date: date | None = None
    if args.since:
        try:
            since_date = date.fromisoformat(args.since)
        except ValueError:
            print(f"ERROR: --since must be YYYY-MM-DD, got: {args.since}", file=sys.stderr)
            sys.exit(1)

    if args.threshold < 1:
        print("ERROR: --threshold must be >= 1", file=sys.stderr)
        sys.exit(1)

    rules = load_rules()
    findings = scan_log(args.log_file, rules, args.threshold, since_date)
    emit_findings(findings)


if __name__ == "__main__":
    main()
