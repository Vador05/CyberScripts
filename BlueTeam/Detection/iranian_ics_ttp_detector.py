"""
Iranian ICS TTP Detector for Siemens, Schneider, and Rockwell PLCs

Scans plain-text OT network traffic log exports for indicators of known Iranian
threat actor TTPs targeting Siemens, Schneider Electric, and Rockwell Automation PLCs.

Usage:
    python iranian_ics_ttp_detector.py traffic.log
    python iranian_ics_ttp_detector.py traffic.log --iocs cisa_iocs.json --severity high

Example log formats supported:
    - Siemens WinCC audit CSV
    - Rockwell Logix historian plaintext
    - Schneider EcoStruxure syslog
    - Generic Modbus/EtherNet-IP tab-delimited
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

CISA_IRANIAN_IPS = {
    "146.70.87.14", "146.70.87.91", "185.220.101.0", "162.247.74.200",
    "194.165.16.0", "194.165.17.0", "45.155.205.0", "91.108.4.0",
}

AUTHORIZED_ENGINEERING_IPS = set()
APPROVED_RESOLVERS = {"8.8.8.8", "8.8.4.4", "1.1.1.1"}

RULES = [
    {
        "stage": "PLCRecon",
        "technique": "T0846",
        "name": "ModbusTCP-FC43-DeviceID-Read",
        "severity": "medium",
        "protocol": r"modbus",
        "payload": r"\bfc[:\s=]?43\b|function.code[:\s=]?43|read.device.id",
    },
    {
        "stage": "PLCRecon",
        "technique": "T0888",
        "name": "ModbusTCP-FC17-ServerID-Request",
        "severity": "medium",
        "protocol": r"modbus",
        "payload": r"\bfc[:\s=]?17\b|function.code[:\s=]?17|report.server.id",
    },
    {
        "stage": "PLCRecon",
        "technique": "T0846",
        "name": "EtherNetIP-ListIdentity-Broadcast",
        "severity": "medium",
        "port": r"44818",
        "payload": r"list.identity|list_identity|0x0063|enip.list",
    },
    {
        "stage": "PLCRecon",
        "technique": "T0846",
        "name": "PROFINET-DCP-Identify-Multicast",
        "severity": "medium",
        "protocol": r"profinet|pn.dcp|dcp",
        "payload": r"identify.filter|dcp.identify|01:0e:cf:00:00:00",
    },
    {
        "stage": "PLCRecon",
        "technique": "T0888",
        "name": "S7comm-Module-Identification-JobRequest",
        "severity": "medium",
        "protocol": r"s7comm|s7\b",
        "payload": r"job.request|pdu.type[:\s=]?1|module.ident|szl.id|0x0111|0x001c",
    },
    {
        "stage": "CommandInjection",
        "technique": "T0836",
        "name": "ModbusTCP-FC5-WriteCoil-Unauthorized",
        "severity": "high",
        "protocol": r"modbus",
        "payload": r"\bfc[:\s=]?5\b|function.code[:\s=]?5|write.single.coil",
        "src_ip_exclude": AUTHORIZED_ENGINEERING_IPS,
    },
    {
        "stage": "CommandInjection",
        "technique": "T0836",
        "name": "ModbusTCP-FC6-WriteRegister-Unauthorized",
        "severity": "high",
        "protocol": r"modbus",
        "payload": r"\bfc[:\s=]?6\b|function.code[:\s=]?6|write.single.register",
        "src_ip_exclude": AUTHORIZED_ENGINEERING_IPS,
    },
    {
        "stage": "CommandInjection",
        "technique": "T0855",
        "name": "ModbusTCP-FC16-WriteMultipleRegisters",
        "severity": "high",
        "protocol": r"modbus",
        "payload": r"\bfc[:\s=]?16\b|function.code[:\s=]?16|write.multiple.reg",
        "src_ip_exclude": AUTHORIZED_ENGINEERING_IPS,
    },
    {
        "stage": "CommandInjection",
        "technique": "T0821",
        "name": "EtherNetIP-ForwardOpen-OutputObject",
        "severity": "high",
        "protocol": r"enip|ethernet.ip|cip",
        "payload": r"forward.open|forward_open|0x54|output.object|assembly.object",
        "src_ip_exclude": AUTHORIZED_ENGINEERING_IPS,
    },
    {
        "stage": "CommandInjection",
        "technique": "T0855",
        "name": "S7comm-WriteVariable-PDU",
        "severity": "high",
        "protocol": r"s7comm|s7\b",
        "payload": r"write.var|pdu.type[:\s=]?5|write.variable|0x0500|cpu.stop|0x0029",
        "src_ip_exclude": AUTHORIZED_ENGINEERING_IPS,
    },
    {
        "stage": "CommandInjection",
        "technique": "T0836",
        "name": "Schneider-Modbus-FC23-ReadWriteMultiple",
        "severity": "high",
        "protocol": r"modbus",
        "payload": r"\bfc[:\s=]?23\b|function.code[:\s=]?23|read.write.multiple",
        "src_ip_exclude": AUTHORIZED_ENGINEERING_IPS,
    },
    {
        "stage": "Persistence",
        "technique": "T0839",
        "name": "RepeatedAuthFailure-S7-CIP",
        "severity": "high",
        "protocol": r"s7comm|s7\b|cip|enip",
        "payload": r"auth.fail|login.fail|access.denied|wrong.password|0x08d0|error.code[:\s=]?8",
    },
    {
        "stage": "Persistence",
        "technique": "T0885",
        "name": "HistorianHost-Outbound-DNS-NonApproved",
        "severity": "medium",
        "protocol": r"dns",
        "port": r"53\b",
        "payload": r"query|request|resolve",
        "dst_ip_allow": APPROVED_RESOLVERS,
    },
    {
        "stage": "Persistence",
        "technique": "T0891",
        "name": "CISA-Flagged-Iranian-IP-Session",
        "severity": "high",
        "src_ip_set": CISA_IRANIAN_IPS,
    },
]

LOG_PATTERNS = [
    re.compile(
        r'(?P<ts>[\d\-T:\.Z ]+?)[,\t].*?(?P<src>[\d\.]+)[,\t](?P<dst>[\d\.]+)[,\t](?P<port>\d+)[,\t](?P<proto>\w[\w\.\-]*)[,\t](?P<payload>.+)',
        re.IGNORECASE,
    ),
    re.compile(
        r'(?P<ts>[\d\-T:\.Z ]+?)\s+(?P<src>[\d\.]+)\s*->\s*(?P<dst>[\d\.]+):(?P<port>\d+)\s+(?P<proto>\w[\w\.\-]*)\s+(?P<payload>.+)',
        re.IGNORECASE,
    ),
    re.compile(
        r'(?P<ts>[\w\s:]+?)\s+\S+\s+\S+:\s+src=(?P<src>[\d\.]+).*?dst=(?P<dst>[\d\.]+).*?dport=(?P<port>\d+).*?proto=(?P<proto>\w+)\s+(?P<payload>.+)',
        re.IGNORECASE,
    ),
]


def parse_line(line):
    line = line.strip()
    if not line or line.startswith('#') or re.match(r'^[Tt]imestamp|^[Dd]ate|^[Ss]ource', line):
        return None
    for pat in LOG_PATTERNS:
        m = pat.match(line)
        if m:
            payload = m.group('payload')
            payload = re.sub(r'\\x([0-9a-fA-F]{2})', lambda h: chr(int(h.group(1), 16)), payload)
            return {
                "ts": m.group('ts').strip(),
                "src": m.group('src'),
                "dst": m.group('dst'),
                "port": m.group('port'),
                "proto": m.group('proto').lower(),
                "payload": payload,
                "raw": line,
            }
    return None


def match_rules(entry, rules, dedup_window):
    hits = []
    key_ts = entry["ts"]
    try:
        parsed_ts = datetime.fromisoformat(key_ts.replace('Z', '+00:00'))
    except Exception:
        parsed_ts = None
    for rule in rules:
        if "src_ip_set" in rule:
            if entry["src"] not in rule["src_ip_set"]:
                continue
        else:
            proto_pat = rule.get("protocol")
            port_pat = rule.get("port")
            payload_pat = rule.get("payload")
            if proto_pat and not re.search(proto_pat, entry["proto"], re.IGNORECASE):
                if not re.search(proto_pat, entry["payload"], re.IGNORECASE):
                    continue
            if port_pat and not re.search(port_pat, entry["port"]):
                continue
            if payload_pat and not re.search(payload_pat, entry["payload"], re.IGNORECASE):
                continue

        src_exclude = rule.get("src_ip_exclude")
        if src_exclude and entry["src"] in src_exclude:
            continue

        dst_allow = rule.get("dst_ip_allow")
        if dst_allow and entry["dst"] in dst_allow:
            continue

        dedup_key = (entry["src"], rule["name"])
        last_seen = dedup_window.get(dedup_key)
        if last_seen and parsed_ts:
            try:
                if (parsed_ts - last_seen).total_seconds() < 60:
                    continue
            except Exception:
                pass
        if parsed_ts:
            dedup_window[dedup_key] = parsed_ts
        hits.append(rule)
    return hits


def load_iocs(path, rules):
    with open(path) as f:
        data = json.load(f)
    for ip in data.get("attacker_ips", []):
        CISA_IRANIAN_IPS.add(ip)
    for ip in data.get("authorized_engineering_ips", []):
        AUTHORIZED_ENGINEERING_IPS.add(ip)
    for ip in data.get("approved_resolvers", []):
        APPROVED_RESOLVERS.add(ip)
    for seq in data.get("malicious_fc_sequences", []):
        rules.append({
            "stage": "CommandInjection",
            "technique": "T0836",
            "name": f"CustomIOC-FC-{seq}",
            "severity": "high",
            "protocol": r"modbus",
            "payload": rf"\bfc[:\s=]?{re.escape(str(seq))}\b",
            "src_ip_exclude": AUTHORIZED_ENGINEERING_IPS,
        })
    for ind in data.get("exploit_payload_indicators", []):
        if not isinstance(ind, str):
            continue
        rules.append({
            "stage": "CommandInjection",
            "technique": "T0855",
            "name": f"CustomIOC-Payload-{ind[:20]}",
            "severity": "high",
            "payload": re.escape(ind),
            "src_ip_exclude": AUTHORIZED_ENGINEERING_IPS,
        })


def main():
    parser = argparse.ArgumentParser(
        description="Iranian ICS TTP Detector for Siemens, Schneider, and Rockwell PLCs"
    )
    parser.add_argument("log_file", help="Path to OT network log export")
    parser.add_argument("--iocs", help="Path to supplemental CISA ICS-CERT IOC JSON file")
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum alert severity to emit (default: low)",
    )
    args = parser.parse_args()

    rules = list(RULES)
    if args.iocs:
        try:
            load_iocs(args.iocs, rules)
        except Exception as e:
            print(f"[WARN] Failed to load IOC file: {e}", file=sys.stderr)

    min_sev = SEVERITY_ORDER[args.severity]
    stage_counts = defaultdict(int)
    technique_hits = set()
    attacker_ips = set()
    peak_severity = "low"
    dedup_window = {}

    try:
        fh = open(args.log_file, errors="replace")
    except OSError as e:
        print(f"[ERROR] Cannot open log file: {e}", file=sys.stderr)
        sys.exit(2)

    with fh:
        for line in fh:
            entry = parse_line(line)
            if not entry:
                continue
            for rule in match_rules(entry, rules, dedup_window):
                sev = rule["severity"]
                if SEVERITY_ORDER[sev] < min_sev:
                    continue
                stage_counts[rule["stage"]] += 1
                technique_hits.add(rule["technique"])
                attacker_ips.add(entry["src"])
                if SEVERITY_ORDER[sev] > SEVERITY_ORDER[peak_severity]:
                    peak_severity = sev
                print(
                    f"[{entry['ts']}] ALERT stage={rule['stage']} technique={rule['technique']} "
                    f"severity={sev.upper()} rule={rule['name']} src={entry['src']} "
                    f"| {entry['raw']}"
                )

    print("\n--- Summary ---")
    for stage, count in sorted(stage_counts.items()):
        print(f"  {stage}: {count} hit(s)")
    print(f"  ATT&CK for ICS techniques: {', '.join(sorted(technique_hits)) or 'none'}")
    print(f"  Unique attacker IPs: {len(attacker_ips)}")
    print(f"  Peak severity: {peak_severity.upper()}")

    if peak_severity == "high":
        sys.exit(1)


if __name__ == "__main__":
    main()