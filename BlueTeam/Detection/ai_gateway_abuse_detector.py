"""
AI Gateway CloudTrail Abuse & Cryptomining Egress Detector

Scans plain-text CloudTrail or LLM gateway log exports for AI-gateway abuse
patterns across three kill-chain stages.

Usage:
    python ai_gateway_abuse_detector.py cloudtrail.json
    python ai_gateway_abuse_detector.py gateway.log --iocs extra_iocs.json --severity high
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

APPROVED_MODELS = {"anthropic.claude-3-sonnet", "anthropic.claude-3-haiku", "amazon.titan-text-express-v1"}
HIGH_RISK_IAM = {"CreateAccessKey", "AttachUserPolicy", "PassRole", "PutUserPolicy", "AddUserToGroup"}
ENUM_IAM = {"ListRoles", "ListUsers", "GetAccountAuthorizationDetails", "ListAttachedRolePolicies"}
MINING_DOMAINS = {"pool.supportxmr.com", "xmrpool.eu", "moneroocean.stream", "nanopool.org", "f2pool.com", "nicehash.com", "2miners.com", "miningpoolhub.com"}
STRATUM_PORTS = {3333, 4444, 5555, 7777, 8888, 14444, 45560, 9999}
GPU_TYPES = {"p4d", "p3", "g5", "g4dn", "p2", "inf1", "inf2"}
AI_SERVICES = {"bedrock", "sagemaker"}
BUSINESS_HOURS = range(8, 18)

RULES = {
    "AnomalousInvocation": [
        ("UnauthorizedModelID", "high", lambda e: e.get("model_id") and e.get("model_id") not in APPROVED_MODELS),
        ("ExcessiveTokenConsumption", "medium", lambda e: (e.get("token_count") or 0) > 100000),
        ("OffHoursInference", "low", lambda e: e.get("service") in AI_SERVICES and e.get("hour") is not None and e["hour"] not in BUSINESS_HOURS),
        ("CrossAccountAssumeRole", "high", lambda e: e.get("event") == "AssumeRole" and e.get("service") in AI_SERVICES and e.get("cross_account") is True),
    ],
    "LateralIAM": [
        ("IAMPrivilegeEscalation", "high", lambda e: e.get("service") == "iam" and e.get("event") in HIGH_RISK_IAM),
        ("IAMEnumeration", "medium", lambda e: e.get("service") == "iam" and e.get("event") in ENUM_IAM),
        ("CrossServicePivot", "medium", lambda e: e.get("service") in {"s3", "ec2"} and any(ai in (e.get("principal") or "") for ai in {"bedrock", "sagemaker"})),
        ("DeepAssumeRoleChain", "high", lambda e: e.get("event") == "AssumeRole" and (e.get("hop_count") or 0) > 2),
    ],
    "CryptominingEgress": [
        ("MiningPoolDomain", "high", lambda e: any(d in (e.get("domain") or "") for d in MINING_DOMAINS)),
        ("StratumPort", "high", lambda e: (e.get("dest_port") or 0) in STRATUM_PORTS),
        ("GPUReservationAfterAbuse", "high", lambda e: e.get("event") in {"RunInstances", "CreateCapacityReservation"} and any(g in (e.get("instance_type") or "") for g in GPU_TYPES)),
        ("AIRoleInstanceEnum", "medium", lambda e: e.get("event") in {"DescribeInstances", "RunInstances"} and any(ai in (e.get("principal") or "") for ai in {"bedrock", "sagemaker"})),
    ],
}

TS_RE = re.compile(r'"eventTime"\s*:\s*"([^"]+)"')
PRIN_RE = re.compile(r'"arn"\s*:\s*"([^"]+)"')
SVC_RE = re.compile(r'"eventSource"\s*:\s*"([^.]+)')
EVT_RE = re.compile(r'"eventName"\s*:\s*"([^"]+)"')
MODEL_RE = re.compile(r'"modelId"\s*:\s*"([^"]+)"|model[_-]?id[=:]\s*([^\s,&]+)', re.I)
TOKEN_RE = re.compile(r'"totalTokens"\s*:\s*(\d+)|tokens[=:]\s*(\d+)', re.I)
DOMAIN_RE = re.compile(r'"destinationDomain"\s*:\s*"([^"]+)"|domain[=:]\s*([^\s,&]+)', re.I)
PORT_RE = re.compile(r'"destinationPort"\s*:\s*(\d+)|dport[=:]\s*(\d+)', re.I)
INST_RE = re.compile(r'"instanceType"\s*:\s*"([^"]+)"', re.I)
HOP_RE = re.compile(r'"assumedRoleChainDepth"\s*:\s*(\d+)', re.I)
ROLE_ARN_RE = re.compile(r'"roleArn"\s*:\s*"arn:[^:]*:[^:]*:[^:]*:(\d+):', re.I)

def parse_entry(line):
    e = {"raw": line.strip()}
    ts_m = TS_RE.search(line)
    if ts_m:
        try:
            dt = datetime.fromisoformat(ts_m.group(1).replace("Z", "+00:00"))
            e["timestamp"] = dt.isoformat()
            e["hour"] = dt.astimezone(timezone.utc).hour
        except ValueError:
            pass
    for pat, key in [(PRIN_RE, "principal"), (EVT_RE, "event"), (INST_RE, "instance_type")]:
        m = pat.search(line)
        if m:
            e[key] = m.group(1)
    svc_m = SVC_RE.search(line)
    if svc_m:
        e["service"] = svc_m.group(1).lower()
    mdl_m = MODEL_RE.search(line)
    if mdl_m:
        e["model_id"] = (mdl_m.group(1) or mdl_m.group(2) or "").strip()
    tok_m = TOKEN_RE.search(line)
    if tok_m:
        e["token_count"] = int(tok_m.group(1) or tok_m.group(2))
    dom_m = DOMAIN_RE.search(line)
    if dom_m:
        e["domain"] = (dom_m.group(1) or dom_m.group(2) or "").strip()
    prt_m = PORT_RE.search(line)
    if prt_m:
        e["dest_port"] = int(prt_m.group(1) or prt_m.group(2))
    hop_m = HOP_RE.search(line)
    if hop_m:
        e["hop_count"] = int(hop_m.group(1))
    role_m = ROLE_ARN_RE.search(line)
    if role_m:
        e["target_acct"] = role_m.group(1)
    principal = e.get("principal", "")
    if ":assumed-role/" in principal or ":role/" in principal:
        parts = principal.split(":")
        if len(parts) >= 6:
            source_acct = parts[4]
            target_acct = e.get("target_acct", "")
            e["cross_account"] = bool(source_acct and target_acct and source_acct != target_acct)
    return e

def load_iocs(path):
    try:
        with open(path) as f:
            data = json.load(f)
        if models := data.get("approved_models"):
            APPROVED_MODELS.update(m for m in models if isinstance(m, str))
        if actions := data.get("high_risk_iam"):
            HIGH_RISK_IAM.update(a for a in actions if isinstance(a, str))
        if domains := data.get("mining_domains"):
            MINING_DOMAINS.update(d for d in domains if isinstance(d, str))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[WARN] Could not load IOCs: {exc}", file=sys.stderr)

SEV_ORDER = {"low": 0, "medium": 1, "high": 2}

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log_file", help="Path to CloudTrail JSON export or LLM gateway log")
    ap.add_argument("--iocs", metavar="FILE", help="Supplemental IOC JSON file")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low", help="Minimum severity (default: low)")
    args = ap.parse_args()

    if args.iocs:
        load_iocs(args.iocs)

    min_sev = SEV_ORDER[args.severity]
    counts = defaultdict(int)
    principals = set()
    peak = "low"
    dedup = {}
    found_high = False

    try:
        with open(args.log_file, errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                entry = parse_entry(line)
                for stage, rule_list in RULES.items():
                    for rule_name, severity, check in rule_list:
                        if SEV_ORDER[severity] < min_sev:
                            continue
                        try:
                            hit = check(entry)
                        except (KeyError, TypeError, ValueError):
                            continue
                        if not hit:
                            continue
                        principal = entry.get("principal", "unknown")
                        ts = entry.get("timestamp", "unknown")
                        key = (principal, stage, rule_name)
                        if key in dedup:
                            prev_ts = dedup[key]
                            try:
                                delta = (datetime.fromisoformat(ts) - datetime.fromisoformat(prev_ts)).total_seconds()
                                if abs(delta) < 300:
                                    continue
                            except (ValueError, TypeError):
                                pass
                        dedup[key] = ts
                        counts[stage] += 1
                        principals.add(principal)
                        if SEV_ORDER[severity] > SEV_ORDER[peak]:
                            peak = severity
                        if severity == "high":
                            found_high = True
                        raw = entry["raw"][:200]
                        print(f"[{ts}] [{stage}] [{severity.upper()}] rule={rule_name} principal={principal} | {raw}")
    except OSError as exc:
        print(f"[ERROR] Cannot read log file: {exc}", file=sys.stderr)
        sys.exit(2)

    print("\n--- Summary ---")
    for stage in ("AnomalousInvocation", "LateralIAM", "CryptominingEgress"):
        print(f"  {stage}: {counts[stage]} hits")
    print(f"  Unique principals: {len(principals)}")
    print(f"  Peak severity: {peak.upper()}")

    sys.exit(1 if found_high else 0)

if __name__ == "__main__":
    main()