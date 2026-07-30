"""
AWS AI-Assisted Attack Chain Lab

Simulates credential theft, IAM pivoting, and S3 exfiltration, generating
synthetic CloudTrail-style log events and mapping attacker actions to
GuardDuty findings and CloudTrail detection signals.

Usage:
    python aws_ai_attack_chain_lab.py
    python aws_ai_attack_chain_lab.py --stage credential-theft
    python aws_ai_attack_chain_lab.py --mode simulate
    python aws_ai_attack_chain_lab.py --mode detect --log cloudtrail.log
"""

import argparse
import json
import re
import sys
import time

STAGES = ["credential-theft", "iam-pivot", "s3-exfil"]
GD = {
    "credential-theft": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
    "iam-pivot": "PrivilegeEscalation:IAMUser/AdministrativePermissions",
    "s3-exfil": "Exfiltration:S3/ObjectRead",
}
RFC1918 = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)")
AI_UA = re.compile(r"(python|boto|langchain|ai.agent|openai|anthropic)", re.I)
X_ACCT = re.compile(r"arn:aws:iam::(\d+):role/")
SENS_BKT = re.compile(r"(backup|secret|data|prod)", re.I)
EXT = lambda ip: not RFC1918.match(ip)  # noqa: E731


def generate_chain(stages):
    ts = int(time.time())
    base = {"sourceIPAddress": "203.0.113.42", "userAgent": "python-boto3/1.26 AI-agent/0.9"}
    chain = []
    if "credential-theft" in stages:
        for name in ("GetCallerIdentity", "DescribeInstances"):
            chain.append({**base, "eventTime": ts, "eventName": name,
                "userIdentity": {"arn": "arn:aws:sts::123456789012:assumed-role/EC2Role/i-abc"}})
            ts += 1
    if "iam-pivot" in stages:
        for role in ("arn:aws:iam::999999999999:role/AdminRole", "arn:aws:iam::888888888888:role/S3Role"):
            chain.append({**base, "eventTime": ts, "eventName": "AssumeRole",
                "userIdentity": {"arn": "arn:aws:sts::123456789012:assumed-role/EC2Role/i-abc"},
                "requestParameters": {"roleArn": role}})
            ts += 2
    if "s3-exfil" in stages:
        chain.append({**base, "eventTime": ts, "eventName": "ListBuckets",
            "userIdentity": {"arn": "arn:aws:sts::888888888888:assumed-role/S3Role/sess"}})
        ts += 1
        for _ in range(3):
            chain.append({**base, "eventTime": ts, "eventName": "GetObject",
                "userIdentity": {"arn": "arn:aws:sts::888888888888:assumed-role/S3Role/sess"},
                "requestParameters": {"bucketName": "prod-backup-secret-data"}})
            ts += 1
    return chain


def detect_stages(events, requested):
    findings, seen, prev_ts = [], {}, {}
    for ev in events:
        name = ev.get("eventName", "")
        ip = ev.get("sourceIPAddress", "")
        ua = ev.get("userAgent", "")
        stage = sev = expl = None

        if name in ("GetCallerIdentity", "DescribeInstances") and AI_UA.search(ua) and EXT(ip):
            stage, sev = "credential-theft", "HIGH"
            expl = f"EC2 credential used from external IP {ip} with AI-agent UA"

        elif name == "AssumeRole":
            rp = ev.get("requestParameters") or {}
            caller = (ev.get("userIdentity") or {}).get("arn", "")
            ca = re.search(r"::(\d+):", caller)
            ta = X_ACCT.search(rp.get("roleArn", ""))
            cross = ca and ta and ca.group(1) != ta.group(1)
            last = prev_ts.get("AssumeRole")
            rapid = last and (ev["eventTime"] - last) < 5
            prev_ts["AssumeRole"] = ev["eventTime"]
            if (cross or rapid) and EXT(ip):
                stage, sev = "iam-pivot", "HIGH"
                expl = "Rapid cross-account AssumeRole chain from external IP"

        elif name == "ListBuckets" and EXT(ip):
            stage, sev = "s3-exfil", "MEDIUM"
            expl = "ListBuckets enumeration from external IP precedes exfiltration"

        elif name == "GetObject":
            bkt = (ev.get("requestParameters") or {}).get("bucketName", "")
            if SENS_BKT.search(bkt) and EXT(ip):
                stage, sev = "s3-exfil", "HIGH"
                expl = f"GetObject on sensitive bucket '{bkt}' from external IP"

        if stage and stage in requested:
            key = (stage, ip)
            seen[key] = seen.get(key, 0) + 1
            if seen[key] <= 2:
                findings.append({"stage": stage, "eventName": name, "gd": GD[stage],
                    "severity": sev, "ip": ip, "ua": ua[:55], "explanation": expl})
    return findings


def report(findings, requested):
    for f in findings:
        print(f"[{f['stage'].upper()}] {f['eventName']}")
        print(f"  Source IP : {f['ip']}")
        print(f"  User-Agent: {f['ua']}")
        print(f"  GuardDuty : {f['gd']}")
        print(f"  Severity  : {f['severity']}")
        print(f"  Signal    : {f['explanation']}")
        print()
    hits = {s: [f for f in findings if f["stage"] == s] for s in requested}
    w = [22, 54, 28, 10]
    sep = "-" * sum(w)
    print(sep)
    print(f"{'Stage':<{w[0]}} {'GuardDuty Finding':<{w[1]}} {'CloudTrail APIs':<{w[2]}} {'Verdict'}")
    print(sep)
    all_det = True
    for s in requested:
        h = hits[s]
        gd = GD[s] if h else "\u2014"
        apis = ", ".join(dict.fromkeys(x["eventName"] for x in h)) or "\u2014"
        v = "DETECTED" if h else "MISSED"
        if not h:
            all_det = False
        print(f"{s:<{w[0]}} {gd:<{w[1]}} {apis:<{w[2]}} {v}")
    print(sep)
    return all_det


def main():
    p = argparse.ArgumentParser(description="AWS AI-Assisted Attack Chain Lab")
    p.add_argument("--log", help="CloudTrail log file path (one JSON per line)")
    p.add_argument("--stage", choices=STAGES, help="Restrict to single attack phase")
    p.add_argument("--mode", choices=["simulate", "detect", "both"], default="both")
    args = p.parse_args()

    if args.mode == "detect" and not args.log:
        p.error("--mode detect requires --log")

    requested = [args.stage] if args.stage else STAGES

    if args.log:
        try:
            with open(args.log) as fh:
                events = [json.loads(ln) for ln in fh if ln.strip()]
        except (OSError, json.JSONDecodeError) as exc:
            sys.exit(f"Error reading log: {exc}")
    else:
        events = generate_chain(requested)

    if args.mode == "simulate":
        for ev in events:
            print(json.dumps({k: v for k, v in ev.items() if not k.startswith("_")}))
        return

    findings = detect_stages(events, requested)
    if report(findings, requested):
        sys.exit(1)


if __name__ == "__main__":
    main()