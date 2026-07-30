"""Entra ID MFA/Passkey Enrollment Vishing Detector (O-UNC-066).

Parses Entra ID / Microsoft Sentinel audit log exports to flag anomalous
passkey or MFA enrollment events preceded by atypical sign-in geography,
new ASN, or off-hours timing, matching the O-UNC-066 vishing pattern.

Usage:
    python entra_mfa_vishing_detector.py [log_file] [--window 60] [--severity low]
    python entra_mfa_vishing_detector.py sentinel_export.log --window 90 --severity high
"""
import argparse, json, sys
from datetime import datetime, timezone, timedelta

SEV_RANK = {"low": 0, "medium": 1, "high": 2}
ENROLL_OPS = {"registersecurityinfo", "add method to user"}
BUSINESS_HOURS = range(7, 20)

def _t(s):
    try: return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception: return None

def _g(d, *keys, default=""):
    for k in keys:
        v = d.get(k)
        if v is not None: return str(v)
    return default

def synthetic_log():
    now = datetime(2026, 7, 11, 4, 0, 0, tzinfo=timezone.utc)
    lines = []
    for i in range(30):
        dt = (now - timedelta(days=30 - i)).isoformat().replace("+00:00", "Z")
        lines.append(json.dumps({"operationName": "Sign-in", "userPrincipalName": "clean@contoso.com",
            "createdDateTime": dt, "ipAddress": "1.2.3.4", "location": {"countryOrRegion": "US"},
            "autonomousSystemNumber": "AS7922", "isInteractive": True, "clientAppUsed": "Browser"}))
        lines.append(json.dumps({"operationName": "Sign-in", "userPrincipalName": "victim@contoso.com",
            "createdDateTime": dt, "ipAddress": "5.6.7.8", "location": {"countryOrRegion": "US"},
            "autonomousSystemNumber": "AS7922", "isInteractive": True, "clientAppUsed": "Browser"}))
    vish_signin = (now - timedelta(hours=1, minutes=22)).isoformat().replace("+00:00", "Z")
    vish_enroll = (now - timedelta(hours=0, minutes=44)).isoformat().replace("+00:00", "Z")
    lines.append(json.dumps({"operationName": "Sign-in", "userPrincipalName": "victim@contoso.com",
        "createdDateTime": vish_signin, "ipAddress": "91.200.12.5", "location": {"countryOrRegion": "RU"},
        "autonomousSystemNumber": "AS48721", "isInteractive": True, "clientAppUsed": "Browser"}))
    lines.append(json.dumps({"operationName": "RegisterSecurityInfo", "userPrincipalName": "victim@contoso.com",
        "activityDateTime": vish_enroll, "targetResources": [{"authenticationMethodType": "Fido2Key"}]}))
    return lines

def parse_log(path):
    lines = synthetic_log() if path is None else None
    if lines is None:
        with open(path, errors="replace") as f:
            lines = f.readlines()
    signins, enrollments = [], []
    for raw in lines:
        raw = raw.strip()
        if not raw: continue
        try: ev = json.loads(raw)
        except json.JSONDecodeError: continue
        op = _g(ev, "operationName", "OperationName").lower()
        upn = _g(ev, "userPrincipalName", "UserId")
        if not upn: continue
        if "sign" in op or op == "sign-in":
            loc = ev.get("location") or {}
            signins.append({"upn": upn, "ts": _t(_g(ev, "createdDateTime", "CreationTime")),
                "ip": _g(ev, "ipAddress", "ClientIP"), "country": _g(loc, "countryOrRegion"),
                "asn": _g(ev, "autonomousSystemNumber"), "interactive": ev.get("isInteractive", True)})
        elif any(x in op for x in ENROLL_OPS):
            tr = ev.get("targetResources") or [{}]
            mtype = _g(tr[0] if tr else {}, "authenticationMethodType", "displayName", default="unknown")
            enrollments.append({"upn": upn, "ts": _t(_g(ev, "activityDateTime", "createdDateTime")),
                "op": op, "method": mtype})
    return signins, enrollments

def detect_vishing(signins, enrollments, window_min, min_sev):
    earliest_enroll = {}
    for e in enrollments:
        u = e["upn"]
        ets = e["ts"]
        if u not in earliest_enroll or (ets and (earliest_enroll[u] is None or ets < earliest_enroll[u])):
            earliest_enroll[u] = ets
    baseline = {}
    for s in signins:
        u = s["upn"]
        sts = s["ts"]
        if u not in baseline: baseline[u] = {"countries": set(), "asns": set()}
        if u not in earliest_enroll or (sts and earliest_enroll[u] and sts < earliest_enroll[u]):
            baseline[u]["countries"].add(s["country"])
            baseline[u]["asns"].add(s["asn"])
    findings = []
    seen = {}
    for e in sorted(enrollments, key=lambda x: x["ts"] or datetime.min.replace(tzinfo=timezone.utc)):
        if not e["ts"]: continue
        upn, ets = e["upn"], e["ts"]
        dedup_key = (upn, e["method"], ets.strftime("%Y%m%d%H")[:-1])
        if dedup_key in seen: continue
        seen[dedup_key] = True
        wstart = ets - timedelta(minutes=window_min)
        prior = sorted([s for s in signins if s["upn"] == upn and s["ts"] and wstart <= s["ts"] <= ets], key=lambda x: x["ts"], reverse=True)
        ub = baseline.get(upn, {"countries": set(), "asns": set()})
        user_enrollments = {x["upn"]: x for x in enrollments if x["upn"] == upn}
        prior_enrolls = [x for x in enrollments if x["upn"] == upn and x["ts"] and x["ts"] < ets]
        reasons, corr = [], None
        for s in (prior[:1] if prior else []):
            if s["country"] and s["country"] not in ub["countries"]: reasons.append("new_country")
            if s["asn"] and s["asn"] not in ub["asns"]: reasons.append("new_asn")
            gap = (ets - s["ts"]).total_seconds() / 60
            if gap < 10: reasons.append("vishing_gap")
            corr = s
        if ets.hour not in BUSINESS_HOURS: reasons.append("off_hours")
        if not prior_enrolls: reasons.append("first_enrollment")
        reasons = list(dict.fromkeys(reasons))
        has_geo = "new_country" in reasons or "new_asn" in reasons
        if "new_country" in reasons and "new_asn" in reasons: sev = "high"
        elif "new_country" in reasons or ("first_enrollment" in reasons and "off_hours" in reasons): sev = "medium"
        elif ("off_hours" in reasons or "vishing_gap" in reasons) and not has_geo: sev = "low"
        else: continue
        if SEV_RANK[sev] < SEV_RANK[min_sev]: continue
        findings.append({"sev": sev, "upn": upn, "method": e["method"], "ts": ets,
            "reasons": reasons, "corr": corr, "wstart": wstart})
    return findings

def report(findings, signins, enrollments, window_min):
    kql = '''-- Q1: RegisterSecurityInfo from new country
AuditLogs | where OperationName == "Register Security Info"
| join kind=inner (SigninLogs | summarize Countries=make_set(Location) by UserPrincipalName) on UserPrincipalName
| where not(Location has_any (Countries))
-- Q2: First-ever MFA method added (AuthenticationMethods count was zero)
AuditLogs | where OperationName has "Add method to user"
| where TimeGenerated > ago(7d)
| join kind=leftanti (AuditLogs | where OperationName has "Add method to user" | where TimeGenerated > ago(30d) | summarize by UserPrincipalName, TargetResources) on UserPrincipalName
-- Q3: Fido2Key enrollment from new ASN
AuditLogs | where OperationName == "Register Security Info" and TargetResources has "Fido2Key"
| join kind=inner (SigninLogs | summarize KnownASNs=make_set(AutonomousSystemNumber) by UserPrincipalName) on UserPrincipalName
| extend ASN = tostring(parse_json(AdditionalDetails).autonomousSystemNumber)
| where not(ASN has_any (KnownASNs))'''
    high = sum(1 for f in findings if f["sev"] == "high")
    methods = {}
    for f in findings: methods[f["method"]] = methods.get(f["method"], 0) + 1
    affected = len({f["upn"] for f in findings})
    if not findings: print("[*] No vishing indicators detected.")
    for f in findings:
        corr_ts = f["corr"]["ts"].isoformat() if f["corr"] and f["corr"]["ts"] else "N/A"
        corr_ip = f["corr"]["ip"] if f["corr"] else "N/A"
        print(f"[{f['sev'].upper()}] {f['upn']} | {f['method']} | reasons={','.join(f['reasons'])} | "
              f"enroll={f['ts'].isoformat()} | signin={corr_ts} ip={corr_ip} | "
              f"window={f['wstart'].isoformat()}/{f['ts'].isoformat()} | "
              f"action=Revoke session + disable new authenticator + notify user")
    print(f"\n--- Summary ---\nScanned: {len(enrollments)} enrollment(s) | Suspicious: {len(findings)} "
          f"(high={high}, medium={sum(1 for f in findings if f['sev']=='medium')}, "
          f"low={sum(1 for f in findings if f['sev']=='low')}) | Affected users: {affected}")
    for m, c in sorted(methods.items()): print(f"  {m}: {c}")
    print(f"\n--- Sentinel KQL ---\n{kql}")
    if high: sys.exit(1)

def main():
    ap = argparse.ArgumentParser(description="Entra ID MFA/Passkey Enrollment Vishing Detector (O-UNC-066)")
    ap.add_argument("log_file", nargs="?", default=None)
    ap.add_argument("--window", type=int, default=60, metavar="5-1440")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low")
    args = ap.parse_args()
    if not (5 <= args.window <= 1440):
        sys.exit("ERROR: --window must be between 5 and 1440")
    if args.log_file is None: print("[*] No log file — using built-in synthetic demo log.\n")
    try: signins, enrollments = parse_log(args.log_file)
    except OSError as e: sys.exit(f"ERROR: {e}")
    findings = detect_vishing(signins, enrollments, args.window, args.severity)
    report(findings, signins, enrollments, args.window)

if __name__ == "__main__": main()