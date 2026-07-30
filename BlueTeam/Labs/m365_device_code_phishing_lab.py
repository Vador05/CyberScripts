"""DEBULL M365 Device-Code Phishing Detection Lab.

Parses M365 Unified Audit Log exports for OAuth device-code phishing indicators
across three kill-chain stages a defender must interrupt before token issuance.

Usage:
    python m365_device_code_phishing_lab.py audit.log
    python m365_device_code_phishing_lab.py audit.log --patterns iocs.json --severity medium
"""
import argparse, json, re, sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

ABUSED_IDS = {
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264", "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "d3590ed6-52b3-4102-aeff-aad2292ab01c", "29d9ed98-a469-4536-ade2-f981bc1d605e",
    "872cd9fa-d31f-45e0-9eab-6e460a02d1f1", "ab9b8c07-8f02-4f72-87fa-80105867a763",
}
HEADLESS  = re.compile(r"python-requests|curl/|wget/|go-http|headless|phantomjs|selenium|puppeteer|playwright|httpx|aiohttp", re.I)
CLOUD_ASN = re.compile(r"amazonaws|azure|googlecloud|digitalocean|linode|vultr|hetzner|ovh|rackspace", re.I)
BAD_APP   = re.compile(r"device.?login.?helper|token.?fetcher|oauth.?proxy|auth.?relay|deviceauth|phishauth", re.I)
FIELD_RE  = re.compile(r'"(\w+)"\s*:\s*"([^"]*)"')
OP_DCR    = re.compile(r"devicecode(?:request|initiat|creat)", re.I)
OP_ACT    = re.compile(r"devicecode(?:activat|usersign|authent)", re.I)
OP_TKN    = re.compile(r"devicecode(?:token|poll|success|complet)", re.I)
OP_DONE   = re.compile(r"devicecode(?:success|complet)", re.I)
SEV       = {"low": 0, "medium": 1, "high": 2}
HOURS_OK  = range(8, 18)


def _g(d, *keys): return str(next((d[k] for k in keys if k in d and d[k] is not None), ""))


def parse_log_entries(path):
    entries = []
    try: lines = Path(path).read_text(errors="replace").splitlines()
    except OSError as e: sys.exit(f"ERROR: {e}")
    for raw_line in lines:
        line = raw_line.strip()
        if not line: continue
        try: raw = json.loads(line)
        except json.JSONDecodeError:
            pairs = dict(FIELD_RE.findall(line))
            raw = pairs if pairs else {}
        if not raw: continue
        entries.append({
            "ts":  _g(raw, "CreationTime", "Timestamp", "time"),
            "upn": _g(raw, "UserId", "UserPrincipalName", "user"),
            "op":  _g(raw, "Operation", "operation"),
            "cid": _g(raw, "ClientId", "AppId", "client_id"),
            "app": _g(raw, "AppDisplayName", "ApplicationDisplayName", "app_name"),
            "ip":  _g(raw, "ClientIP", "IPAddress", "ip"),
            "ua":  _g(raw, "UserAgent", "user_agent"),
        })
    return entries


def parse_ts(s):
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try: return datetime.strptime(s[:19], fmt)
        except Exception: pass
    return None


def match_rules(entries, extra):
    abused      = ABUSED_IDS | set(extra.get("client_ids", []))
    bad_names   = [n.lower() for n in extra.get("app_names", [])]
    poll_thresh = float(extra.get("poll_threshold_seconds", 5))
    findings, act_times, poll_times = [], defaultdict(list), defaultdict(list)
    baseline, prior_ips, multi_warned = set(), defaultdict(set), set()
    req_ips, completion_times, activated_cids = defaultdict(list), {}, set()

    def emit(stage, sev, rule, upn, indicator, fix, ts):
        findings.append((stage, sev, rule, upn, indicator[:120], fix, ts))

    for e in entries:
        op, cid, upn = e["op"], e["cid"].lower(), e["upn"]
        ua, ip, app  = e["ua"], e["ip"], e["app"]
        ts = parse_ts(e["ts"])

        if OP_DCR.search(op):
            if cid in abused:
                emit("DeviceCodeRequest", "high",   "abused_client_id",        upn, f"client_id={cid}",   "Block client_id in Conditional Access; revoke existing tokens", ts)
            if HEADLESS.search(ua):
                emit("DeviceCodeRequest", "medium", "headless_ua_device_code", upn, f"ua={ua}",            "Restrict non-interactive device-code flow in Conditional Access policy", ts)
            if CLOUD_ASN.search(ip):
                emit("DeviceCodeRequest", "medium", "cloud_asn_device_code",   upn, f"src_ip={ip}",        "Enable sign-in risk policy; require MFA step-up for device-code flow", ts)
            if BAD_APP.search(app) or any(n in app.lower() for n in bad_names):
                emit("DeviceCodeRequest", "high",   "malicious_app_name",      upn, f"app_name={app}",     "Remove app registration; revoke all tokens issued to this app", ts)
            req_ips[(upn, cid)].append(ip)

        elif OP_ACT.search(op):
            req_ip_list = req_ips.get((upn, cid), [])
            if req_ip_list:
                req_ip = req_ip_list[-1]
                if bool(CLOUD_ASN.search(ip)) != bool(CLOUD_ASN.search(req_ip)):
                    emit("UserActivation", "high", "ip_asn_mismatch_activation", upn, f"req_ip={req_ip} activation_ip={ip}", "Suspend account; require re-auth from known-good network location", ts)
            if ts and ts.hour not in HOURS_OK and cid not in activated_cids:
                emit("UserActivation", "high", "first_seen_client_activation",  upn, f"client_id={cid} hour={ts.hour:02d}:00", "Require admin consent workflow; disable self-service consent grant", ts)
            activated_cids.add(cid)
            if ts:
                act_times[upn].append(ts)
                if upn not in multi_warned:
                    window = [t for t in act_times[upn] if t != ts and abs((ts - t).total_seconds()) <= 600]
                    if window:
                        multi_warned.add(upn)
                        emit("UserActivation", "high", "multi_code_activation", upn, f"{len(window)+1} activations in 10min", "Revoke all session tokens; escalate to IR for account-takeover review", ts)
            prior_ips[upn].add(ip)

        elif OP_TKN.search(op):
            if ts:
                poll_times[cid].append(ts)
                pts = sorted(poll_times[cid])
                if len(pts) > 1:
                    gap = (pts[-1] - pts[-2]).total_seconds()
                    if 0 < gap < poll_thresh:
                        emit("TokenHarvest", "high", "rapid_token_polling",        upn, f"poll_interval={gap:.1f}s client_id={cid}", "Block client_id; rotate affected user credentials immediately", ts)
            if cid not in baseline:
                emit("TokenHarvest", "high", "baseline_absent_client_id",          upn, f"client_id={cid} absent from interactive baseline", "Revoke token; add client_id to Conditional Access block policy", ts)
            if OP_DONE.search(op) and ts:
                completion_times[(upn, cid)] = ts
        else:
            if ip and CLOUD_ASN.search(ip) and ip not in prior_ips.get(upn, set()):
                if (upn, cid) in completion_times and ts:
                    elapsed = (ts - completion_times[(upn, cid)]).total_seconds()
                    if 0 < elapsed <= 900:
                        emit("TokenHarvest", "high", "post_issuance_asn_jump", upn, f"post-issuance_ip={ip}", "Revoke refresh token; open IR incident for lateral-movement review", ts)
            if cid: baseline.add(cid)

    return findings


def report_findings(findings, min_sev):
    seen, out = {}, []
    for stage, sev, rule, upn, indicator, fix, ts in findings:
        if SEV.get(sev, 0) < SEV[min_sev]: continue
        key  = (rule, upn, indicator[:30])
        prev = seen.get(key)
        if prev is not None and ts is not None and (ts - prev).total_seconds() < 300: continue
        seen[key] = ts
        out.append((stage, sev))
        print(f"[{sev.upper():6}] [{stage}] {rule} | user={upn} | {indicator}")
        print(f"         MITIGATION: {fix}")
    counts, peak, harvest_hit = defaultdict(int), 0, False
    for stage, sev in out:
        counts[stage] += 1
        peak = max(peak, SEV.get(sev, 0))
        if stage == "TokenHarvest": harvest_hit = True
    print("\n--- Detection Summary ---")
    for s in ("DeviceCodeRequest", "UserActivation", "TokenHarvest"):
        print(f"  {s}: {counts[s]} hit(s)")
    print(f"  Peak Severity: {['LOW', 'MEDIUM', 'HIGH'][peak]}")
    if harvest_hit: print("  ACTION REQUIRED: TokenHarvest hits present — initiate token revocation immediately.")
    return peak == 2


def main():
    ap = argparse.ArgumentParser(description="DEBULL M365 Device-Code Phishing Detection Lab")
    ap.add_argument("log_file", help="Path to M365 Unified Audit Log export (JSON-per-line or field-delimited)")
    ap.add_argument("--patterns", help="JSON file with supplemental client_ids, app_names, poll_threshold_seconds")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low", help="Minimum alert severity (default: low)")
    args = ap.parse_args()
    extra = {}
    if args.patterns:
        try: extra = json.loads(Path(args.patterns).read_text())
        except Exception as e: sys.exit(f"ERROR loading patterns: {e}")
    findings = match_rules(parse_log_entries(args.log_file), extra)
    sys.exit(1 if report_findings(findings, args.severity) else 0)


if __name__ == "__main__":
    main()