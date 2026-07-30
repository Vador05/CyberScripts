"""Forg365 AiTM + Device-Code Phishing Detection Lab.

Parses M365 Unified Audit Log exports for AiTM proxy phishing and OAuth
device-code phishing indicators, mapping each hit to its kill-chain stage.

Usage:
    python m365_aitm_device_code_lab.py [log_file] [--mode both] [--severity low]
    python m365_aitm_device_code_lab.py audit.log --mode aitm --severity high
"""
import argparse, json, re, sys
from datetime import datetime

FORG_CIDS = {"1fec8e78-bce4-4aaf-ab1b-5451cc387264","04b07795-8ddb-461a-bbee-02f9e1bf7b46",
             "d3590ed6-52b3-4102-aeff-aad2292ab01c","29d9ed98-a469-4536-ade2-f981bc1d605e",
             "872cd9fa-d31f-45e0-9eab-6e460a02d1f1","ab9b8c07-8f02-4f72-87fa-80105867a763"}
HOSTING  = re.compile(r"amazonaws|azureedge|googlecloud|digitalocean|linode|vultr|hetzner|ovh|rackspace",re.I)
HEADLESS = re.compile(r"python-requests|curl/|wget/|go-http|headless|phantomjs|selenium|puppeteer|playwright|httpx|aiohttp",re.I)
OP_SIGN  = re.compile(r"userloggedin|signin|authenticate",re.I)
OP_DCR   = re.compile(r"devicecode(?:request|initiat|creat)",re.I)
OP_ACT   = re.compile(r"devicecode(?:activat|usersign)",re.I)
OP_TKN   = re.compile(r"devicecode(?:success|complet|token|poll)",re.I)
SEV_RANK = {"low":0,"medium":1,"high":2}
SYNTH = [
    {"CreationTime":"2026-07-10T09:00:00Z","UserId":"alice@contoso.com","Operation":"UserLoggedIn","ClientIP":"185.220.101.5","SessionId":"sess-abc","AuthenticationMethod":"MFA","NetworkLocationDetails":"amazonaws","UserAgent":"Mozilla/5.0"},
    {"CreationTime":"2026-07-10T09:04:00Z","UserId":"alice@contoso.com","Operation":"UserLoggedIn","ClientIP":"198.51.100.77","SessionId":"sess-abc","AuthenticationMethod":"previouslySatisfied","NetworkLocationDetails":"","UserAgent":"Mozilla/5.0"},
    {"CreationTime":"2026-07-10T10:00:00Z","UserId":"bob@contoso.com","Operation":"DeviceCodeRequest","ClientId":"1fec8e78-bce4-4aaf-ab1b-5451cc387264","ClientIP":"203.0.113.10","UserAgent":"python-requests/2.28"},
    {"CreationTime":"2026-07-10T10:00:03Z","UserId":"bob@contoso.com","Operation":"DeviceCodeActivated","ClientId":"1fec8e78-bce4-4aaf-ab1b-5451cc387264","ClientIP":"185.220.101.5","UserAgent":"Mozilla/5.0"},
    {"CreationTime":"2026-07-10T10:00:04Z","UserId":"bob@contoso.com","Operation":"DeviceCodeSuccess","ClientId":"1fec8e78-bce4-4aaf-ab1b-5451cc387264","ClientIP":"203.0.113.10","UserAgent":"python-requests/2.28"},
    {"CreationTime":"2026-07-10T10:00:05Z","UserId":"bob@contoso.com","Operation":"DeviceCodePoll","ClientId":"1fec8e78-bce4-4aaf-ab1b-5451cc387264","ClientIP":"203.0.113.10","UserAgent":"python-requests/2.28"},
]

def _g(d,*k): return str(next((d[x] for x in k if x in d and d[x] is not None),""))
def _t(s):
    try: return datetime.fromisoformat(s.replace("Z","+00:00"))
    except Exception: return None
def _norm(r):
    return {"ts":_g(r,"CreationTime","Timestamp","time"),"upn":_g(r,"UserId","UserPrincipalName","user"),
            "op":_g(r,"Operation","operation"),"cid":_g(r,"ClientId","AppId","client_id"),
            "ip":_g(r,"ClientIP","IPAddress","ip"),"ua":_g(r,"UserAgent","user_agent"),
            "sid":_g(r,"SessionId","session_id"),"auth":_g(r,"AuthenticationMethod","auth_method"),
            "net":_g(r,"NetworkLocationDetails","network_location")}

def parse_log(path):
    if path is None:
        print("[*] No log file — using built-in synthetic Forg365 demo log.\n")
        return [_norm(e) for e in SYNTH]
    try:
        with open(path, errors="replace") as fh:
            lines = fh.readlines()
    except OSError as e:
        sys.exit(f"ERROR: {e}")
    out = []
    for l in lines:
        l = l.strip()
        if not l: continue
        try: out.append(_norm(json.loads(l)))
        except Exception: pass
    return out

def detect_chain(entries, mode):
    alerts, sess, dc_req, dc_poll = [], {}, {}, {}
    for e in entries:
        op,upn,ip,ua,sid = e["op"],e["upn"],e["ip"],e["ua"],e["sid"]
        cid,auth,net,ts   = e["cid"],e["auth"],e["net"],e["ts"]
        t = _t(ts)
        if mode in ("aitm","both") and OP_SIGN.search(op):
            if HOSTING.search(net) or HOSTING.search(ip):
                alerts.append(("AiTM","ProxySession","high","AiTM_ProxyHostingASN",upn,f"IP={ip} net={net[:50]}",t,"Block hosting-ASN sign-ins via Named Locations CA policy"))
            if sid and t:
                if sid in sess:
                    pip,pt = sess[sid]
                    if pip != ip and (t-pt).total_seconds() <= 1800:
                        alerts.append(("AiTM","CookieHarvest","high","AiTM_SessionCookieReuse",upn,f"sid={sid[:20]} prev={pip} now={ip}",t,"Revoke session via CAE; rotate credentials immediately"))
                sess[sid] = (ip,t)
            if auth == "previouslySatisfied":
                alerts.append(("AiTM","MFABypass","medium","AiTM_MFASatisfiedReused",upn,f"auth={auth} ip={ip}",t,"Enforce CAE sign-in frequency; require phish-resistant MFA (FIDO2/CBA)"))
        if mode in ("device-code","both"):
            if OP_DCR.search(op):
                ind = []
                if cid in FORG_CIDS: ind.append(f"client_id={cid}")
                if HEADLESS.search(ua): ind.append(f"ua={ua[:50]}")
                if ind:
                    alerts.append(("DeviceCode","CodeRequest","medium","DC_Forg365ClientOrHeadlessUA",upn,"; ".join(ind),t,"Block flagged client_ids via Azure AD Conditional Access policy"))
                if t: dc_req[upn] = (ip,t)
            elif OP_ACT.search(op) and upn in dc_req:
                rip,_ = dc_req[upn]
                if ip != rip:
                    alerts.append(("DeviceCode","TokenIssuance","high","DC_ActivationIPMismatch",upn,f"req_ip={rip} act_ip={ip}",t,"Require MFA step-up at activation; alert on request/activation IP delta"))
            elif OP_TKN.search(op) and t:
                if upn in dc_poll:
                    gap = (t-dc_poll[upn]).total_seconds()
                    if 0 < gap < 5:
                        alerts.append(("DeviceCode","TokenIssuance","high","DC_SubSecondPolling",upn,f"poll_interval={gap:.1f}s",t,"Revoke token; block client_id; alert on sub-5s polling"))
                dc_poll[upn] = t
    return alerts

def report(alerts, min_sev):
    min_rank = SEV_RANK[min_sev]
    seen, deduped = {}, []
    for a in alerts:
        k = (a[4], a[3])
        t = a[6]
        prev_t = seen.get(k)
        if k not in seen or prev_t is None or t is None or (t - prev_t).total_seconds() > 300:
            seen[k] = t if t is not None else prev_t
            deduped.append(a)
    high = False; printed = 0
    for path,stage,sev,rule,upn,ind,t,mit in deduped:
        if SEV_RANK[sev] >= min_rank:
            print(f"[{sev.upper():6}] [{path:10}] [{stage:16}] {rule}")
            print(f"         User: {upn} | {ind[:100]}")
            print(f"         Mitigate: {mit}\n")
            printed += 1
        if sev == "high": high = True
    sup = len(deduped) - printed
    if sup: print(f"[*] {sup} finding(s) suppressed by --severity {min_sev}\n")
    rules = list({a[3] for a in deduped})
    print("="*70)
    print("KILL-CHAIN DISRUPTION CHECKLIST")
    print("="*70)
    print("AiTM Path:")
    print("  1. [ProxySession]  Block hosting-ASN IPs via Named Locations CA policy BEFORE proxy relay completes")
    print("  2. [CookieHarvest] Enable CAE + Entra ID token protection to invalidate harvested session cookies")
    print("  3. [MFABypass]     Set sign-in frequency to 1hr; deploy token binding; require phish-resistant MFA")
    print("DeviceCode Path:")
    print("  4. [CodeRequest]   Disable device-code flow for non-compliant apps; blocklist Forg365 client_ids in CA")
    print("  5. [TokenIssuance] Require MFA step-up at device-code activation; alert on request/activation IP delta")
    print("  6. [TokenIssuance] Monitor poll rate; revoke token on sub-5s polling or post-issuance IP change")
    if rules:
        print("\nSentinel KQL Rules Matched (adapt before deploying to production):")
        for r in rules: print(f"  // {r}")
        print("  // SigninLogs | where NetworkLocationDetails has_any('amazonaws','digitalocean','vultr') | where AuthenticationRequirement == 'singleFactorAuthentication'")
        print("  // AuditLogs | where OperationName startswith 'DeviceCode' | where AppId in ('1fec8e78-bce4-4aaf-ab1b-5451cc387264') | where TimeGenerated - prev(TimeGenerated) < 5s")
    print(f"\n[*] Total: {len(deduped)} finding(s) | Shown: {printed} | High: {sum(1 for a in deduped if a[2]=='high')}")
    return high

def main():
    ap = argparse.ArgumentParser(description="Forg365 AiTM + Device-Code Phishing Detection Lab")
    ap.add_argument("log_file", nargs="?", help="M365 Unified Audit Log export (one JSON event per line)")
    ap.add_argument("--mode", choices=["aitm","device-code","both"], default="both")
    ap.add_argument("--severity", choices=["low","medium","high"], default="low")
    args = ap.parse_args()
    entries = parse_log(args.log_file)
    print(f"[*] Loaded {len(entries)} log entries. Mode={args.mode} MinSeverity={args.severity}\n")
    alerts = detect_chain(entries, args.mode)
    high = report(alerts, args.severity)
    sys.exit(1 if high else 0)

if __name__ == "__main__": main()