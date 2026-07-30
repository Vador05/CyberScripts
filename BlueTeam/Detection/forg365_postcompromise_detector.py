"""Forg365 Antibot Bypass and Post-Compromise Forwarding Detector.

Parses M365 Unified Audit Log exports for Forg365 PhaaS antibot-bypass
indicators during OAuth device-code delivery and post-compromise mailbox
manipulation events following session-cookie or device-code token theft.

Usage:
    python forg365_postcompromise_detector.py [log_file] [--mode both] [--severity low]
    python forg365_postcompromise_detector.py audit.log --mode forwarding --severity high
    python forg365_postcompromise_detector.py  # uses built-in synthetic Forg365 demo log
"""
import argparse, json, re, sys
from collections import defaultdict
from datetime import datetime

RESI_ASN = re.compile(r"185\.220\.|193\.32\.|141\.98\.|45\.142\.|194\.165\.|91\.108\.|198\.54\.")
HEADLESS  = re.compile(r"python-requests|curl/|wget/|go-http|headless|phantomjs|selenium|puppeteer|playwright|httpx|aiohttp", re.I)
BROWSER_UA = re.compile(r"Mozilla/5\.0.+(?:Chrome|Firefox|Safari|Edge|Trident)", re.I)
TENANT_DOMAINS = {"contoso.com", "contoso.onmicrosoft.com"}
SEV_RANK = {"low": 0, "medium": 1, "high": 2}

SYNTH = [
    {"CreationTime":"2026-07-14T09:00:00Z","UserId":"alice@contoso.com","Operation":"DeviceCodeRequest","ClientId":"1fec8e78-bce4-4aaf-ab1b-5451cc387264","ClientIP":"185.220.101.5","UserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36","Parameters":[]},
    {"CreationTime":"2026-07-14T09:00:05Z","UserId":"alice@contoso.com","Operation":"DeviceCodeRequest","ClientId":"1fec8e78-bce4-4aaf-ab1b-5451cc387264","ClientIP":"185.220.101.5","UserAgent":"python-requests/2.28.2","Parameters":[]},
    {"CreationTime":"2026-07-14T09:00:45Z","UserId":"alice@contoso.com","Operation":"DeviceCodeActivated","ClientId":"1fec8e78-bce4-4aaf-ab1b-5451cc387264","ClientIP":"185.220.101.5","UserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64)","Parameters":[]},
    {"CreationTime":"2026-07-14T09:05:00Z","UserId":"alice@contoso.com","Operation":"Set-Mailbox","ClientIP":"185.220.101.6","UserAgent":"","Parameters":[{"Name":"ForwardingSmtpAddress","Value":"exfil@gmail.com"}]},
    {"CreationTime":"2026-07-14T09:06:00Z","UserId":"alice@contoso.com","Operation":"New-InboxRule","ClientIP":"185.220.101.6","UserAgent":"","Parameters":[{"Name":"ForwardTo","Value":"exfil@gmail.com"}]},
    {"CreationTime":"2026-07-14T09:07:00Z","UserId":"alice@contoso.com","Operation":"Add-MailboxPermission","ClientIP":"185.220.101.6","UserAgent":"","Parameters":[{"Name":"AccessRights","Value":"FullAccess"},{"Name":"User","Value":"attacker#ext#@contoso.onmicrosoft.com"}]},
]

def _g(d, *keys): return str(next((d[k] for k in keys if k in d and d[k] is not None), ""))
def _t(s):
    try: return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception: return None
def _ext(addr):
    m = re.search(r"@([\w.-]+)", addr)
    dom = m.group(1).lower() if m else ""
    return bool(dom) and dom not in TENANT_DOMAINS

def norm(r):
    params = r.get("Parameters") or []
    if isinstance(params, str):
        try: params = json.loads(params)
        except Exception: params = []
    lang = _g(r, "AcceptLanguage", "Accept-Language")
    if not lang:
        for ep in (r.get("ExtendedProperties") or []):
            if isinstance(ep, dict) and ep.get("Name", "").lower() in ("acceptlanguage", "accept-language"):
                lang = str(ep.get("Value", ""))
                break
    return {"ts": _g(r,"CreationTime","Timestamp"), "upn": _g(r,"UserId","UserPrincipalName").lower(),
            "op": _g(r,"Operation"), "cid": _g(r,"ClientId","AppId").lower(),
            "ip": _g(r,"ClientIP","IPAddress"), "ua": _g(r,"UserAgent"),
            "lang": lang,
            "params": {str(p.get("Name","")).lower(): str(p.get("Value","")) for p in params if isinstance(p, dict)}}

def parse_events(path):
    if path is None:
        print("[*] No log file supplied — running built-in synthetic Forg365 demo sequence.\n")
        return [norm(e) for e in SYNTH]
    try:
        events = []
        with open(path, errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line: continue
                try: events.append(norm(json.loads(line)))
                except Exception: continue
        return events
    except OSError as e:
        sys.exit(f"ERROR opening log: {e}")

def detect(events, mode):
    hits, dc_by_ip, dc_by_sess = [], defaultdict(list), defaultdict(dict)
    alerted_rapid = {}
    dc_activation_by_upn = {}
    for e in events:
        op_l = e["op"].lower(); ua = e["ua"]; ip = e["ip"]; upn = e["upn"]; ts = e["ts"]; p = e["params"]
        lang = e.get("lang", "")
        sess = f"{upn}:{e['cid']}"

        # Track device-code activations unconditionally — PostCompromise auto-reply rule needs
        # this for temporal correlation regardless of which detection mode is active.
        if re.search(r"devicecode(?:activat|usersign)", op_l):
            t = _t(ts)
            if t and (upn not in dc_activation_by_upn or t > dc_activation_by_upn[upn]):
                dc_activation_by_upn[upn] = t

        if mode in ("both", "antibot"):
            if re.search(r"devicecode(?:request|initiat|creat)", op_l):
                if RESI_ASN.search(ip):
                    hits.append(("high","AntibotBypass","DeliveryBypass","ResidentialProxyDeviceCode",upn,f"IP={ip}","Block residential-proxy ASN ranges in Conditional Access; revoke device-code tokens"))
                if HEADLESS.search(ua):
                    hits.append(("high","AntibotBypass","DeviceCodeAbuse","HeadlessUADeviceCode",upn,f"UA={ua[:80]}","Enforce CA policy blocking device-code flow for headless or non-compliant clients"))
                # Accept-Language absent with modern browser UA suggests headless spoofing.
                # The field is only present in some UAL export configurations; skip when absent
                # from the event entirely (lang will be empty string in both cases, so gate on
                # the UA match to avoid noisy medium findings when the field is simply not logged).
                if BROWSER_UA.search(ua) and not HEADLESS.search(ua) and lang == "":
                    hits.append(("medium","AntibotBypass","DeliveryBypass","AbsentAcceptLanguageBrowserUA",upn,f"UA={ua[:60]} AcceptLanguage=<absent>","Possible headless browser spoofing: modern browser UA with no Accept-Language claim; confirm with endpoint telemetry and approved-client allowlist"))
                t = _t(ts)
                if t:
                    dc_by_ip[ip].append(t)
                    dc_by_ip[ip] = [x for x in dc_by_ip[ip] if (t - x).total_seconds() <= 60]
                    if len(dc_by_ip[ip]) >= 2:
                        last_alert = alerted_rapid.get(ip)
                        if last_alert is None or (t - last_alert).total_seconds() >= 60:
                            alerted_rapid[ip] = t
                            hits.append(("medium","AntibotBypass","DeliveryBypass","RapidDeviceCodeRequests",upn,f"IP={ip} burst={len(dc_by_ip[ip])} in <60s","Rate-limit device-code endpoint; investigate automated lure-page serving"))
                dc_by_sess[sess]["req_ua"] = ua
            elif re.search(r"devicecode(?:activat|usersign)", op_l):
                req = dc_by_sess[sess].get("req_ua", "")
                if req and req != ua:
                    hits.append(("high","AntibotBypass","DeviceCodeAbuse","UAMismatchAcrossSession",upn,f"req_ua={req[:45]} act_ua={ua[:45]}","Likely Forg365 relay split; revoke tokens; investigate full session chain"))
        if mode in ("both", "forwarding"):
            if re.search(r"set-(?:cas)?mailbox$", op_l):
                fwd = p.get("forwardingsmtpaddress","") or p.get("forwardingaddress","")
                if fwd and _ext(fwd):
                    hits.append(("high","PostCompromise","MailboxForward","ExternalSmtpForwarding",upn,f"ForwardTo={fwd[:80]}","Remove forwarding rule; revoke sessions; notify security team and affected user"))
            elif re.search(r"(?:new|set)-inboxrule", op_l):
                fwd = p.get("forwardto","") or p.get("redirectto","")
                if fwd and _ext(fwd):
                    hits.append(("high","PostCompromise","InboxRule","MaliciousInboxRule",upn,f"ForwardTo={fwd[:80]}","Delete inbox rule; audit all mailbox rules; revoke active sessions"))
            elif re.search(r"add-mailboxpermission", op_l):
                user = p.get("user","") or p.get("trustee","")
                if "fullaccess" in p.get("accessrights","").lower() and ("#ext#" in user.lower() or _ext(user)):
                    hits.append(("high","PostCompromise","DelegateGrant","UnauthorizedFullAccess",upn,f"GrantTo={user[:80]}","Remove delegate grant immediately; audit all mailbox permission assignments"))
            elif re.search(r"set-mailboxautoreplyconfiguration", op_l) and p.get("autoreplystate","").lower() == "enabled":
                ext_aud = p.get("externalaudience","").lower()
                if ext_aud in ("all", "external", "externalpartners"):
                    t_auto = _t(ts)
                    t_dc = dc_activation_by_upn.get(upn)
                    if t_auto and t_dc:
                        delta = (t_auto - t_dc).total_seconds()
                        if 0 < delta < 86400:
                            hits.append(("medium","PostCompromise","MailboxForward","ExternalAutoReplyEnabled",upn,f"AutoReply enabled for {upn}","Disable auto-reply; inspect reply body for exfiltration addresses"))
    return hits

def report(hits, min_sev):
    rank = SEV_RANK[min_sev]
    by_upn, stage_counts, a_upns, pc_upns = defaultdict(lambda: defaultdict(list)), defaultdict(int), set(), set()
    dedup, has_high = set(), False
    for sev, cat, stage, rule, upn, indicator, mitigation in hits:
        key = (upn, rule, indicator[:50])
        if key in dedup: continue
        dedup.add(key)
        stage_counts[stage] += 1
        (a_upns if cat == "AntibotBypass" else pc_upns).add(upn)
        by_upn[upn][cat].append(stage)
        if sev == "high": has_high = True
        if SEV_RANK[sev] >= rank:
            print(f"[{sev.upper():6}] {cat} | {stage} | {rule} | {upn}")
            print(f"         INDICATOR:  {indicator[:100]}")
            print(f"         MITIGATION: {mitigation}")
    print("\n--- Stage Hit Counts ---")
    for s, c in sorted(stage_counts.items()): print(f"  {s}: {c}")
    chained = a_upns & pc_upns
    if chained:
        print("\n--- Cross-Stage Correlation (AntibotBypass -> PostCompromise) ---")
        for upn in sorted(chained):
            print(f"  {upn}: bypass={by_upn[upn]['AntibotBypass']} -> postcomp={by_upn[upn]['PostCompromise']}")
    matched = sorted({r for _,_,_,r,*_ in hits})
    print("\n--- Remediation Checklist (by urgency) ---")
    REMEDS = ["Revoke active sessions and device-code tokens for all flagged principals via Entra ID",
              "Remove ExternalSmtpForwarding and ForwardingAddress from all affected mailboxes",
              "Audit and delete malicious inbox rules; re-enable per-folder audit logging",
              "Remove unauthorized FullAccess delegate grants; review all mailbox permission assignments",
              "Enforce Conditional Access blocking device-code flow for non-managed devices",
              "Update residential-proxy ASN blocklists; monitor for new Forg365 delivery infrastructure"]
    for i, s in enumerate(REMEDS, 1): print(f"  {i}. {s}")
    print("\n--- Sentinel KQL (copy-paste template) ---")
    print(f'let Rules = dynamic([{", ".join(chr(34)+r+chr(34) for r in matched)}]);')
    print("SigninLogs | union AuditLogs | where Category in (Rules)")
    print("| project TimeGenerated, UserPrincipalName, Category, IPAddress, ResultType")
    return has_high

def main():
    ap = argparse.ArgumentParser(description="Forg365 antibot-bypass and post-compromise forwarding detector for M365 UAL exports")
    ap.add_argument("log_file", nargs="?", help="M365 Unified Audit Log export — one JSON event per line")
    ap.add_argument("--mode", choices=["antibot","forwarding","both"], default="both")
    ap.add_argument("--severity", choices=["low","medium","high"], default="low")
    args = ap.parse_args()
    events = parse_events(args.log_file)
    print(f"[*] Parsed {len(events)} events | mode={args.mode} | min_severity={args.severity}\n")
    hits = detect(events, args.mode)
    has_high = report(hits, args.severity)
    if not hits: print("[*] No indicators matched.")
    sys.exit(1 if has_high else 0)

if __name__ == "__main__":
    main()