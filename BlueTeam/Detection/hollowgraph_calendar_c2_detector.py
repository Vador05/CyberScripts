"""HollowGraph M365 Calendar C2 Dead-Drop Detector.

Detects HollowGraph-style Calendar-based C2 dead-drop behavior in M365 Unified
Audit Log exports: encoded event content, GraphAPI polling anomalies, suspicious
calendar access. Maps findings to MITRE T1102.001.

Usage:
    python hollowgraph_calendar_c2_detector.py [log_file] [--severity low] [--tenant contoso.com]
    python hollowgraph_calendar_c2_detector.py audit.log --severity high --tenant contoso.com
"""
import argparse, base64, json, re, sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta

HEADLESS = re.compile(r"python-requests|curl/|wget/|go-http-client|httpx|aiohttp", re.I)
B64 = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
HEX = re.compile(r"[0-9a-fA-F]{32,}")
NONASCII = re.compile(r"[^\x00-\x7F]{4,}")
URLENC = re.compile(r"(?:%[0-9A-Fa-f]{2}){8,}")
SEV = {"low": 0, "medium": 1, "high": 2}

def _synth():
    p = base64.b64encode(b"C2_BEACON_INTERVAL=45;TARGET=EXFIL;CMD=COLLECT_CREDS").decode()
    b = datetime(2026, 7, 10, 10, 0, 0, tzinfo=timezone.utc)
    aid = "deadbeef-c2c2-c2c2-c2c2-000000000000"
    def ev(op, i=0, ua="python-requests/2.28.0"):
        return {"CreationTime": (b+timedelta(seconds=45*i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "UserId": "svc-hg@evil.onmicrosoft.com", "Operation": op, "AppId": aid,
                "ClientIP": "203.0.113.99", "UserAgent": ua, "Subject": "Standup",
                "Location": p, "Body": p if "Create" in op else "", "Attendees": "",
                "OrganizerAddress": "c2@evil.onmicrosoft.com"}
    return ([ev("CalendarEvent_Read", i) for i in range(12)] + [ev("CalendarEvent_Create")] +
            [ev("CalendarEvent_Update", 0, "go-http-client/1.1") for _ in range(5)])

def _g(d, *k): return str(next((d[x] for x in k if x in d and d[x] is not None), ""))
def _t(s):
    try: return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception: return None
def _5min_bucket(ts):
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return (dt.year, dt.month, dt.day, dt.hour, dt.minute // 5)
    except Exception: return None
def _norm(r):
    return {"ts": _g(r,"CreationTime","Timestamp"), "upn": _g(r,"UserId","UserPrincipalName"),
            "op": _g(r,"Operation"), "app_id": _g(r,"AppId","ClientId"),
            "ua": _g(r,"UserAgent","user_agent"), "subject": _g(r,"Subject"),
            "location": _g(r,"Location"), "body": _g(r,"Body"),
            "attendees": _g(r,"Attendees"), "organizer": _g(r,"OrganizerAddress","Organizer")}

def parse_log(path):
    if path is None:
        print("[*] No log file — using built-in synthetic HollowGraph demo log.\n")
        return [_norm(e) for e in _synth()]
    try: fh = open(path, errors="replace")
    except OSError as e: sys.exit(f"ERROR: {e}")
    out = []
    with fh:
        for line in fh:
            line = line.strip()
            if not line: continue
            try: out.append(_norm(json.loads(line)))
            except json.JSONDecodeError: continue
    return out

def detect_c2(entries, tenant):
    c = defaultdict(int)
    for e in entries:
        if "@" in e["organizer"]: c[e["organizer"].split("@",1)[1]] += 1
    dom = tenant or (max(c, key=c.get) if c else "")
    rtimes = defaultdict(list)
    for e in entries:
        if "calendarevent_read" in e["op"].lower():
            t = _t(e["ts"])
            if t: rtimes[e["app_id"]].append(t)
    hits = []; seen = {}
    def hit(ts, upn, aid, sev, rule, ind, action):
        k = (aid, rule, _5min_bucket(ts))
        if k in seen: return
        seen[k] = True
        hits.append({"ts":ts,"upn":upn,"app_id":aid,"severity":sev,"rule":rule,"indicator":ind[:120],"action":action})
    for e in entries:
        ts, upn, aid, op, ua, org = e["ts"], e["upn"], e["app_id"], e["op"], e["ua"], e["organizer"]
        for f, v in [("Subject",e["subject"]),("Location",e["location"]),("Body",e["body"])]:
            if B64.search(v): hit(ts,upn,aid,"high","EncodedBase64EventField",f"{f}={v}","Quarantine event and block app_id in Entra ID")
            if HEX.search(v): hit(ts,upn,aid,"high","EncodedHexEventField",f"{f}={v}","Quarantine event and block app_id in Entra ID")
        if NONASCII.search(e["attendees"]) or URLENC.search(e["attendees"]):
            hit(ts,upn,aid,"medium","EncodedAttendeeField",f"Attendees={e['attendees']}","Review attendee encoding and revoke calendar share")
        if re.search(r"calendarevent_(create|update)", op, re.I):
            od = org.split("@",1)[1] if "@" in org else ""
            if dom and od and od != dom: hit(ts,upn,aid,"medium","ExternalOrganizerAnomaly",f"Organizer={org}","Verify organizer and remove external calendar access")
        if HEADLESS.search(ua): hit(ts,upn,aid,"medium","HeadlessClientCalendarAccess",f"UserAgent={ua}","Block app and revoke OAuth tokens for service principal")
    for aid, times in rtimes.items():
        times.sort()
        upn = next((e["upn"] for e in entries if e["app_id"] == aid), "")
        for i in range(len(times)):
            w = [t for t in times if times[i] <= t <= times[i]+timedelta(minutes=10)]
            if len(w) > 8:
                hit(times[i].strftime("%Y-%m-%dT%H:%M:%SZ"),upn,aid,"high","GraphAPIPollingCadenceAnomaly",
                    f"AppId={aid} reads={len(w)} in 10min","Block app_id and investigate OAuth token scope")
                break
        ivs = [(times[i+1]-times[i]).total_seconds() for i in range(len(times)-1)]
        bk = [v for v in ivs if 30 <= v <= 90]
        if len(bk) >= 3:
            hit(times[0].strftime("%Y-%m-%dT%H:%M:%SZ"),upn,aid,"medium","BeaconIntervalAnomaly",
                f"AppId={aid} intervals={bk[:5]}","Revoke OAuth tokens and enable conditional access")
    return hits

def report(hits, min_sev):
    mr = set()
    vis = [h for h in hits if SEV.get(h["severity"],0) >= SEV.get(min_sev,0)]
    for h in vis:
        print(f"[{h['severity'].upper():6}] T1102.001 | {h['rule']:35} | {(h['upn'] or h['app_id'])[:40]:40} | {h['indicator']} | ACTION: {h['action']}")
        mr.add(h["rule"])
    print(f"\n{'='*80}\nSUMMARY: {len(hits)} total findings ({len(vis)} shown at --severity {min_sev})\n{'='*80}")
    steps = ["Block identified app_id(s) via Entra ID App Governance and disable the service principal",
             "Revoke all OAuth tokens for the associated service principal (Entra ID > Enterprise Apps > Tokens)",
             "Delete or quarantine the dead-drop shared calendar and audit its sharing permissions",
             "Enforce Calendar sharing policy restrictions in Exchange Online Admin Center",
             "Enable Graph Activity Log Diagnostic Settings and route to Sentinel workspace",
             "Deploy emitted Sentinel KQL rules and set alert threshold to 1 event",
             "Hunt for lateral movement from UPNs associated with flagged app_ids"]
    print("\nC2-SEVERANCE CHECKLIST (ordered by urgency):")
    for i, s in enumerate(steps, 1): print(f"  {i}. {s}")
    if mr:
        print("\n--- SENTINEL KQL DEPLOYMENT BLOCK ---")
        for r in sorted(mr):
            print(f"\n// Rule: {r} | MITRE T1102.001 Dead Drop Resolver\nOfficeActivity\n| where TimeGenerated > ago(1d) and Operation in (\"CalendarEvent_Create\",\"CalendarEvent_Update\",\"CalendarEvent_Read\")\n| union (MicrosoftGraphActivityLogs | where RequestUri has \"calendar\" | project TimeGenerated,UserId=UserPrincipalName,Operation=\"GraphCalendarRead\",AppId,IPAddress)\n| summarize Count=count() by UserId,AppId,bin(TimeGenerated,5m)\n| where Count > 8  // Tune threshold for {r}")
    return any(h["severity"] == "high" for h in hits)

def main():
    ap = argparse.ArgumentParser(description="HollowGraph M365 Calendar C2 Dead-Drop Detector")
    ap.add_argument("log_file", nargs="?", default=None, help="M365 Unified Audit Log export (one JSON event per line)")
    ap.add_argument("--severity", choices=["low","medium","high"], default="low", help="Minimum alert severity (default: low)")
    ap.add_argument("--tenant", default="", help="M365 tenant domain, e.g. contoso.com")
    args = ap.parse_args()
    entries = parse_log(args.log_file)
    hits = detect_c2(entries, args.tenant)
    sys.exit(1 if report(hits, args.severity) else 0)

if __name__ == "__main__":
    main()