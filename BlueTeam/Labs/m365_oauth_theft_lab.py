Looking at the two bugs:

1. The `re.error` catch is inside the `for e in entries` loop — it warns per-entry (potentially thousands of times) and can't skip the whole rule cleanly. Fix: validate/compile regexes at load time in `main()` and skip invalid supplemental patterns there.

2. The `"name"`/`"stage"` check in `match_rules` is inside `if ind:` (fires per matching entry, not per rule) and the `continue` only skips one entry iteration. Fix: move the validation to the top of the `for rule in rules` loop.

#!/usr/bin/env python3
"""M365 ConsentFix/ClickFix OAuth Token Theft Lab

Scans M365 Unified Audit Log exports for OAuth consent abuse and token replay.

Usage:
    python m365_oauth_theft_lab.py audit_log.txt
    python m365_oauth_theft_lab.py audit_log.txt --severity high --patterns extra.json
"""
import argparse, json, re, sys
from collections import defaultdict
from datetime import datetime, timezone

RANK = {"low": 0, "medium": 1, "high": 2}
RULES = [
    {"name": "UnverifiedPublisherConsent", "stage": "ConsentAbuse", "severity": "high",
     "unverified_publisher": True,
     "fix": "Enable admin-consent workflow; block unverified-publisher apps via Entra ID policy."},
    {"name": "HighPrivilegeScopePair", "stage": "ConsentAbuse", "severity": "high",
     "scope_pairs": [["Mail.Read", "Files.ReadWrite"], ["Mail.ReadWrite", "Files.ReadWrite"], ["Contacts.Read", "Mail.Send"]],
     "fix": "Restrict delegated grants; require MFA for admin consent; audit existing consents."},
    {"name": "OffHoursConsent", "stage": "ConsentAbuse", "severity": "medium", "op_re": r"(?i)consent", "off_hours": True,
     "fix": "Alert on consent grants outside 08:00-18:00 UTC; enforce CA for app registration."},
    {"name": "SuspiciousAppName", "stage": "ConsentAbuse", "severity": "medium",
     "app_re": r"(?i)ms.{0,8}update|office.{0,8}helper|teams.{0,8}conn|365.{0,8}sync|clickfix|consentfix|document.{0,8}view",
     "fix": "Block lure-name app registrations; require verified publisher for all OAuth apps."},
    {"name": "HeadlessBrowserReplay", "stage": "TokenReplay", "severity": "high",
     "ua_re": r"(?i)headlesschrome|phantomjs|selenium|puppeteer|playwright|python-requests|go-http",
     "fix": "Block automation UAs via continuous-access evaluation; revoke affected tokens."},
    {"name": "ImpossibleTravel", "stage": "TokenReplay", "severity": "high", "impossible_travel": True,
     "fix": "Enable impossible-travel CA policy; revoke session tokens and force re-auth."},
    {"name": "NewASNTokenReplay", "stage": "TokenReplay", "severity": "medium", "new_asn_replay": True,
     "fix": "Require MFA step-up on new ASN post-consent; use Identity Protection risk policies."},
    {"name": "ScopeEscalation24h", "stage": "ScopeEscalation", "severity": "medium", "scope_escalation": True,
     "fix": "Audit incremental grants; enforce admin approval for scope additions on existing apps."},
]
FIELD_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r".*?(?P<upn>[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})"
    r".*?(?:Operation|op)[=:]\s*(?P<op>[A-Za-z][A-Za-z0-9_ ]{2,40})"
    r".*?(?:AppDisplayName|app)[=:]\s*(?P<app>[^\|,;\"]{1,80})"
    r".*?(?:Scopes?|scope)[=:]\s*(?P<scope>[A-Za-z0-9._ ,]{1,200})",
    re.IGNORECASE)
IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
UA_RE = re.compile(r"(?:UserAgent|ua|user.agent)[=:]\s*([^\|;,\n\"]{1,200})", re.IGNORECASE)
PUBLISHER_VER_RE = re.compile(
    r"(?:IsPublisherVerified|PublisherVerified|publisher_verified)[=:]\s*(true|false|yes|no|1|0)",
    re.IGNORECASE)


def parse_log_entries(path):
    entries = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = FIELD_RE.search(line)
                if not m:
                    continue
                try:
                    ts = datetime.fromisoformat(m.group("ts").replace(" ", "T")).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
                ips, ua_m = IP_RE.findall(line), UA_RE.search(line)
                scopes = [s.strip() for s in re.split(r'[,\s]+', m.group("scope").strip()) if s]
                pv_m = PUBLISHER_VER_RE.search(line)
                publisher_verified = None
                if pv_m:
                    publisher_verified = pv_m.group(1).lower() in ("true", "yes", "1")
                entries.append({"ts": ts, "upn": m.group("upn").lower(), "op": m.group("op").strip(),
                                 "app": m.group("app").strip(), "scopes": scopes,
                                 "ip": ips[0] if ips else "", "ua": ua_m.group(1).strip() if ua_m else "",
                                 "publisher_verified": publisher_verified})
    except OSError as exc:
        sys.exit(f"[ERROR] Cannot read log file: {exc}")
    return entries


def match_rules(entries, rules, min_sev):
    findings, by_upn, by_ua = [], defaultdict(list), defaultdict(list)
    for e in entries:
        by_upn[e["upn"]].append(e); by_ua[(e["upn"], e["app"])].append(e)
    for rule in rules:
        if "name" not in rule or "stage" not in rule:
            print(f"[WARN] Rule missing required keys (name, stage), skipping", file=sys.stderr)
            continue
        if RANK.get(rule.get("severity", "low"), 0) < RANK.get(min_sev, 0):
            continue
        for e in entries:
            ind = None
            try:
                if "app_re" in rule:
                    ind = f"Suspicious app: {e['app']}" if re.search(rule["app_re"], e["app"]) else None
                    if not ind: continue
                elif "ua_re" in rule:
                    ind = f"Automation UA: {e['ua'][:60]}" if re.search(rule["ua_re"], e["ua"]) else None
                    if not ind: continue
                elif "scope_pairs" in rule:
                    ss = set(e["scopes"])
                    pair = next((p for p in rule["scope_pairs"] if all(s in ss for s in p)), None)
                    ind = f"High-priv scope pair {pair} on {e['app']}" if pair else None
                    if not ind: continue
                elif "off_hours" in rule:
                    if not re.search(rule.get("op_re", ""), e["op"]) or 8 <= e["ts"].hour < 18: continue
                    ind = f"Consent at {e['ts'].strftime('%H:%M')} UTC for {e['app']}"
                elif "unverified_publisher" in rule:
                    if not re.search(r"(?i)consent", e["op"]): continue
                    if e["publisher_verified"] is True: continue
                    if e["publisher_verified"] is False:
                        ind = f"Consent to unverified-publisher app: {e['app']}"
                    else:
                        ind = f"Consent grant (publisher verification status unknown) for {e['app']}"
                elif "impossible_travel" in rule:
                    peers = sorted(by_upn[e["upn"]], key=lambda x: x["ts"])
                    idx = next((i for i, x in enumerate(peers) if x is e), -1)
                    if idx < 1 or not e["ip"]: continue
                    prev = peers[idx - 1]
                    delta = abs((e["ts"] - prev["ts"]).total_seconds())
                    if delta < 3600 and e["ip"] != prev["ip"] and prev["ip"]:
                        ind = f"IP jump {prev['ip']}→{e['ip']} in {int(delta)}s"
                    else: continue
                elif "new_asn_replay" in rule:
                    cs = [x for x in by_ua[(e["upn"], e["app"])] if re.search(r"(?i)consent", x["op"])]
                    if not cs or not e["ip"]: continue
                    lc = max(cs, key=lambda x: x["ts"])
                    delta = (e["ts"] - lc["ts"]).total_seconds()
                    if 0 < delta <= 1800 and e["ip"] != lc.get("ip", e["ip"]):
                        ind = f"Token from new IP {e['ip']} within {int(delta)}s of consent"
                    else: continue
                elif "scope_escalation" in rule:
                    evts = sorted(by_ua[(e["upn"], e["app"])], key=lambda x: x["ts"])
                    if len(evts) < 2 or evts[-1] is not e: continue
                    seen, added, first = set(), [], True
                    for we in [x for x in evts if abs((x["ts"] - e["ts"]).total_seconds()) <= 86400]:
                        new = set(we["scopes"]) - seen; seen |= set(we["scopes"])
                        if new and not first: added.extend(new)
                        first = False
                    if not added: continue
                    ind = f"Scope escalation on {e['app']}: added {list(added)[:3]}"
                if ind:
                    findings.append({**e, "rule": rule["name"], "stage": rule["stage"],
                                      "severity": rule.get("severity", "low"), "indicator": ind, "mitigation": rule.get("fix", "")})
            except re.error as exc:
                print(f"[WARN] Rule {rule.get('name', '?')} has invalid regex: {exc}", file=sys.stderr)
                break
    return findings


def report_findings(findings):
    stage_counts, peak = defaultdict(int), "low"
    for f in findings:
        stage_counts[f["stage"]] += 1
        if RANK[f["severity"]] > RANK[peak]: peak = f["severity"]
        print(f"[{f['severity'].upper()}] {f['stage']} | {f['rule']} | {f['upn']} | {f['indicator'][:120]}")
        print(f"  MITIGATE: {f['mitigation']}")
    print("\n--- Summary ---")
    for stage, count in stage_counts.items(): print(f"  {stage}: {count} finding(s)")
    print(f"  Peak severity: {peak.upper()}")
    return peak == "high"


def main():
    ap = argparse.ArgumentParser(description="Detect ConsentFix/ClickFix OAuth theft in M365 audit logs.",
                                 epilog="Example: python m365_oauth_theft_lab.py export.txt --severity medium")
    ap.add_argument("log_file", help="Path to plain-text M365 Unified Audit Log export")
    ap.add_argument("--patterns", help="Supplemental JSON file with additional detection patterns")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum severity to emit (default: low)")
    args = ap.parse_args()
    rules = list(RULES)
    if args.patterns:
        try:
            with open(args.patterns, encoding="utf-8") as fh: extra = json.load(fh)
            if isinstance(extra, list):
                for pat in extra:
                    if not isinstance(pat, dict):
                        print(f"[WARN] Skipping non-dict supplemental pattern", file=sys.stderr)
                        continue
                    if "name" not in pat or "stage" not in pat:
                        print(f"[WARN] Supplemental pattern missing required keys (name, stage), skipping", file=sys.stderr)
                        continue
                    regex_valid = True
                    for re_key in ("app_re", "ua_re", "op_re"):
                        if re_key in pat:
                            try:
                                re.compile(pat[re_key])
                            except re.error as exc:
                                print(f"[WARN] Supplemental pattern '{pat['name']}' has invalid regex in '{re_key}': {exc}", file=sys.stderr)
                                regex_valid = False
                                break
                    if not regex_valid:
                        continue
                    rules.append(pat)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[WARN] Could not load supplemental patterns: {exc}", file=sys.stderr)
    entries = parse_log_entries(args.log_file)
    if not entries:
        print("[INFO] No parseable log entries found.", file=sys.stderr); sys.exit(0)
    findings = match_rules(entries, rules, args.severity)
    if not findings:
        print(f"[INFO] No findings at severity >= {args.severity}."); sys.exit(0)
    sys.exit(1 if report_findings(findings) else 0)


if __name__ == "__main__":
    main()