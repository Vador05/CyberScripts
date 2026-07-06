"""
ToddyCat Umbrij Gmail OAuth Token Abuse Detector

Scans Google Workspace audit log exports for ToddyCat Umbrij-style OAuth token
abuse patterns across three kill-chain stages.

Usage:
    python toddycat_gmail_oauth_detector.py audit_log.jsonl
    python toddycat_gmail_oauth_detector.py audit_log.jsonl --iocs iocs.json --severity high

Example iocs.json:
    {
        "allowlisted_service_accounts": ["svc-archive@example.iam.gserviceaccount.com"],
        "suspicious_oauth_client_ids": ["123456789-abc.apps.googleusercontent.com"],
        "known_bad_user_agents": ["CustomC2Tool/1.0"]
    }
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

GMAIL_SCOPES = {"gmail.readonly", "https://mail.google.com/", "gmail.modify"}
MAILBOX_METHODS = {"gmail.users.messages.list", "gmail.users.threads.list", "gmail.users.messages.get"}
UMBRIJ_UA_PATTERNS = [r"Go-http-client/", r"python-requests/", r"Python-urllib/", r"fasthttp", r"net/http"]
BULK_THRESHOLD = 10
WORK_HOURS = (7, 20)
DEDUP_WINDOW = 60
BULK_WINDOW = 300
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

def load_iocs(path):
    with open(path) as f:
        data = json.load(f)
    return (
        set(data.get("allowlisted_service_accounts", [])),
        set(data.get("suspicious_oauth_client_ids", [])),
        list(data.get("known_bad_user_agents", []))
    )

def is_service_account(email):
    return bool(email and (email.endswith(".gserviceaccount.com") or re.search(r"@[^@]+\.iam\.", email)))

def parse_entry(line):
    try:
        raw = json.loads(line[:65536])
    except (json.JSONDecodeError, ValueError):
        return None
    actor = raw.get("actor", {})
    entry = {
        "timestamp": raw.get("id", {}).get("time") or raw.get("timestamp", ""),
        "actor_email": actor.get("email", ""),
        "oauth_client_id": raw.get("authorizationInfo", {}).get("resourceName", "") or raw.get("oauth_client_id", ""),
        "method": raw.get("methodName", "") or raw.get("method", ""),
        "resource": raw.get("resourceName", "") or raw.get("resource", ""),
        "scopes": raw.get("authorizationInfo", {}) .get("grantedScopes", []) or raw.get("scopes", []),
        "source_ip": raw.get("requestMetadata", {}).get("callerIp", "") or raw.get("source_ip", ""),
        "user_agent": raw.get("requestMetadata", {}).get("callerSuppliedUserAgent", "") or raw.get("user_agent", ""),
        "raw_line": line.rstrip(),
    }
    if not entry["scopes"] and "scope" in raw:
        sc = raw["scope"]
        entry["scopes"] = sc.split() if isinstance(sc, str) else sc
    return entry

def parse_ts(ts_str):
    if not ts_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None

def match_rules(entry, allowlist, suspicious_clients, extra_ua_patterns, previous_scopes):
    hits = []
    email = entry["actor_email"]
    scopes = set(entry["scopes"]) if entry["scopes"] else set()
    method = entry["method"]
    ua = entry["user_agent"]
    client_id = entry["oauth_client_id"]
    ts = parse_ts(entry["timestamp"])
    gmail_scopes_granted = scopes & GMAIL_SCOPES

    if gmail_scopes_granted and is_service_account(email):
        if email not in allowlist:
            hits.append(("ScopeGrant", "unexpected_gmail_scope_grant", "high"))
        prev = previous_scopes.get(email, set())
        new_scopes = gmail_scopes_granted - prev
        if prev and new_scopes:
            hits.append(("ScopeGrant", "scope_creep_expansion", "high"))
        previous_scopes[email] = prev | gmail_scopes_granted

    if client_id and client_id in suspicious_clients:
        hits.append(("ScopeGrant", "suspicious_oauth_client_id", "high"))

    if method in MAILBOX_METHODS and is_service_account(email):
        hits.append(("MailboxAccess", "service_account_mailbox_access", "medium"))
        if ts and not (WORK_HOURS[0] <= ts.hour < WORK_HOURS[1]):
            hits.append(("MailboxAccess", "off_hours_mailbox_access", "high"))

    all_ua_patterns = UMBRIJ_UA_PATTERNS + [re.escape(p) for p in extra_ua_patterns]
    if ua and any(re.search(p, ua, re.IGNORECASE) for p in all_ua_patterns):
        hits.append(("MailboxAccess", "umbrij_user_agent_signature", "medium"))

    return hits

def format_alert(stage, severity, rule, actor, ts_str, raw_line):
    return f"[{ts_str}] [{severity.upper()}] [{stage}] rule={rule} actor={actor} | {raw_line}"

def main():
    parser = argparse.ArgumentParser(description="ToddyCat Umbrij Gmail OAuth Token Abuse Detector")
    parser.add_argument("log_file", help="Path to Google Workspace audit log in JSON-lines format")
    parser.add_argument("--iocs", help="Path to supplemental IOCs JSON file")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low", help="Minimum alert severity")
    args = parser.parse_args()

    allowlist, suspicious_clients, extra_ua = set(), set(), []
    if args.iocs:
        try:
            a, s, u = load_iocs(args.iocs)
            allowlist, suspicious_clients, extra_ua = a, s, u
        except (OSError, json.JSONDecodeError, KeyError) as e:
            print(f"[WARN] Failed to load IOCs: {e}", file=sys.stderr)

    min_sev = SEVERITY_RANK[args.severity]
    stage_counts = defaultdict(int)
    unique_actors = set()
    peak_sev = "low"
    dedup_cache = {}
    bulk_tracker = defaultdict(list)
    method_tracker = defaultdict(list)
    previous_scopes = {}
    warn_count = 0
    found_high = False

    try:
        log_fh = open(args.log_file)
    except OSError as e:
        print(f"[ERROR] Cannot open log file: {e}", file=sys.stderr)
        sys.exit(2)

    with log_fh:
        for raw_line in log_fh:
            if not raw_line.strip():
                continue
            entry = parse_entry(raw_line)
            if entry is None:
                warn_count += 1
                continue

            hits = match_rules(entry, allowlist, suspicious_clients, extra_ua, previous_scopes)
            email = entry["actor_email"]
            ts = parse_ts(entry["timestamp"])
            ts_epoch = ts.timestamp() if ts else 0
            ts_str = entry["timestamp"] or "unknown"

            if is_service_account(email) and entry["method"] in MAILBOX_METHODS and entry["resource"]:
                bulk_tracker[email].append((ts_epoch, entry["resource"]))
                bulk_tracker[email] = [(t, r) for t, r in bulk_tracker[email] if ts_epoch - t <= BULK_WINDOW]
                distinct_resources = {r for _, r in bulk_tracker[email]}
                if len(distinct_resources) >= BULK_THRESHOLD:
                    hits.append(("BulkEnumeration", "bulk_mailbox_resource_enumeration", "high"))

            if is_service_account(email) and entry["method"]:
                method_tracker[(email, entry["method"])].append(ts_epoch)
                method_tracker[(email, entry["method"])] = [
                    t for t in method_tracker[(email, entry["method"])] if ts_epoch - t <= BULK_WINDOW
                ]

            for actor_key, times in list(method_tracker.items()):
                if actor_key[0] == email:
                    actors_for_method = {k[0] for k in method_tracker if k[1] == actor_key[1] and method_tracker[k]}
                    if len(actors_for_method) >= 3:
                        hits.append(("BulkEnumeration", "repeated_method_multi_principal", "high"))
                        break

            for stage, rule, severity in hits:
                if SEVERITY_RANK[severity] < min_sev:
                    continue
                dedup_key = (email, rule, stage)
                last_seen = dedup_cache.get(dedup_key, 0)
                if ts_epoch - last_seen < DEDUP_WINDOW:
                    continue
                dedup_cache[dedup_key] = ts_epoch
                print(format_alert(stage, severity, rule, email or entry["oauth_client_id"], ts_str, entry["raw_line"]))
                stage_counts[stage] += 1
                unique_actors.add(email or entry["oauth_client_id"])
                if SEVERITY_RANK[severity] > SEVERITY_RANK[peak_sev]:
                    peak_sev = severity
                if severity == "high":
                    found_high = True

    if warn_count:
        print(f"[WARN] Skipped {warn_count} malformed log lines", file=sys.stderr)

    print("\n--- Summary ---")
    for stage, count in stage_counts.items():
        print(f"  {stage}: {count} hit(s)")
    print(f"  Unique actor principals: {len(unique_actors)}")
    print(f"  Peak severity: {peak_sev.upper()}")

    sys.exit(1 if found_high else 0)

if __name__ == "__main__":
    main()