"""
AiTM PhaaS Token Harvest & M365 OAuth Abuse Detector

Scans plain-text M365 or Azure AD sign-in log exports for adversary-in-the-middle
token harvesting patterns associated with ARToken/EvilTokens PhaaS infrastructure.

Usage:
    python artokens_phaas_detector.py sign_in_logs.json
    python artokens_phaas_detector.py sign_in_logs.csv --iocs custom_iocs.json --severity high
    python artokens_phaas_detector.py audit_export.json --severity medium
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

PHISHING_DOMAINS = [
    "evilginx", "evil-proxy", "artoken", "eviltokens", "phishkit",
    "m365-login", "microsoftonline-proxy", "login-microsoft", "aitm-proxy",
    "oauth-relay", "token-harvest", "mfa-bypass", "aadproxy",
]

SUSPICIOUS_REDIRECT_PATTERNS = [
    r"https?://[^/]*evilginx[^/]*/",
    r"https?://[^/]*artoken[^/]*/",
    r"https?://[^/]*eviltokens[^/]*/",
    r"https?://[^/]*\.tk/",
    r"https?://[^/]*\.ml/",
    r"https?://[^/]*\.ga/",
    r"https?://[^/]*phish[^/]*/",
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/",
]

PHISHING_USER_AGENTS = [
    "evilginx", "go-http-client/2.0", "python-requests/2.2",
    "curl/7.68", "wget/1.20", "okhttp/3.12",
]

KNOWN_PROXY_SUBNETS = [
    "10.0.0.", "172.16.", "172.17.", "172.18.", "192.168.",
]

UNRECOGNIZED_CLIENT_IDS = [
    "00000002-0000-0000-c000-000000000000",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
]


def load_iocs(ioc_path):
    with open(ioc_path) as f:
        data = json.load(f)
    extra_domains = data.get("phishing_domains", [])
    extra_redirects = data.get("redirect_patterns", [])
    extra_agents = data.get("user_agents", [])
    return extra_domains, extra_redirects, extra_agents


def parse_log_entries(log_file):
    entries = []
    ts_re = re.compile(r'"?(?:createdDateTime|time|timestamp)"?\s*[=:]\s*"?([0-9T:\-Z.+]+)"?', re.I)
    upn_re = re.compile(r'"?(?:userPrincipalName|upn|user)"?\s*[=:]\s*"([^"]+)"', re.I)
    ip_re = re.compile(r'"?(?:ipAddress|clientIp|sourceIp|ip)"?\s*[=:]\s*"([^"]+)"', re.I)
    ua_re = re.compile(r'"?(?:userAgent|user_agent|ua)"?\s*[=:]\s*"([^"]+)"', re.I)
    cid_re = re.compile(r'"?(?:appId|clientId|client_id|oauthClientId)"?\s*[=:]\s*"([^"]+)"', re.I)
    redir_re = re.compile(r'"?(?:redirectUri|redirect_uri|redirectUrl)"?\s*[=:]\s*"([^"]+)"', re.I)
    token_re = re.compile(r'"?(?:tokenType|token_type|tokenIssuanceType)"?\s*[=:]\s*"([^"]+)"', re.I)
    result_re = re.compile(r'"?(?:status|resultType|result|authResult)"?\s*[=:]\s*"?([^",}\s]+)"?', re.I)
    mfa_re = re.compile(r'"?(?:mfaDetail|authenticationRequirement|mfa_result)"?\s*[=:]\s*"([^"]+)"', re.I)

    with open(log_file) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            def extract(pattern, default=""):
                m = pattern.search(line)
                return m.group(1) if m else default
            entry = {
                "lineno": lineno,
                "raw": line,
                "timestamp": extract(ts_re),
                "upn": extract(upn_re, "unknown"),
                "ip": extract(ip_re),
                "user_agent": extract(ua_re),
                "client_id": extract(cid_re),
                "redirect_uri": extract(redir_re),
                "token_type": extract(token_re),
                "result": extract(result_re),
                "mfa_detail": extract(mfa_re),
            }
            entries.append(entry)
    return entries


def match_rules(entries, phishing_domains, redirect_patterns, phishing_agents):
    findings = []
    ip_history = defaultdict(list)
    for e in entries:
        ip_history[e["upn"]].append((e["timestamp"], e["ip"]))

    compiled_redirs = [re.compile(p, re.I) for p in redirect_patterns]

    for e in entries:
        redir = e["redirect_uri"]
        ua = e["user_agent"].lower()
        ip = e["ip"]
        upn = e["upn"]
        ts = e["timestamp"]

        for domain in phishing_domains:
            if domain.lower() in redir.lower() or domain.lower() in ua:
                findings.append(("Staging", "high", "PhaaSDomainIOCMatch", upn, ts, e["raw"]))

        for pattern in compiled_redirs:
            if pattern.search(redir):
                findings.append(("Staging", "high", "SuspiciousRedirectURI", upn, ts, e["raw"]))

        for agent in phishing_agents:
            if agent.lower() in ua:
                findings.append(("Staging", "medium", "KnownPhishingUserAgent", upn, ts, e["raw"]))

        if "success" in e["result"].lower() and "mfa" in e["mfa_detail"].lower():
            for other in entries:
                if other["upn"] == upn and other is not e:
                    if other["ip"] != ip and other["ip"] and ip:
                        if abs(entries.index(other) - entries.index(e)) < 5:
                            findings.append(("Staging", "high", "MFASuccessFollowedByForeignIPToken", upn, ts, e["raw"]))
                            break

        if e["client_id"] in UNRECOGNIZED_CLIENT_IDS:
            findings.append(("Harvesting", "medium", "UnrecognizedOAuthClientID", upn, ts, e["raw"]))

        if "authorization_code" in e["token_type"].lower() or "code" in e["result"].lower():
            for other in entries:
                if other["upn"] == upn and other is not e and other["ip"] and ip:
                    if other["ip"] != ip:
                        findings.append(("Harvesting", "high", "AuthCodeFromMismatchedIP", upn, ts, e["raw"]))
                        break

        user_events = [(t, i) for t, i in ip_history[upn] if t and i]
        for i in range(len(user_events)):
            for j in range(i + 1, len(user_events)):
                t1, ip1 = user_events[i]
                t2, ip2 = user_events[j]
                if ip1 != ip2 and ip1 and ip2:
                    try:
                        dt1 = datetime.fromisoformat(t1.replace("Z", "+00:00"))
                        dt2 = datetime.fromisoformat(t2.replace("Z", "+00:00"))
                        if abs((dt2 - dt1).total_seconds()) < 300:
                            findings.append(("Replay", "high", "ImpossibleTravel", upn, ts, e["raw"]))
                    except ValueError:
                        pass

        for subnet in KNOWN_PROXY_SUBNETS:
            if ip.startswith(subnet):
                if "compliant" in e["result"].lower() or "mfa" in e["mfa_detail"].lower():
                    findings.append(("Replay", "medium", "ConditionalAccessBypassFromProxySubnet", upn, ts, e["raw"]))

        for domain in phishing_domains:
            if domain.lower() in ua:
                findings.append(("Replay", "high", "TokenReplayPhishingUserAgent", upn, ts, e["raw"]))

    return findings


def report_findings(findings, min_severity):
    severity_rank = {"low": 0, "medium": 1, "high": 2}
    min_rank = severity_rank.get(min_severity.lower(), 0)
    seen = {}
    stage_counts = defaultdict(int)
    unique_principals = set()
    peak = "low"
    exit_nonzero = False

    for stage, severity, rule, upn, ts, raw in findings:
        if severity_rank.get(severity, 0) < min_rank:
            continue
        dedup_key = (upn, rule)
        now = ts
        if dedup_key in seen:
            last_ts = seen[dedup_key]
            try:
                t1 = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
                t2 = datetime.fromisoformat(now.replace("Z", "+00:00"))
                if abs((t2 - t1).total_seconds()) < 300:
                    continue
            except ValueError:
                pass
        seen[dedup_key] = now
        alert_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"[{alert_ts}] [{stage}] [{severity.upper()}] {rule} | UPN={upn} | {raw[:200]}")
        stage_counts[stage] += 1
        unique_principals.add(upn)
        if severity_rank.get(severity, 0) > severity_rank.get(peak, 0):
            peak = severity
        if severity == "high":
            exit_nonzero = True

    print("\n=== Detection Summary ===")
    for stage in ("Staging", "Harvesting", "Replay"):
        print(f"  {stage}: {stage_counts.get(stage, 0)} hit(s)")
    print(f"  Unique principals involved: {len(unique_principals)}")
    print(f"  Peak severity observed: {peak.upper()}")
    return exit_nonzero


def main():
    parser = argparse.ArgumentParser(
        description="AiTM PhaaS Token Harvest & M365 OAuth Abuse Detector",
        epilog="Example: python artokens_phaas_detector.py sign_in_logs.json --iocs iocs.json --severity medium"
    )
    parser.add_argument("log_file", help="Path to plain-text M365 sign-in log or Azure AD audit log export")
    parser.add_argument("--iocs", help="Path to supplemental JSON file with additional PhaaS IOCs")
    parser.add_argument("--severity", default="low", choices=["low", "medium", "high"],
                        help="Minimum alert level to emit (default: low)")
    args = parser.parse_args()

    phishing_domains = list(PHISHING_DOMAINS)
    redirect_patterns = list(SUSPICIOUS_REDIRECT_PATTERNS)
    phishing_agents = list(PHISHING_USER_AGENTS)

    if args.iocs:
        try:
            extra_d, extra_r, extra_a = load_iocs(args.iocs)
            phishing_domains.extend(extra_d)
            redirect_patterns.extend(extra_r)
            phishing_agents.extend(extra_a)
        except (OSError, json.JSONDecodeError, KeyError) as e:
            print(f"[ERROR] Failed to load IOC file: {e}", file=sys.stderr)
            sys.exit(2)

    try:
        entries = parse_log_entries(args.log_file)
    except OSError as e:
        print(f"[ERROR] Cannot read log file: {e}", file=sys.stderr)
        sys.exit(2)

    if not entries:
        print("[INFO] No log entries parsed.", file=sys.stderr)
        sys.exit(0)

    findings = match_rules(entries, phishing_domains, redirect_patterns, phishing_agents)
    should_exit_nonzero = report_findings(findings, args.severity)
    sys.exit(1 if should_exit_nonzero else 0)


if __name__ == "__main__":
    main()