"""PeopleSoft CVE-2026-35273 Hunt Rule Generator.

Scans plain-text PeopleSoft access/app logs for exploitation indicators
attributed to ShinyHunters TTPs and emits Sigma-compatible detection rules.

Usage:
    python peoplesoft_hunt_rule_gen.py access.log --mode both --threshold 3
    python peoplesoft_hunt_rule_gen.py app.log --mode sigma --threshold 1
    python peoplesoft_hunt_rule_gen.py app.log --mode guide
"""
import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

IOC_PATTERNS = {
    "uri_traversal": re.compile(
        r'(?:GET|POST|PUT)\s+(?:/psc/[^/]+/[^/]+/[^/]+/[^?\s]*\.\./|'
        r'/psp/[^/]+/[^?\s]*(?:%2e%2e|\.\.)[^?\s]*)', re.IGNORECASE),
    "auth_bypass_endpoint": re.compile(
        r'(?:GET|POST)\s+/psc/[^/]+/(?:WEBLIB_|PTAJAX|PT_DIAGNOSTICS)[^\s]*', re.IGNORECASE),
    "bulk_export": re.compile(
        r'(?:GET|POST)\s+/psc/[^/]+/[^\s]*(?:PTQRYSVC|PSQUERY|AE_RUN|'
        r'RUNCTL_PRCSRQST|PRCS_RUN_CNTL)[^\s]*', re.IGNORECASE),
    "credential_stuffing": re.compile(
        r'POST\s+/psp/[^/]+/[^\s]*(?:signonprocesscontrol|signon\.html)[^\n]*(?:40[13]|failed|invalid)',
        re.IGNORECASE),
    "shiny_ua": re.compile(
        r'(?:python-requests/|Go-http-client/|curl/[0-9]|axios/|okhttp/|libwww-perl/)', re.IGNORECASE),
    "ssrf_probe": re.compile(
        r'(?:GET|POST)\s+/psc/[^/]+/[^\s]*(?:url=|redirect=|next=)(?:https?://|//)[^\s]+', re.IGNORECASE),
    "admin_escalation": re.compile(
        r'(?:GET|POST)\s+/psc/[^/]+/(?:EMPLOYEE|CUSTOMER)/[^\s]*(?:USERMAINT|ROLEDEFN|PERMLISTMAINT)[^\s]*',
        re.IGNORECASE),
}

MITRE = {
    "uri_traversal": "T1190", "auth_bypass_endpoint": "T1190", "bulk_export": "T1530",
    "credential_stuffing": "T1078", "shiny_ua": "T1190", "ssrf_probe": "T1190", "admin_escalation": "T1078",
}

# Maps technique ID to its primary ATT&CK tactic tag for Sigma metadata.
_TECHNIQUE_TACTIC = {
    "T1190": "attack.initial_access",
    "T1078": "attack.initial_access",
    "T1530": "attack.collection",
}


def parse_logs(path: str, threshold: int) -> dict:
    hits: dict = defaultdict(int)
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                for name, pat in IOC_PATTERNS.items():
                    if pat.search(line):
                        hits[name] += 1
    except OSError as exc:
        print(f"[ERROR] Cannot read log file: {exc}", file=sys.stderr)
        sys.exit(1)
    return {k: v for k, v in hits.items() if v >= threshold}


def emit_sigma_rule(hits: dict) -> None:
    if not hits:
        print("# No patterns met the threshold — no Sigma rule generated.")
        return

    technique_tags = sorted({f"attack.{MITRE[k]}" for k in hits})
    tactic_tags = sorted({_TECHNIQUE_TACTIC[MITRE[k]] for k in hits if MITRE.get(k) in _TECHNIQUE_TACTIC})
    tags = technique_tags + tactic_tags

    kw: list = []
    if "uri_traversal" in hits or "auth_bypass_endpoint" in hits:
        kw += ["        - '/psc/'", "        - '../'", "        - '%2e%2e'"]
    if "bulk_export" in hits:
        kw += ["        - 'PTQRYSVC'", "        - 'PSQUERY'", "        - 'AE_RUN'"]
    if "credential_stuffing" in hits:
        kw.append("        - 'signonprocesscontrol'")
    if "shiny_ua" in hits:
        kw += ["        - 'python-requests'", "        - 'Go-http-client'"]
    if "ssrf_probe" in hits:
        kw += ["        - 'url=http://'", "        - 'url=https://'",
               "        - 'redirect=http://'", "        - 'redirect=https://'"]
    if "admin_escalation" in hits:
        kw += ["        - 'USERMAINT'", "        - 'ROLEDEFN'"]

    ts = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    nl = "\n"
    print(f"""title: PeopleSoft CVE-2026-35273 ShinyHunters Exploitation
id: ps-cve-2026-35273-shinyhunters
status: experimental
description: Detects CVE-2026-35273 auth-bypass and data-exfil patterns attributed to ShinyHunters.
references:
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-35273
author: peoplesoft_hunt_rule_gen
date: {ts}
tags:
{nl.join(f'    - {t}' for t in tags)}
logsource:
    category: webserver
    product: peoplesoft
detection:
    keywords:
{nl.join(kw)}
    condition: keywords
falsepositives:
    - Legitimate admin bulk-export workflows
    - Automated integration middleware
level: high""")


def emit_hunting_guide(hits: dict) -> None:
    sep = "=" * 60
    print(sep)
    print("ShinyHunters / CVE-2026-35273 PeopleSoft Hunting Guide")
    print(sep)
    print(f"\nGenerated : {datetime.now(timezone.utc).isoformat()}")
    print(f"IOC hits above threshold: {len(hits)}\n")
    print(f"  {'Pattern':<28} {'Hits':>6}  MITRE")
    print(f"  {'-'*28} {'------':>6}  ------")
    for name, count in sorted(hits.items(), key=lambda x: -x[1]):
        print(f"  {name:<28} {count:>6}  {MITRE.get(name, 'N/A')}")
    print("\nStep 1 — SCOPE")
    print("  1a. Identify IPs firing >10 reqs in 60s windows.")
    print("  1b. Cross-reference with ShinyHunters ASN / IP blocklists.")
    print("  1c. Capture full request/response pairs for flagged IPs.")
    print("\nStep 2 — PIVOT QUERIES (Splunk examples)")
    if "uri_traversal" in hits or "auth_bypass_endpoint" in hits:
        print('  Auth-bypass: index=weblog uri="/psc/*" (uri="*../*" OR uri="*%2e%2e*")')
    if "bulk_export" in hits:
        print('  Bulk-export: index=weblog uri IN ("*PTQRYSVC*","*AE_RUN*","*PSQUERY*")')
    if "credential_stuffing" in hits:
        print('  Cred-stuff:  index=weblog uri="*signonprocesscontrol*" status IN (401,403)')
    if "shiny_ua" in hits:
        print('  Scraper UA:  index=weblog useragent IN ("python-requests*","Go-http-client*")')
    if "admin_escalation" in hits:
        print('  Priv-esc:    index=weblog uri IN ("*USERMAINT*","*ROLEDEFN*")')
    print("\nStep 3 — CONTAINMENT CHECKLIST")
    for item in ["Block offending IPs at perimeter WAF.",
                 "Rotate PeopleSoft service-account credentials.",
                 "Apply vendor patch or enable auth workaround for CVE-2026-35273.",
                 "Enable PIA lockout policy (max 5 failed logins).",
                 "Audit recently created/modified user accounts and roles.",
                 "Preserve raw logs to immutable storage for chain-of-custody."]:
        print(f"  [ ] {item}")
    print("\nStep 4 — ESCALATION")
    print("  Bulk-export or admin-escalation confirmed -> declare incident,")
    print("  notify DPO/legal, engage IR for memory forensics on app-tier hosts.")
    print(sep)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Generate Sigma rules/hunting guide for CVE-2026-35273.",
        epilog="Example: python peoplesoft_hunt_rule_gen.py access.log --mode both --threshold 3")
    ap.add_argument("log_file", help="Path to plain-text PeopleSoft access/app log")
    ap.add_argument("--mode", choices=["sigma", "guide", "both"], default="both")
    ap.add_argument("--threshold", type=int, default=3, help="Min hit count (default: 3)")
    args = ap.parse_args()
    if args.threshold < 1:
        print("[ERROR] --threshold must be >= 1", file=sys.stderr)
        sys.exit(1)
    try:
        hits = parse_logs(args.log_file, args.threshold)
        if args.mode in ("sigma", "both"):
            emit_sigma_rule(hits)
        if args.mode in ("guide", "both"):
            emit_hunting_guide(hits)
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)


if __name__ == "__main__":
    main()