"""Fake Job Interview Phishing & OAuth Lure Lab.

Parses plain-text email header dumps for indicators of multi-brand fake job interview
phishing campaigns, labeling each finding with a kill-chain stage and mitigation.

Usage:
    python fake_job_lure_phishing_lab.py headers.txt
    python fake_job_lure_phishing_lab.py headers.txt --patterns extra_iocs.json --severity high
"""
import argparse, json, re, sys
from pathlib import Path

BRANDS = ["linkedin", "indeed", "glassdoor", "workday", "greenhouse"]
FREE = re.compile(r"@(?:gmail|yahoo|hotmail|outlook|protonmail|zoho)\.", re.I)
LOOKALIKE = re.compile(
    r"(?:1inkedin|linkedln|lnkd1n|ind33d|g1assdoor|workd4y|linkedin-jobs|indeed-careers)[\.\-@]", re.I
)
URGENCY = re.compile(
    r"urgent|immediate|action required|interview scheduled|offer expires|last chance|24.hour|respond now", re.I
)
OAUTH_REDIR = re.compile(
    r"redirect_uri=https?://(?!(?:linkedin|indeed|glassdoor|workday|greenhouse|microsoft|google)\.com)[^\s&\"']+", re.I
)
IMPLICIT = re.compile(r"response_type=token", re.I)
ABUSED_CID = re.compile(
    r"client_id=(?:1fec8e78-bce4-4aaf-ab1b-5451cc387264|04b07795-8ddb-461a-bbee-02f9e1bf7b46)", re.I
)
MITIGATIONS = {
    "from_reply_mismatch":        ("Delivery",          "high",   "Enforce DMARC reject policy and verify sender identity"),
    "free_provider_impersonation":("Delivery",          "medium", "Block sender domain at mail gateway"),
    "spf_dkim_dmarc_fail":        ("Delivery",          "high",   "Quarantine message and report to abuse@domain"),
    "lookalike_domain":           ("Delivery",          "high",   "Add lookalike domain to URL filtering blocklist"),
    "urgency_subject":            ("SocialEngineering", "medium", "Flag for user-awareness training campaign"),
    "geo_hop_mismatch":           ("SocialEngineering", "medium", "Cross-reference with SIEM geo-enrichment logs"),
    "oauth_redirect_lure":        ("TokenTheft",        "high",   "Revoke OAuth app consent in IdP admin portal"),
    "implicit_flow_token":        ("TokenTheft",        "high",   "Disable implicit grant flow in OAuth policy"),
    "abused_client_id":           ("TokenTheft",        "high",   "Block client_id in conditional-access policy"),
}
SEV = {"low": 0, "medium": 1, "high": 2}


def parse_blocks(path):
    try:
        text = Path(path).read_text(errors="replace")
    except OSError as e:
        sys.exit(f"ERROR: {e}")
    blocks, cur = [], []
    for line in text.splitlines():
        if line.strip():
            cur.append(line)
        elif cur:
            blocks.append("\n".join(cur))
            cur = []
    if cur:
        blocks.append("\n".join(cur))
    return blocks


def get_hdr(block, name):
    m = re.search(rf"^{name}:\s*(.+)", block, re.I | re.M)
    return m.group(1).strip() if m else ""


def domain_of(addr):
    m = re.search(r"@([\w.\-]+)", addr)
    return m.group(1).lower() if m else ""


def match_rules(block, extra):
    frm = get_hdr(block, "From")
    rto = get_hdr(block, "Reply-To")
    subj = get_hdr(block, "Subject")
    auth = get_hdr(block, "Authentication-Results")
    body = get_hdr(block, "body")
    recvd = " ".join(re.findall(r"^Received:\s*(.+)", block, re.I | re.M))
    fd, rd = domain_of(frm), domain_of(rto)
    hits = []

    if rto and fd and rd and fd != rd:
        hits.append(("from_reply_mismatch", f"From={fd} Reply-To={rd}"))
    if FREE.search(frm) and any(b in frm.lower() for b in BRANDS):
        hits.append(("free_provider_impersonation", frm[:120]))
    if auth and re.search(r"spf=fail|dkim=fail|dmarc=fail", auth, re.I):
        hits.append(("spf_dkim_dmarc_fail", auth[:120]))
    for fld in (frm, rto):
        if fld and LOOKALIKE.search(fld):
            hits.append(("lookalike_domain", fld[:120]))
            break
    for pat in extra.get("lookalike_domains", []):
        if pat.lower() in frm.lower() or pat.lower() in rto.lower():
            hits.append(("lookalike_domain", f"supplemental:{pat}"))
    if subj and URGENCY.search(subj):
        hits.append(("urgency_subject", subj[:120]))
    if fd and any(b in fd for b in BRANDS) and recvd and not any(b in recvd.lower() for b in BRANDS):
        hits.append(("geo_hop_mismatch", recvd[:120]))
    if body:
        m = OAUTH_REDIR.search(body)
        if m:
            hits.append(("oauth_redirect_lure", m.group(0)[:120]))
        if IMPLICIT.search(body):
            hits.append(("implicit_flow_token", body[:120]))
        m2 = ABUSED_CID.search(body)
        if m2:
            hits.append(("abused_client_id", m2.group(0)[:120]))
        for pat in extra.get("oauth_redirect_fragments", []):
            if pat.lower() in body.lower():
                hits.append(("oauth_redirect_lure", f"supplemental:{pat}"))
    return hits


def main():
    ap = argparse.ArgumentParser(
        description="Detect fake-job-interview phishing indicators in email header dumps.",
        epilog="Example: python fake_job_lure_phishing_lab.py headers.txt --severity medium",
    )
    ap.add_argument("log_file", help="Path to plain-text email header dump")
    ap.add_argument("--patterns", help="JSON file with supplemental IOC patterns")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low")
    args = ap.parse_args()

    extra = {}
    if args.patterns:
        try:
            extra = json.loads(Path(args.patterns).read_text())
        except (OSError, json.JSONDecodeError) as e:
            sys.exit(f"ERROR: cannot load patterns: {e}")

    min_sev = SEV[args.severity]
    seen, counts, peak, any_high = set(), {"Delivery": 0, "SocialEngineering": 0, "TokenTheft": 0}, "low", False

    for block in parse_blocks(args.log_file):
        mid = get_hdr(block, "Message-ID") or block[:40]
        for rule, indicator in match_rules(block, extra):
            stage, sev, mitigation = MITIGATIONS[rule]
            if SEV[sev] < min_sev or (mid, rule) in seen:
                continue
            seen.add((mid, rule))
            print(f"[{sev.upper():6}] {stage:20} {rule:30} | {indicator[:60]:60} | {mitigation}")
            counts[stage] += 1
            if SEV[sev] > SEV[peak]:
                peak = sev
            if sev == "high":
                any_high = True

    print("\n--- Summary ---")
    for stage, n in counts.items():
        print(f"  {stage}: {n} hit(s)")
    print(f"  Peak severity: {peak.upper()}")
    if counts["TokenTheft"]:
        print("  [!] TokenTheft hits detected — audit OAuth consent logs immediately")
    sys.exit(1 if any_high else 0)


if __name__ == "__main__":
    main()