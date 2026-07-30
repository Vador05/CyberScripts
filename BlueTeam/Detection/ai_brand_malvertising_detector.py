"""AI-Brand Malvertising & SectopRAT Staging Detector.

Parses plain-text proxy or DNS resolver logs for malvertising campaign indicators
targeting AI-brand impersonation — detecting typosquat domains, Bing ad referrer
chains, and SectopRAT staging patterns across three kill-chain stages.

Usage:
    python ai_brand_malvertising_detector.py proxy.log
    python ai_brand_malvertising_detector.py dns.log --iocs extra.json --severity high
"""
import argparse, json, re, sys
from pathlib import Path

SEV = {"low": 0, "medium": 1, "high": 2}

RULES = [
    ("Delivery","medium","ai_typosquat_domain","url",r"(?:claud[e3]|c1aud[e3]?|ch[a4]{1,2}tgpt|m[i1]djourney?|gern1ni|gem[i1]{2}ni|c[o0]p[i1]l[o0]t)[.\-](?:com|net|io|app|ai|site|online|xyz|store|top)","Block domain at DNS/proxy and submit to AI vendor abuse team"),
    ("Delivery","high","ai_typosquat_hyphen","url",r"(?:claude|chatgpt|midjourney|gemini|copilot)-(?:ai|app|login|official|download|free|pro|plus|studio|api)\.(?:com|net|io|app|site|online|xyz|store)","Add hyphen-variant lookalike to URL filtering blocklist"),
    ("Delivery","medium","bing_ad_referrer","referrer",r"bing\.com/aclk|msn\.com/.*(?:adurl|redirect)|bingads\.microsoft\.com","Capture full referrer chain and correlate with endpoint browser history"),
    ("Delivery","medium","bing_ad_param_redirect","url",r"bing\.com/aclk\?|bat\.bing\.com/action|go\.microsoft\.com/fwlink.*adid=","Report full ad-click URL to Microsoft Advertising abuse portal"),
    ("InstallerDrop","high","ai_installer_path","url",r"(?:AI[-_]tool[-_]?setup|Model[-_]installer|(?:claude|chatgpt|midjourney|gemini|copilot)[-_]?(?:setup|installer|client))(?:[-_v][\d.]+)?\.(?:msi|exe|zip)","Quarantine file, collect SHA-256 hash, and submit to sandbox"),
    ("InstallerDrop","high","nsis_innosetup_ua","useragent",r"NSIS_Inetc|InnoSetup|InnoDownload|Mozilla/[\d.]+ \(NSIS\)","Isolate host, preserve memory image, and initiate IR playbook"),
    ("InstallerDrop","high","exe_from_lookalike","url",r"(?:claude|chatgpt|midjourney|gemini|copilot)[^/]{0,30}\.[a-z]{2,10}/.*\.(?:exe|msi|zip|bat|ps1)","Block URL at proxy, alert endpoint AV team, and escalate to IR"),
    ("C2Staging","high","sectoprat_gate_path","url",r"/(?:gate\.php|api/v[12]/(?:update|check|ping|beacon|init)|panel/gate|connect\.php)\?","Block C2 endpoint at perimeter and capture PCAP for forensic review"),
    ("C2Staging","high","c2_base64_param","url",r"\?[a-z_]{1,16}=[A-Za-z0-9+/]{20,}={0,2}(?:&|$|\s)","Decode base64 beacon payload and pivot on C2 infrastructure"),
    ("C2Staging","medium","c2_staging_path","url",r"/(?:gate|connect|panel|update|task|cmd)\.[a-z]{2,4}(?:\?|$)","Correlate URI pattern with SectopRAT campaign IOCs from threat-intel feeds"),
]

LOG_RE = re.compile(
    r"(?:(?P<ts>\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)\s+)?"
    r"(?P<src>\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?|[a-zA-Z0-9._-]{3,})\s+"
    r"(?:[A-Z]{2,7}\s+)?"
    r"(?P<url>https?://\S+|[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}(?:/\S*)?)"
    r"(?:.*?\s(?P<ref>https?://\S+))?"
    r'(?:.*?"(?P<ua>[^"]{5,})")?',
    re.I,
)


def parse_log_entries(path):
    try:
        lines = Path(path).read_text(errors="replace").splitlines()
    except OSError as e:
        sys.exit(f"ERROR reading log: {e}")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = LOG_RE.search(line)
        if not m:
            continue
        yield {
            "ts": m.group("ts") or "",
            "src": (m.group("src") or "unknown").split(":")[0],
            "url": m.group("url") or "",
            "referrer": m.group("ref") or "",
            "useragent": m.group("ua") or "",
        }


def load_iocs(path):
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"ERROR loading IOCs: {e}")
    extra = []
    for items in data.values():
        for e in (items if isinstance(items, list) else [items]):
            pattern = e.get("pattern", "(?!)")
            try:
                re.compile(pattern)
            except re.error as re_err:
                sys.exit(f"ERROR compiling pattern '{e.get('name', 'unknown')}': {re_err}")
            extra.append((e.get("stage", "Delivery"), e.get("severity", "medium"),
                          e.get("name", "custom_ioc"), e.get("field", "url"),
                          pattern,
                          e.get("action", "Investigate and escalate per IR playbook")))
    return extra


def match_indicators(entries, rules, min_sev):
    seen = set()
    for entry in entries:
        for stage, sev, name, field, pattern, action in rules:
            if SEV.get(sev, 0) < SEV[min_sev]:
                continue
            text = entry.get(field, "")
            key = (entry["src"], name)
            if not text or key in seen:
                continue
            if re.search(pattern, text, re.I):
                seen.add(key)
                yield {"stage": stage, "sev": sev, "name": name,
                       "src": entry["src"], "indicator": text[:120], "action": action}


def report_findings(findings):
    stage_counts, src_ips, peak, any_high, any_installer = {}, set(), "low", False, False
    for h in findings:
        sev_label = f"[{h['sev'].upper():6s}]"
        print(f"{sev_label} [{h['stage']:13s}] {h['name']:30s} src={h['src']}")
        print(f"           indicator : {h['indicator']}")
        print(f"           ACTION    : {h['action']}")
        stage_counts[h["stage"]] = stage_counts.get(h["stage"], 0) + 1
        src_ips.add(h["src"])
        if SEV.get(h["sev"], 0) > SEV.get(peak, 0):
            peak = h["sev"]
        any_high |= h["sev"] == "high"
        any_installer |= h["stage"] == "InstallerDrop"
    print("\n" + "=" * 70)
    print(f"SUMMARY | Unique source IPs: {len(src_ips)} | Peak severity: {peak.upper()}")
    for stage in ("Delivery", "InstallerDrop", "C2Staging"):
        if stage in stage_counts:
            print(f"  {stage:15s}: {stage_counts[stage]} hit(s)")
    if any_installer:
        print("NOTE: Pull binary hashes from proxy cache and submit to sandboxing platform.")
    if not stage_counts:
        print("  No indicators matched at the specified severity threshold.")
    return 1 if any_high else 0


def main():
    ap = argparse.ArgumentParser(description="AI-Brand Malvertising & SectopRAT Staging Detector")
    ap.add_argument("log_file", help="Proxy, DNS resolver, or browser history export (one entry per line)")
    ap.add_argument("--iocs", metavar="FILE", help="Supplemental JSON file with extra detection rules")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum alert severity to emit (default: low)")
    args = ap.parse_args()
    rules = RULES + (load_iocs(args.iocs) if args.iocs else [])
    entries = list(parse_log_entries(args.log_file))
    if not entries:
        print("WARNING: No parseable log entries found.", file=sys.stderr)
    sys.exit(report_findings(list(match_indicators(entries, rules, args.severity))))


if __name__ == "__main__":
    main()