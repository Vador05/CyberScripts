"""
npm SDK Exfiltration & Rogue Network Call Monitor

Scans npm install logs, audit output, or postinstall hook execution traces for
credential harvesting and rogue outbound network calls across two kill-chain stages.

Usage:
    python sdk_exfil_monitor.py install.log
    python sdk_exfil_monitor.py npm-debug.log --iocs extra_iocs.json --severity medium
    python sdk_exfil_monitor.py postinstall.log --severity high
"""
import argparse, json, re, sys
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

KEY_EXFIL_RULES = [
    ("CredEnvAWS",     re.compile(r"\bAWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)\b"), "high"),
    ("CredEnvGitHub",  re.compile(r"\b(?:GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN)\b"), "high"),
    ("CredEnvGeneric", re.compile(r"\b\w*(?:API_KEY|SECRET|PASSWORD|PRIVATE_KEY|AUTH_TOKEN)\w*\b", re.I), "high"),
    ("CredFileNpmrc",  re.compile(r"\.npmrc\b"), "high"),
    ("CredFileEnv",    re.compile(r"(?<!\w)\.env\b"), "high"),
    ("CredFileSSH",    re.compile(r"\.ssh[/\\](?:id_rsa|id_ed25519|credentials|config)\b", re.I), "high"),
    ("CredFileAWS",    re.compile(r"\.aws[/\\]credentials\b", re.I), "high"),
    ("ProcessEnv",     re.compile(r"\bprocess\.env\b"), "medium"),
    ("TokenAccess",    re.compile(r"\b\w*TOKEN\w*\b", re.I), "low"),
]
C2_DOMAINS = {"cdn-bootstrap.net", "npmpackage.live", "pkg-update.xyz", "registry-mirror.cc",
               "wallet-harvest.io", "crypto-exfil.ru", "npm-stats.cc", "exfil-pipe.io",
               "pastebin.com", "ngrok.io", "requestbin.com", "webhook.site"}
C2_IPS = {"185.220.101.45", "45.142.212.100", "194.165.16.11", "91.108.4.0", "77.91.68.0", "5.188.206.0"}
REGISTRY_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com", "npmjs.com", "yarnpkg.com", "npmjs.org"}

PKG_RE = re.compile(r"(?:added|installing|postinstall)[:\s]+([\w\-\.@/]+)@([\d][\w\.\-]+)", re.I)
HOST_RE = re.compile(r"(?:https?://|(?:GET|POST|fetch|curl|wget|connect)\s+(?:https?://)?)([a-zA-Z0-9][\w\-\.]*\.[a-zA-Z]{2,})", re.I)
IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def load_iocs(path):
    try:
        data = json.loads(Path(path).read_text())
        return set(data.get("c2_domains", [])), set(data.get("c2_ips", [])), data.get("env_patterns", [])
    except Exception as e:
        print(f"[WARN] Failed to load IOCs from {path}: {e}", file=sys.stderr)
        return set(), set(), []


def parse_entry(line):
    m = PKG_RE.search(line)
    return {"pkg": f"{m.group(1)}@{m.group(2)}" if m else None,
            "hosts": HOST_RE.findall(line), "ips": IP_RE.findall(line), "raw": line.rstrip()}


def match_rules(entry, key_rules, rogue_domain_re, rogue_ip_re, registry_hosts):
    hits, line = [], entry["raw"]
    for name, pat, sev in key_rules:
        if pat.search(line):
            hits.append(("KeyExfil", name, sev))
    if rogue_domain_re and rogue_domain_re.search(line):
        hits.append(("RogueNetwork", "C2Domain", "high"))
    if rogue_ip_re and rogue_ip_re.search(line):
        hits.append(("RogueNetwork", "C2IP", "high"))
    for host in entry["hosts"]:
        b = host.lower()
        if not any(b == r or b.endswith("." + r) for r in registry_hosts):
            hits.append(("RogueNetwork", "NonRegistryHost", "medium"))
            break
    return hits


def fmt_alert(stage, sev, rule, pkg, line):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"[{ts}] {stage}/{sev.upper()} rule={rule}{' pkg=' + pkg if pkg else ''} | {line}"


def main():
    parser = argparse.ArgumentParser(description="npm SDK Exfiltration & Rogue Network Call Monitor")
    parser.add_argument("log_file", help="Path to npm install log or postinstall hook trace")
    parser.add_argument("--iocs", help="JSON file with additional C2 domains/IPs and env-var patterns")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum severity level to emit (default: low)")
    args = parser.parse_args()

    c2_domains, c2_ips = set(C2_DOMAINS), set(C2_IPS)
    registry_hosts, key_rules = set(REGISTRY_HOSTS), list(KEY_EXFIL_RULES)

    if args.iocs:
        extra_d, extra_i, extra_e = load_iocs(args.iocs)
        c2_domains |= extra_d
        c2_ips |= extra_i
        for p in extra_e:
            try:
                key_rules.append(("CustomEnv", re.compile(p, re.I), "high"))
            except re.error:
                print(f"[WARN] Invalid regex in --iocs env_patterns: {p}", file=sys.stderr)

    rogue_domain_re = re.compile(r"(?:" + "|".join(re.escape(d) for d in c2_domains) + r")", re.I) if c2_domains else None
    rogue_ip_re = re.compile(r"\b(?:" + "|".join(re.escape(ip) for ip in c2_ips) + r")\b") if c2_ips else None
    min_sev, seen = SEVERITY_RANK[args.severity], set()
    stage_hits, peak_sev, exit_code = {"KeyExfil": 0, "RogueNetwork": 0}, -1, 0

    try:
        log_lines = Path(args.log_file).read_text(errors="replace").splitlines()
    except OSError as e:
        print(f"[ERROR] Cannot read log file: {e}", file=sys.stderr)
        sys.exit(2)

    for line in log_lines:
        entry = parse_entry(line)
        for stage, rule, sev in match_rules(entry, key_rules, rogue_domain_re, rogue_ip_re, registry_hosts):
            if SEVERITY_RANK[sev] < min_sev:
                continue
            dk = (stage, rule, entry["pkg"], line[:80])
            if dk in seen:
                continue
            seen.add(dk)
            print(fmt_alert(stage, sev, rule, entry["pkg"], entry["raw"]))
            stage_hits[stage] += 1
            peak_sev = max(peak_sev, SEVERITY_RANK[sev])
            if sev == "high":
                exit_code = 1

    peak_label = next((k for k, v in SEVERITY_RANK.items() if v == peak_sev), "none")
    print("\n--- Summary ---")
    for stage, count in stage_hits.items():
        print(f"  {stage}: {count} hit(s)")
    print(f"  Peak severity: {peak_label.upper()}")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()