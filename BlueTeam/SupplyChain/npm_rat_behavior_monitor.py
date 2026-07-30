"""
npm RAT Behavior & Exfiltration Monitor

Scans npm postinstall hook execution traces or install logs for credential
exfiltration and rogue outbound network callbacks characteristic of supply-chain RATs.

Usage:
    python npm_rat_behavior_monitor.py install.log
    python npm_rat_behavior_monitor.py postinstall.log --iocs extra_iocs.json --severity medium
    python npm_rat_behavior_monitor.py npm-debug.log --severity high
"""
import argparse, json, re, sys
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

KEY_EXFIL_RULES = [
    ("CredEnvAWS",     re.compile(r"\bAWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)\b"), "high"),
    ("CredEnvGitHub",  re.compile(r"\b(?:GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|NPM_TOKEN)\b"), "high"),
    ("CredEnvGeneric", re.compile(r"\b\w*(?:API_KEY|SECRET|PASSWORD|PRIVATE_KEY|AUTH_TOKEN)\w*\b", re.I), "high"),
    ("CredFileNpmrc",  re.compile(r"\.npmrc\b"), "high"),
    ("CredFileEnv",    re.compile(r"(?<!\w)\.env\b"), "high"),
    ("CredFileSSH",    re.compile(r"\.ssh[/\\](?:id_rsa|id_ed25519|credentials|config)\b", re.I), "high"),
    ("CredFileAWS",    re.compile(r"\.aws[/\\]credentials\b", re.I), "high"),
    ("ProcessEnv",     re.compile(r"\bprocess\.env\b"), "medium"),
    ("TokenAccess",    re.compile(r"\b\w*TOKEN\w*\b", re.I), "low"),
]

C2_DOMAINS = {
    "cdn-bootstrap.net", "npmpackage.live", "pkg-update.xyz", "registry-mirror.cc",
    "wallet-harvest.io", "crypto-exfil.ru", "npm-stats.cc", "exfil-pipe.io",
    "pastebin.com", "ngrok.io", "requestbin.com", "webhook.site",
}
C2_IPS = {
    "185.220.101.45", "45.142.212.100", "194.165.16.11",
    "91.108.4.0", "77.91.68.0", "5.188.206.0",
}
REGISTRY_HOSTS = {
    "registry.npmjs.org", "registry.yarnpkg.com", "npmjs.com", "yarnpkg.com", "npmjs.org",
}

PKG_RE = re.compile(r"(?:added|installing|postinstall)[:\s]+([\w\-\.@/]+)@(\d[\w.\-]+)", re.I)
HOST_RE = re.compile(r"(?:https?://|(?:GET|POST|fetch|curl|wget|connect)\s+(?:https?://)?)([a-zA-Z0-9][\w\-.]*\.[a-zA-Z]{2,})", re.I)
IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def load_iocs(path):
    try:
        data = json.loads(Path(path).read_text())
        return (
            set(data.get("c2_domains", [])),
            set(data.get("c2_ips", [])),
            data.get("env_patterns", []),
            set(data.get("allowed_hosts", [])),
        )
    except Exception as exc:
        print(f"[WARN] Failed to load IOCs from {path}: {exc}", file=sys.stderr)
        return set(), set(), [], set()


def parse_log_entries(log_path):
    current_pkg = None
    try:
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.rstrip()
                m = PKG_RE.search(line)
                if m:
                    current_pkg = f"{m.group(1)}@{m.group(2)}"
                yield {
                    "lineno": lineno,
                    "pkg": current_pkg,
                    "hosts": HOST_RE.findall(line),
                    "ips": IP_RE.findall(line),
                    "raw": line,
                }
    except OSError as exc:
        print(f"[ERROR] Cannot read log file: {exc}", file=sys.stderr)
        sys.exit(2)


def match_rules(entry, key_rules, c2_domains, c2_ips, registry_hosts, allowed_hosts):
    findings = []
    for rule_name, pattern, severity in key_rules:
        if pattern.search(entry["raw"]):
            findings.append(("KeyExfil", rule_name, severity))
    for host in entry["hosts"]:
        host_lower = host.lower()
        if host_lower in registry_hosts or host_lower in allowed_hosts:
            continue
        if host_lower in c2_domains:
            findings.append(("RogueNetwork", f"C2Domain:{host_lower}", "high"))
        else:
            findings.append(("RogueNetwork", f"UnknownOutbound:{host_lower}", "medium"))
    for ip in entry["ips"]:
        if ip in c2_ips:
            findings.append(("RogueNetwork", f"C2IP:{ip}", "high"))
    return findings


def report_findings(log_path, iocs_path, min_severity):
    extra_domains, extra_ips, extra_patterns, allowed_hosts = set(), set(), [], set()
    if iocs_path:
        extra_domains, extra_ips, extra_patterns, allowed_hosts = load_iocs(iocs_path)

    all_domains = C2_DOMAINS | extra_domains
    all_ips = C2_IPS | extra_ips

    extra_rules = [
        (f"CredEnvCustom:{p}", re.compile(rf"\b{re.escape(p)}\b", re.I), "high")
        for p in extra_patterns
    ]
    key_rules = KEY_EXFIL_RULES + extra_rules

    min_rank = SEVERITY_RANK[min_severity]
    seen = set()
    stage_counts = {"KeyExfil": 0, "RogueNetwork": 0}
    peak_severity = {"KeyExfil": "low", "RogueNetwork": "low"}
    any_high = False
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for entry in parse_log_entries(log_path):
        findings = match_rules(entry, key_rules, all_domains, all_ips, REGISTRY_HOSTS, allowed_hosts)
        for stage, rule_name, severity in findings:
            if SEVERITY_RANK[severity] < min_rank:
                continue
            dedup_key = (entry["pkg"], stage, rule_name)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            pkg_label = entry["pkg"] or "unknown"
            print(f"[{ts}] [{stage}] [{severity.upper()}] rule={rule_name} pkg={pkg_label} line={entry['lineno']}: {entry['raw']}")
            stage_counts[stage] += 1
            if SEVERITY_RANK[severity] > SEVERITY_RANK[peak_severity[stage]]:
                peak_severity[stage] = severity
            if severity == "high":
                any_high = True

    print("\n--- Summary ---")
    for stage in ("KeyExfil", "RogueNetwork"):
        print(f"  {stage}: {stage_counts[stage]} hit(s), peak severity={peak_severity[stage].upper()}")
    total = sum(stage_counts.values())
    print(f"  Total alerts: {total}")
    return any_high


def main():
    parser = argparse.ArgumentParser(
        description="Detect RAT-characteristic behavior in npm package lifecycle scripts."
    )
    parser.add_argument("log_file", help="Path to npm install log or postinstall hook execution trace")
    parser.add_argument("--iocs", metavar="FILE", help="JSON file with supplemental C2 domains/IPs, env-var patterns, and allowed hosts")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum alert level to emit (default: low)")
    args = parser.parse_args()

    if not Path(args.log_file).is_file():
        print(f"[ERROR] Log file not found: {args.log_file}", file=sys.stderr)
        sys.exit(2)

    any_high = report_findings(args.log_file, args.iocs, args.severity)
    sys.exit(1 if any_high else 0)


if __name__ == "__main__":
    main()