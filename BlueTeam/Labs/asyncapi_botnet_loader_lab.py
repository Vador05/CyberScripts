"""
AsyncAPI Compromised Package Botnet Loader Chain Lab & Signature Generator

Scans npm install logs, audit output, or postinstall hook execution traces for the
three-stage @asyncapi supply-chain compromise chain and emits YARA rules and npm overrides.

Usage:
    python asyncapi_botnet_loader_lab.py install.log
    python asyncapi_botnet_loader_lab.py npm-debug.log --iocs extra_iocs.json --severity medium
    python asyncapi_botnet_loader_lab.py postinstall.log --severity high
"""
import argparse, json, re, sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
REGISTRY_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com", "npmjs.com", "yarnpkg.com"}
SKIP_RE = re.compile(r"^\s*(?:[\u2800-\u28ff⠿]|npm WARN|npm timing|npm http 304|[▐▌])", re.U)

ASYNCAPI_PKGS = {
    "@asyncapi/parser", "@asyncapi/generator", "@asyncapi/cli", "@asyncapi/studio",
    "@asyncapi/modelina", "@asyncapi/bundler", "@asyncapi/diff", "@asyncapi/optimizer",
}
COMPROMISED_VERSIONS = re.compile(r"\b(0\.0\.\d+|9{1,3}\.\d+\.\d+|6{3,}\.\d+\.\d+)\b")
LOADER_EXTS = re.compile(r"\.(sh|bin|exe|elf|py|ps1)\b", re.I)
C2_DOMAINS = {
    "cdn-bootstrap.net", "npmpackage.live", "pkg-update.xyz", "registry-mirror.cc",
    "wallet-harvest.io", "npm-stats.cc", "exfil-pipe.io", "pastebin.com",
    "ngrok.io", "requestbin.com", "webhook.site", "asyncapi-cdn.net",
}
DGA_RE = re.compile(r"\b([a-z0-9]{8,16}\.[a-z]{2,4})\b")
B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")
HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
PKG_RE = re.compile(r"(?:added|installing|postinstall)[:\s]+((?:@[\w\-]+/)?[\w\-\.]+)@([\d][\w\.\-]*)", re.I)
HOST_RE = re.compile(r"(?:https?://|(?:fetch|curl|wget|GET|POST)\s+(?:https?://)?)([a-zA-Z0-9][\w\-\.]*\.[a-zA-Z]{2,})", re.I)
CHMOD_SPAWN_RE = re.compile(r"\b(?:chmod|execSync|spawn|exec|child_process)\b.*?(?:\.sh|\.bin|\.exe)\b", re.I)
ENV_EXFIL_RE = re.compile(r"process\.env\b.*(?:pipe|curl|fetch|POST|send)", re.I)

STAGE_RULES = {
    "PackageInject": [
        ("AsyncAPIKnownPkg",    lambda e: any(e["raw"].find(p) != -1 for p in ASYNCAPI_PKGS), "medium"),
        ("CompromisedVersion",  lambda e: bool(COMPROMISED_VERSIONS.search(e["raw"])), "high"),
        ("PostinstallPresent",  lambda e: "postinstall" in e["raw"].lower() and e["pkg"] and e["pkg"].startswith("@asyncapi"), "medium"),
        ("ObfuscatedBase64",    lambda e: bool(B64_RE.search(e["raw"])), "high"),
        ("ObfuscatedHex",       lambda e: bool(HEX_RE.search(e["raw"])), "high"),
    ],
    "LoaderFetch": [
        ("OutboundFetch",       lambda e: bool(HOST_RE.search(e["raw"])) and bool(set(e["hosts"]) - REGISTRY_HOSTS), "high"),
        ("ExecutableDownload",  lambda e: bool(LOADER_EXTS.search(e["raw"])) and bool(HOST_RE.search(e["raw"])), "high"),
        ("ChmodSpawnSequence",  lambda e: bool(CHMOD_SPAWN_RE.search(e["raw"])), "high"),
    ],
    "C2Beacon": [
        ("KnownC2Domain",       lambda e: bool(set(e["hosts"]) & e["c2_domains"]), "high"),
        ("DGADomain",           lambda e: bool(DGA_RE.search(e["raw"])) and not any(h in REGISTRY_HOSTS for h in e["hosts"]), "medium"),
        ("EnvVarExfil",         lambda e: bool(ENV_EXFIL_RE.search(e["raw"])), "high"),
    ],
}


def load_iocs(path):
    try:
        data = json.loads(Path(path).read_text())
        return set(data.get("c2_domains", [])), set(data.get("package_names", [])), data.get("loader_urls", [])
    except Exception as exc:
        print(f"[WARN] IOC load failed {path}: {exc}", file=sys.stderr)
        return set(), set(), []


def redact_secrets(line):
    patterns = [
        (r'_authToken=[^\s&]+', '_authToken=***'),
        (r'npm_token=[^\s]+', 'NPM_TOKEN=***'),
        (r'NPM_TOKEN=[^\s]+', 'NPM_TOKEN=***'),
        (r'Authorization:\s+Bearer\s+[^\s]+', 'Authorization: Bearer ***'),
        (r'token=[^\s&]+', 'token=***'),
        (r'api[_-]?key=[^\s&]+', 'api_key=***'),
        (r'password=[^\s&]+', 'password=***'),
        (r'secret=[^\s&]+', 'secret=***'),
        (r'ghp_[a-zA-Z0-9]+', 'ghp_***'),
        (r'github_pat_[a-zA-Z0-9]+', 'github_pat_***'),
        (r'AWS_SECRET_ACCESS_KEY=[^\s]+', 'AWS_SECRET_ACCESS_KEY=***'),
        (r'AWS_ACCESS_KEY_ID=[^\s]+', 'AWS_ACCESS_KEY_ID=***'),
        (r'(https?://)([^:@\s]+):([^:@\s]+)@', r'\1***:***@'),
    ]
    result = line
    for pattern, replacement in patterns:
        result = re.sub(pattern, replacement, result, flags=re.I)
    return result


def parse_entry(line, c2_domains):
    raw = unquote(line.rstrip())
    m = PKG_RE.search(raw)
    hosts = HOST_RE.findall(raw)
    return {"pkg": f"{m.group(1)}@{m.group(2)}" if m else None,
            "hosts": hosts, "raw": raw, "c2_domains": c2_domains | C2_DOMAINS}


def escape_yara_string(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def emit_yara(url_patterns, hash_patterns):
    rules = []
    for i, url in enumerate(url_patterns):
        escaped_url = escape_yara_string(url)
        safe = re.sub(r"[^\w]", "_", url)[:40]
        rules.append(f'rule AsyncAPI_Loader_{safe}_{i} {{\n  meta:\n    stage = "LoaderFetch"\n    severity = "high"\n    source = "asyncapi_botnet_loader_lab"\n  strings:\n    $url = "{escaped_url}" nocase\n  condition:\n    $url\n}}')
    for i, h in enumerate(hash_patterns):
        escaped_h = escape_yara_string(h)
        rules.append(f'rule AsyncAPI_Hash_{h[:16]}_{i} {{\n  meta:\n    stage = "PackageInject"\n    severity = "high"\n  strings:\n    $h = "{escaped_h}" nocase\n  condition:\n    $h\n}}')
    return rules


def emit_overrides(pkgs):
    overrides = {}
    for pkg in pkgs:
        name = pkg.rsplit("@", 1)[0] if "@" in pkg else pkg
        overrides[name] = "latest"
    return overrides


def main():
    ap = argparse.ArgumentParser(description="AsyncAPI Botnet Loader Chain Lab & Signature Generator")
    ap.add_argument("log_file", help="Path to npm install log, audit output, or postinstall hook trace")
    ap.add_argument("--iocs", help="Path to supplemental JSON IOC file")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low", help="Minimum severity to emit (default: low)")
    args = ap.parse_args()

    extra_c2, extra_pkgs, extra_urls = load_iocs(args.iocs) if args.iocs else (set(), set(), [])
    min_sev = SEVERITY_RANK[args.severity]

    try:
        lines = Path(args.log_file).read_text(errors="replace").splitlines()
    except OSError as exc:
        print(f"[ERROR] Cannot read log: {exc}", file=sys.stderr); sys.exit(2)

    counts = {s: 0 for s in STAGE_RULES}
    seen, loader_urls, hash_hits, bad_pkgs = set(), set(extra_urls), set(), set()
    peak = "low"; has_high = False
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for line in lines:
        if SKIP_RE.match(line) or not line.strip():
            continue
        entry = parse_entry(line, extra_c2)
        for stage, rules in STAGE_RULES.items():
            for rule_name, fn, sev in rules:
                if SEVERITY_RANK[sev] < min_sev:
                    continue
                try:
                    hit = fn(entry)
                except Exception:
                    hit = False
                if not hit:
                    continue
                key = (stage, rule_name, entry["pkg"] or "", entry["raw"][:80])
                if key in seen:
                    continue
                seen.add(key)
                counts[stage] += 1
                if SEVERITY_RANK[sev] > SEVERITY_RANK[peak]:
                    peak = sev
                if sev == "high":
                    has_high = True
                pkg_id = entry["pkg"] or "unknown"
                if stage == "PackageInject" and entry["pkg"]:
                    bad_pkgs.add(entry["pkg"])
                if stage == "LoaderFetch":
                    for h in entry["hosts"]:
                        if h not in REGISTRY_HOSTS:
                            loader_urls.add(h)
                if stage in ("PackageInject", "LoaderFetch"):
                    for hx in HEX_RE.findall(entry["raw"]):
                        if len(hx) >= 32:
                            hash_hits.add(hx)
                print(f"[{ts}] ALERT stage={stage} sev={sev} rule={rule_name} pkg={pkg_id} | {redact_secrets(entry['raw'])[:120]}")

    yara_rules = emit_yara(list(loader_urls), list(hash_hits))
    for rule in yara_rules:
        print("\n" + rule)

    if bad_pkgs:
        print("\n// npm overrides JSON stanza:")
        print(json.dumps({"overrides": emit_overrides(bad_pkgs)}, indent=2))

    print(f"\n=== Summary === stage_hits={dict(counts)} yara_rules={len(yara_rules)} overrides={len(bad_pkgs)} peak_severity={peak}")
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()