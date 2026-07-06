"""
npm Typosquat & Impersonator Detection Lab

Scans a package.json or npm install log for typosquatted and impersonator packages
using bigram-overlap similarity scoring and lifecycle script pattern matching.

Usage:
    python npm_typosquat_lab.py package.json
    python npm_typosquat_lab.py npm_install.log --threshold 0.75
    python npm_typosquat_lab.py package.json --baseline my_baseline.json
    echo $? # non-zero if any HIGH severity finding
"""

import argparse
import json
import re
import sys
from collections import defaultdict

POPULAR_PACKAGES = [
    "react","react-dom","lodash","express","axios","moment","webpack","babel-core",
    "typescript","jest","eslint","prettier","vue","angular","next","nuxt","gatsby",
    "redux","mobx","graphql","apollo","prisma","sequelize","mongoose","knex",
    "passport","bcrypt","jsonwebtoken","dotenv","cors","helmet","morgan","nodemon",
    "pm2","socket.io","ws","uuid","chalk","commander","yargs","inquirer","ora",
    "cheerio","puppeteer","playwright","selenium-webdriver","mocha","chai","sinon",
    "supertest","enzyme","testing-library","cypress","vitest","vite","rollup",
    "parcel","esbuild","swc","turbopack","lerna","nx","turborepo","pnpm","yarn",
    "npm","semver","glob","minimatch","chokidar","fs-extra","rimraf","mkdirp",
    "cross-env","concurrently","husky","lint-staged","commitizen","standard",
    "prettier","autoprefixer","postcss","tailwindcss","sass","less","styled-components",
    "emotion","material-ui","antd","bootstrap","bulma","foundation","semantic-ui",
    "d3","chart.js","three","pixi.js","phaser","tone","howler","sharp","jimp",
    "multer","formidable","busboy","stripe","twilio","sendgrid","nodemailer",
    "redis","ioredis","memcached","elasticsearch","neo4j","cassandra","firebase",
    "aws-sdk","azure","@google-cloud","pg","mysql","mysql2","sqlite3","better-sqlite3",
]

NETWORK_PATTERNS = [
    re.compile(r'\bcurl\b', re.I),
    re.compile(r'\bwget\b', re.I),
    re.compile(r'\bfetch\b', re.I),
    re.compile(r'https?://', re.I),
    re.compile(r'\bhttp\.get\b|\bhttp\.request\b', re.I),
    re.compile(r'\bnet\.connect\b|\bnet\.createConnection\b', re.I),
    re.compile(r'\bdns\.lookup\b|\bdns\.resolve\b', re.I),
    re.compile(r'\bnc\s+-', re.I),
    re.compile(r'\bbash\s+-i\b|\b/dev/tcp\b', re.I),
]

CREDENTIAL_PATTERNS = [
    re.compile(r'\bSECRET\b', re.I),
    re.compile(r'\bTOKEN\b', re.I),
    re.compile(r'\bAPI_KEY\b|\bAPP_KEY\b', re.I),
    re.compile(r'\bPASSWORD\b|\bPASSWD\b', re.I),
    re.compile(r'\.npmrc', re.I),
    re.compile(r'\.env\b', re.I),
    re.compile(r'\bprocess\.env\b'),
    re.compile(r'/etc/passwd|/etc/shadow', re.I),
    re.compile(r'\.ssh/', re.I),
    re.compile(r'\bAWS_|GCP_|AZURE_', re.I),
]


def bigrams(s):
    s = s.lower().replace("-", "").replace("_", "").replace(".", "")
    return set(s[i:i+2] for i in range(len(s) - 1))


def similarity(a, b):
    bg_a, bg_b = bigrams(a), bigrams(b)
    if not bg_a or not bg_b:
        return 0.0
    return len(bg_a & bg_b) / len(bg_a | bg_b)


def parse_packages(input_file):
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError as e:
        print(f"ERROR: Cannot read {input_file}: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        data = json.loads(content)
        deps = {}
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            deps.update(data.get(section, {}))
        scripts = data.get("scripts", {})
        for name, version in deps.items():
            pkg_scripts = {}
            if "scripts" in data:
                pkg_scripts = {k: v for k, v in scripts.items()}
            yield name, version, pkg_scripts
        return
    except json.JSONDecodeError:
        pass

    install_re = re.compile(r'(?:added|installing|npm install|npm add)\s+([a-zA-Z0-9@/_.-]+)(?:@([^\s]+))?', re.I)
    for line in content.splitlines():
        m = install_re.search(line)
        if m:
            name = m.group(1).strip().lstrip("+").strip()
            version = m.group(2) or "unknown"
            if name:
                yield name, version, {}


def score_packages(packages, baseline, threshold):
    findings = []
    for name, version, scripts in packages:
        best_match, best_score = None, 0.0
        for bp in baseline:
            s = similarity(name, bp)
            if s > best_score:
                best_score, best_match = s, bp
        if best_score >= threshold and name not in baseline:
            findings.append({
                "package": name, "version": version,
                "type": "Typosquat", "severity": "HIGH",
                "detail": f"similarity={best_score:.2f} vs '{best_match}'",
                "hint": f"Replace '{name}' with '{best_match}' or verify it is intentional.",
            })
        for script_name, script_body in scripts.items():
            for pat in NETWORK_PATTERNS:
                if pat.search(script_body):
                    findings.append({
                        "package": name, "version": version,
                        "type": "NetworkCallback", "severity": "HIGH",
                        "detail": f"script '{script_name}': matched /{pat.pattern}/",
                        "hint": "Audit lifecycle script for unauthorized outbound connections.",
                    })
                    break
            for pat in CREDENTIAL_PATTERNS:
                if pat.search(script_body):
                    findings.append({
                        "package": name, "version": version,
                        "type": "SecretAccess", "severity": "HIGH",
                        "detail": f"script '{script_name}': matched /{pat.pattern}/",
                        "hint": "Lifecycle script accesses sensitive env vars or credential files.",
                    })
                    break
    return findings


def report_findings(findings):
    severity_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    peak = "LOW"
    counts = defaultdict(int)

    for f in findings:
        sev = f["severity"]
        counts[f["type"]] += 1
        if severity_rank.get(sev, 0) > severity_rank.get(peak, 0):
            peak = sev
        print(f"[{sev}] {f['package']}@{f['version']} | {f['type']} | {f['detail']} | HINT: {f['hint']}")

    print("\n--- Summary ---")
    for ftype, count in sorted(counts.items()):
        print(f"  {ftype}: {count}")
    print(f"  Total: {sum(counts.values())} finding(s) | Peak severity: {peak if findings else 'NONE'}")

    if any(f["severity"] == "HIGH" for f in findings):
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="npm Typosquat & Impersonator Detection Lab")
    parser.add_argument("input_file", help="Path to package.json or npm install log")
    parser.add_argument("--baseline", help="Path to JSON file with trusted package names")
    parser.add_argument("--threshold", type=float, default=0.80, help="Similarity threshold (default: 0.80)")
    args = parser.parse_args()

    if not 0.0 <= args.threshold <= 1.0:
        print("ERROR: --threshold must be between 0.0 and 1.0", file=sys.stderr)
        sys.exit(2)

    baseline = list(POPULAR_PACKAGES)
    if args.baseline:
        try:
            with open(args.baseline, "r", encoding="utf-8") as f:
                extra = json.load(f)
            if isinstance(extra, list):
                baseline.extend(extra)
            elif isinstance(extra, dict):
                baseline.extend(extra.keys())
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: Cannot load baseline {args.baseline}: {e}", file=sys.stderr)
            sys.exit(2)

    baseline_set = set(baseline)
    packages = list(parse_packages(args.input_file))
    findings = score_packages(packages, baseline_set, args.threshold)
    report_findings(findings)


if __name__ == "__main__":
    main()