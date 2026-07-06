#!/usr/bin/env python3
"""
PolinRider Package Registry Threat Detector

Usage:
    python polinrider_package_detector.py /path/to/package --registry auto --min-severity low
    python polinrider_package_detector.py /path/to/package.json --registry npm
    python polinrider_package_detector.py /path/to/go.mod --registry go --min-severity high
"""
import argparse, json, os, re, sys, time
from pathlib import Path

POPULAR = [
    "react","lodash","express","axios","webpack","babel","eslint","jest","typescript","moment",
    "chalk","commander","dotenv","uuid","debug","request","async","bluebird","underscore","jquery",
    "vue","angular","next","nuxt","gatsby","svelte","rollup","vite","parcel","prettier","mocha",
    "chai","sinon","supertest","nodemon","pm2","mongoose","sequelize","knex","pg","redis","cors",
    "helmet","jsonwebtoken","bcrypt","passport","multer","sharp","cheerio","puppeteer","playwright",
    "fastify","koa","hapi","restify","feathers","sails","strapi","winston","pino","bunyan","morgan",
    "github.com/gin-gonic/gin","github.com/gorilla/mux","github.com/go-chi/chi",
    "github.com/sirupsen/logrus","github.com/uber-go/zap","github.com/stretchr/testify",
    "symfony/console","laravel/framework","guzzlehttp/guzzle","monolog/monolog",
    "phpunit/phpunit","doctrine/orm","twig/twig","vlucas/phpdotenv","nesbot/carbon",
]

# Only Cyrillic lookalikes are suspicious in package names; common ASCII chars like o/0/l/1 are not.
HOMOGLYPH_RE = re.compile(r'[аеорсухАВСЕМОРТХ]')
CANARY_VER   = re.compile(r'\b9\d{3,}\b|\b[1-9]\d{4,}\b')
BASE64_EXEC  = re.compile(r'(?:base64|atob|Buffer\.from).{0,80}(?:exec|eval|spawn|child_process)', re.I|re.S)
EXFIL_ENV    = re.compile(r'(?:process\.env|os\.environ|getenv|ENV\[)', re.I)
CURL_FETCH   = re.compile(r'\b(?:curl|wget|fetch|http\.get|https\.get|urllib\.request)\b', re.I)
OUTBOUND_URL = re.compile(r'https?://(?!localhost|127\.0\.0\.1)[^\s\'"]{10,}', re.I)
PLACEHOLDER  = re.compile(r'^(?:your[_\-]?name|maintainer|todo|fixme|unknown|n/?a|example)$', re.I)
SEV          = {"low": 0, "medium": 1, "high": 2}

def _edit(a, b):
    if abs(len(a)-len(b)) > 3: return 99
    row = list(range(len(b)+1))
    for c in a:
        nrow = [row[0]+1]
        for j, d in enumerate(b):
            nrow.append(min(nrow[-1]+1, row[j+1]+1, row[j]+(c!=d)))
        row = nrow
    return row[-1]

def parse_package(path, registry):
    p = Path(path)
    meta = None
    if p.is_file():
        meta = p
        if registry == "auto":
            registry = {"package.json":"npm","go.mod":"go","composer.json":"packagist"}.get(p.name,"npm")
    else:
        if registry == "auto":
            for fname, reg in [("package.json","npm"),("go.mod","go"),("composer.json","packagist")]:
                c = p/fname
                if c.exists():
                    meta, registry = c, reg
                    break
        else:
            fname_map = {"npm":"package.json","go":"go.mod","packagist":"composer.json"}
            meta = p / fname_map[registry]
    if not meta or not meta.exists():
        raise FileNotFoundError(f"No metadata file in {path}")
    content = meta.read_text(errors="replace")
    pkg = {"_reg":registry,"_mtime":meta.stat().st_mtime,"_scripts":"","name":"","version":"","authors":[],"description":"","deps":{}}
    if registry == "npm":
        d = json.loads(content)
        auth = d.get("author")
        if isinstance(auth, str):
            authors = [auth]
        elif isinstance(auth, dict) and auth.get("name"):
            authors = [auth["name"]]
        else:
            authors = []
        pkg.update(name=d.get("name",""), version=d.get("version",""), description=d.get("description",""),
                   authors=authors, deps={**d.get("dependencies",{}),**d.get("devDependencies",{})})
        s = d.get("scripts",{})
        pkg["_scripts"] = " ".join(v for k,v in s.items() if k in ("preinstall","postinstall","install"))
    elif registry == "go":
        m = re.search(r'^module\s+(\S+)',content,re.M); v = re.search(r'^go\s+([\d.]+)',content,re.M)
        pkg.update(name=m.group(1) if m else "", version=v.group(1) if v else "",
                   deps=dict(re.findall(r'^\s+(\S+)\s+(v\S+)',content,re.M)))
    elif registry == "packagist":
        d = json.loads(content)
        pkg.update(name=d.get("name",""), version=d.get("version",""), description=d.get("description",""),
                   authors=[a.get("name","") for a in d.get("authors",[]) if isinstance(a,dict)],
                   deps={**d.get("require",{}),**d.get("require-dev",{})})
        pkg["_scripts"] = " ".join(str(v) for k,v in d.get("scripts",{}).items() if "install" in k.lower())
    return pkg

def detect_indicators(pkg):
    hits, name, ver, scripts = [], pkg["name"], pkg["version"], pkg["_scripts"]
    short = name.split("/")[-1]
    naming = False
    for pop in POPULAR:
        ps = pop.split("/")[-1]
        if short and 1 <= _edit(short.lower(), ps.lower()) <= 2:
            hits.append(("medium","Naming","TyposquattingMatch",f"{name!r} ~ {pop!r}")); naming=True; break
    if HOMOGLYPH_RE.search(name): hits.append(("medium","Naming","HomoglyphName",name[:120])); naming=True
    if CANARY_VER.search(ver):     hits.append(("medium","Naming","DependencyConfusionVersion",ver)); naming=True
    if re.fullmatch(r'\d+', short or "x"): hits.append(("medium","Metadata","AllNumericName",name))
    if short and len(short)==1:            hits.append(("low","Metadata","SingleCharName",name))
    clean = [a.strip() for a in pkg["authors"] if a and a.strip()]
    if not clean:                               hits.append(("low","Metadata","MissingAuthor","no author field"))
    elif any(PLACEHOLDER.match(a) for a in clean): hits.append(("medium","Metadata","PlaceholderAuthor",str(clean)[:120]))
    if (time.time()-pkg["_mtime"])/86400 < 1:  hits.append(("low","Metadata","RecentMtime",f"{(time.time()-pkg['_mtime'])/86400:.2f}d old"))
    behavioral = False
    if CURL_FETCH.search(scripts):  hits.append(("high","Behavioral","CurlFetchInScript",scripts[:120])); behavioral=True
    if BASE64_EXEC.search(scripts): hits.append(("high","Behavioral","Base64DecodeChain",scripts[:120])); behavioral=True
    if EXFIL_ENV.search(scripts):   hits.append(("high","Behavioral","EnvVarExfiltration",scripts[:120])); behavioral=True
    m = OUTBOUND_URL.search(scripts)
    if m: hits.append(("medium","Behavioral","OutboundURL",m.group()[:120])); behavioral=True
    if naming and behavioral:
        hits = [("high" if SEV[s]<SEV["high"] else s, *rest) for s,*rest in hits]
    return hits

def report_findings(findings, min_sev):
    threshold, counts, peak = SEV[min_sev], {}, "low"
    for sev, cat, rule, val in findings:
        if SEV[sev] >= threshold:
            print(f"[{sev.upper():6}] {cat:10} {rule:30} {val[:120]}")
            counts[cat] = counts.get(cat,0)+1
            if SEV[sev] > SEV[peak]: peak = sev
    print("---")
    if not counts:
        print("No findings above threshold.")
    else:
        for cat,cnt in sorted(counts.items()): print(f"  {cat}: {cnt} finding(s)")
        print(f"  Peak severity: {peak.upper()}")
    return peak == "high"

def main():
    ap = argparse.ArgumentParser(description="PolinRider Package Registry Threat Detector")
    ap.add_argument("pkg_path")
    ap.add_argument("--registry", default="auto", choices=["npm","go","packagist","auto"])
    ap.add_argument("--min-severity", default="low", choices=["low","medium","high"], dest="min_severity")
    args = ap.parse_args()
    try:
        pkg = parse_package(args.pkg_path, args.registry)
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr); sys.exit(2)
    sys.exit(1 if report_findings(detect_indicators(pkg), args.min_severity) else 0)

if __name__ == "__main__":
    main()