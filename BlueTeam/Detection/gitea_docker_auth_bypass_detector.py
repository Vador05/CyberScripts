"""Gitea Docker Registry Auth Bypass and Admin Impersonation Detector."""
import argparse, ipaddress, json, re, sys
from collections import defaultdict, deque
from urllib.parse import unquote

LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\w+) (?P<uri>\S+) HTTP/[\d.]+" '
    r'(?P<status>\d+) \S+(?: "[^"]*" "(?P<ua>[^"]*)"(?:\s+"(?P<auth>[^"]*)")?)?'
)
CONTAINER_NETS = [ipaddress.ip_network(c) for c in ("172.16.0.0/12", "10.0.0.0/8")]
V2_RE = re.compile(r'^/v2(/token|/auth)?(/|$|\?)', re.I)
ADMIN_RE = re.compile(r'^/(?:api/v1/admin|[-_]admin|user/settings)/', re.I)
PACK_RE = re.compile(r'/info/refs\?service=git-upload-pack|/git-upload-pack$', re.I)
GITEA_TOK = re.compile(r'^[A-Za-z0-9]{40,64}$')
DOCKER_UA = re.compile(r'docker|curl|python-requests|go-http|wget', re.I)
BARE_BASIC = re.compile(r'^Basic [A-Za-z0-9+/]{0,36}={0,2}$')

RULES = [
    {"name": "V2ApiUnauthProbe", "stage": "AuthBypassRecon", "sev": "medium",
     "fn": lambda e: bool(V2_RE.match(e["uri"])) and (not e["auth"] or bool(BARE_BASIC.match(e["auth"]))) and e["status"] in ("200", "401")},
    {"name": "AdminBearerAnomalous", "stage": "AdminImpersonation", "sev": "high",
     "fn": lambda e: bool(ADMIN_RE.match(e["uri"])) and e["auth"].startswith("Bearer ") and not bool(GITEA_TOK.match(e["auth"][7:]))},
    {"name": "AdminDockerUA", "stage": "AdminImpersonation", "sev": "high",
     "fn": lambda e: bool(ADMIN_RE.match(e["uri"])) and bool(DOCKER_UA.search(e["ua"]))},
    {"name": "ContainerUploadPack", "stage": "RepoExfiltration", "sev": "high",
     "fn": lambda e: bool(PACK_RE.search(e["uri"])) and _in_cnet(e["ip"]) and e["status"] == "200"},
]

_counts: dict = defaultdict(int)
_uniq: set = set()
_peak = ["low"]
_high = [False]
_dedup: dict = defaultdict(lambda: deque(maxlen=60))
_repos: dict = defaultdict(list)
_recon: dict = defaultdict(list)
_tokens: dict = defaultdict(list)


def _in_cnet(ip):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in CONTAINER_NETS)
    except ValueError:
        return False


def _rank(s):
    return {"low": 0, "medium": 1, "high": 2}.get(s, 0)


def _time_minutes(t1_str, t2_str):
    try:
        from datetime import datetime
        t1 = datetime.strptime(t1_str, "%d/%b/%Y:%H:%M:%S %z")
        t2 = datetime.strptime(t2_str, "%d/%b/%Y:%H:%M:%S %z")
        return abs((t2 - t1).total_seconds() / 60)
    except:
        return float('inf')


def _emit(e, stage, sev, name, min_sev):
    if _rank(sev) < _rank(min_sev):
        return
    dq = _dedup[(e["ip"], name)]
    if e["uri"] in dq:
        return
    dq.append(e["uri"])
    _counts[stage] += 1
    _uniq.add(e["ip"])
    if _rank(sev) > _rank(_peak[0]):
        _peak[0] = sev
    if sev == "high":
        _high[0] = True
    print(f"[{e['time']}] {stage} | {sev.upper()} | {name} | src={e['ip']} | {e.get('_raw', e['uri'])[:140]}")


def _parse(line):
    m = LOG_RE.match(line)
    if not m:
        return None
    d = {k: (m.group(k) or "") for k in ("ip", "time", "method", "uri", "status", "ua", "auth")}
    d["uri"] = unquote(d["uri"])
    d["_raw"] = line[:200]
    return d


def scan(path, iocs, min_sev):
    bad_ips = set(iocs.get("ips", []))
    bad_bp = iocs.get("bearer_prefixes", [])
    bad_rf = iocs.get("repo_fragments", [])
    warns = 0
    try:
        with open(path) as f:
            for raw in f:
                raw = raw.rstrip()
                if not raw or raw.startswith("#"):
                    continue
                e = _parse(raw)
                if not e:
                    warns += 1
                    continue
                ip, uri, auth, time_str = e["ip"], e["uri"], e["auth"], e["time"]
                if ip in bad_ips:
                    _emit(e, "AuthBypassRecon", "high", "IOC-IP", min_sev)
                if any(r in uri for r in bad_rf):
                    _emit(e, "RepoExfiltration", "high", "IOC-Repo", min_sev)
                if auth and any(auth.startswith("Bearer " + p) for p in bad_bp):
                    _emit(e, "AdminImpersonation", "high", "IOC-Bearer", min_sev)
                for r in RULES:
                    if r["fn"](e):
                        if r["stage"] in ("AuthBypassRecon", "AdminImpersonation"):
                            _recon[ip].append((time_str, e))
                        _emit(e, r["stage"], r["sev"], r["name"], min_sev)
                if auth.startswith("Bearer ") and ADMIN_RE.match(uri):
                    tok = auth[7:]
                    _tokens[tok].append((time_str, ip, e))
                    same_window = [(t, i) for t, i, _ in _tokens[tok] if _time_minutes(t, time_str) <= 5]
                    if len(set(i for _, i in same_window)) >= 2:
                        _emit(e, "AdminImpersonation", "high", "TokenRelay", min_sev)
                if PACK_RE.search(uri):
                    repo = re.sub(r'(/info/refs.*|/git-upload-pack.*)', '', uri)
                    _repos[ip].append((time_str, repo, e))
                    recent = [(t, r) for t, r, _ in _repos[ip] if _time_minutes(t, time_str) <= 5]
                    if len(set(r for _, r in recent)) >= 3:
                        _emit(e, "RepoExfiltration", "high", "MultiRepoEnum", min_sev)
                if _in_cnet(ip) and PACK_RE.search(uri):
                    if ip in _recon:
                        recent_recon = [t for t, _ in _recon[ip] if _time_minutes(t, time_str) <= 10]
                        if recent_recon:
                            _emit(e, "RepoExfiltration", "high", "PostBypassContainerPull", min_sev)
    except OSError as ex:
        sys.exit(f"ERROR: {ex}")
    if warns:
        print(f"WARNING: {warns} skipped/malformed lines", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log_file")
    ap.add_argument("--iocs")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low")
    args = ap.parse_args()
    iocs = {}
    if args.iocs:
        try:
            with open(args.iocs) as f:
                iocs = json.load(f)
        except (OSError, json.JSONDecodeError) as ex:
            sys.exit(f"ERROR loading IOCs: {ex}")
    scan(args.log_file, iocs, args.severity)
    print("\n--- Summary ---")
    for stage, n in sorted(_counts.items()):
        print(f"  {stage}: {n} hit(s)")
    print(f"  Unique source IPs: {len(_uniq)} | Peak severity: {_peak[0].upper()}")
    sys.exit(1 if _high[0] else 0)


if __name__ == "__main__":
    main()