"""
wp2shell_waf_detection_lab.py - ModSecurity WAF rule generation and coverage lab for wp2shell WordPress RCE.

Usage:
    python wp2shell_waf_detection_lab.py evaluate
    python wp2shell_waf_detection_lab.py generate --severity high
    python wp2shell_waf_detection_lab.py simulate
    python wp2shell_waf_detection_lab.py evaluate --iocs iocs.json --severity medium

Exit code 1 if any high-severity kill-chain stage has less than 100% coverage.
"""
import argparse, json, re, sys

SEV = {"low": 0, "medium": 1, "high": 2}
_RK = ("id", "phase", "stage", "severity", "technique", "target", "pattern", "desc")
_VK = ("method", "uri", "headers", "body", "stage")

_RD = [
    (9001001, 2, "CredentialAccess", "medium", "T1110", "REQUEST_URI", r"/wp-login\.php|/wp-admin/admin-ajax\.php", "WP login brute-force flood"),
    (9001002, 2, "CredentialAccess", "high", "T1110", "REQUEST_URI", r"/xmlrpc\.php", "XMLRPC system.multicall burst"),
    (9001003, 2, "CredentialAccess", "medium", "T1110", "User-Agent", r"wp2shell|WPScan|hydra|medusa|masscan", "Known attacker UA credential access"),
    (9001004, 2, "ShellDeployment", "high", "T1505.003", "REQUEST_URI", r"/wp-admin/(?:theme|plugin)-editor\.php", "Theme/plugin editor PHP injection"),
    (9001005, 2, "ShellDeployment", "high", "T1505.003", "REQUEST_URI", r"/wp-content/uploads/[^?]*\.php", "PHP file drop to uploads directory"),
    (9001006, 2, "ShellDeployment", "high", "T1505.003", "REQUEST_BODY", r"eval\(|base64_decode\(|system\(|passthru\(", "PHP shell payload in request body"),
    (9001007, 2, "PostExploit", "high", "T1059.004", "REQUEST_URI", r"/wp-content/(?:uploads|cache)/[^?]*\.php\?.*(?:cmd|exec|shell|command|system|run)=", "Post-exploit shell cmd via query param"),
    (9001008, 2, "PostExploit", "high", "T1059.004", "REQUEST_URI", r"/wp-content/(?:uploads|cache|plugins|themes)/(?:c99|r57|b374k|wso|alfa|shell)[\w.-]*\.php", "Known web shell filename"),
]

_VD = [
    ("POST", "/wp-login.php", {"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"}, "log=admin&pwd=P@ssw0rd1&wp-submit=Log+In", "CredentialAccess"),
    ("POST", "/wp-login.php", {"User-Agent": "wp2shell/2.1", "Content-Type": "application/x-www-form-urlencoded"}, "log=admin&pwd=test", "CredentialAccess"),
    ("POST", "/xmlrpc.php", {"User-Agent": "Mozilla/5.0", "Content-Type": "text/xml"}, "<?xml version='1.0'?><methodCall><methodName>system.multicall</methodName></methodCall>", "CredentialAccess"),
    ("POST", "/wp-admin/theme-editor.php", {"User-Agent": "python-requests/2.25", "Content-Type": "application/x-www-form-urlencoded"}, "newcontent=<?php eval(base64_decode('aWQ='));?>&action=edit-theme-plugin-file", "ShellDeployment"),
    ("POST", "/wp-admin/plugin-editor.php", {"User-Agent": "curl/7.68", "Content-Type": "application/x-www-form-urlencoded"}, "newcontent=<?php system($_POST['exec']); ?>&action=edit-theme-plugin-file", "ShellDeployment"),
    ("PUT", "/wp-content/uploads/wp_shell.php", {"User-Agent": "Mozilla/5.0"}, "<?php passthru($_GET['cmd']); ?>", "ShellDeployment"),
    ("GET", "/wp-content/uploads/wp_shell.php?cmd=id", {"User-Agent": "Mozilla/5.0"}, "", "PostExploit"),
    ("GET", "/wp-content/cache/c99.php?exec=whoami", {"User-Agent": "Mozilla/5.0"}, "", "PostExploit"),
    ("GET", "/wp-content/uploads/wso.php", {"User-Agent": "Mozilla/5.0"}, "", "PostExploit"),
]


def build_rules(iocs=None, severity="low"):
    rules = [dict(zip(_RK, r)) for r in _RD]
    if iocs:
        try:
            with open(iocs) as f:
                data = json.load(f)
        except Exception as e:
            print(f"[WARN] --iocs load failed: {e}", file=sys.stderr)
            data = {}
        if data.get("user_agents"):
            rules[2]["pattern"] += "|" + "|".join(re.escape(u) for u in data["user_agents"])
        if data.get("shell_filenames"):
            rules[7]["pattern"] += "|" + "|".join(re.escape(s) for s in data["shell_filenames"])
        if data.get("exploit_uri_fragments"):
            rules[6]["pattern"] += "|" + "|".join(data["exploit_uri_fragments"])
    return [r for r in rules if SEV[r["severity"]] >= SEV[severity]]


def build_vectors():
    return [dict(zip(_VK, v)) for v in _VD]


def _match(rule, vec):
    t = rule["target"]
    text = vec["uri"] if t == "REQUEST_URI" else vec["body"] if t == "REQUEST_BODY" else vec["headers"].get(t, "")
    return bool(re.search(rule["pattern"], text, re.IGNORECASE))


def _secrule(r):
    tgt = "REQUEST_HEADERS:User-Agent" if r["target"] == "User-Agent" else r["target"]
    print(f"# Stage: {r['stage']} | {r['technique']} | Severity: {r['severity'].upper()}")
    print(f"SecRule {tgt} \"@rx {r['pattern']}\" \\")
    print(f"    \"id:{r['id']},phase:{r['phase']},deny,status:403,log,msg:'{r['desc']} [{r['technique']}]',severity:{r['severity'].upper()}\"")
    print()


def run_lab(mode, rules, vectors):
    if mode == "generate":
        for r in rules:
            _secrule(r)
        return 0

    if mode == "simulate":
        for i, v in enumerate(vectors, 1):
            print(f"--- Vector {i} [{v['stage']}] ---")
            print(f"  {v['method']} {v['uri']}")
            for k, h in v["headers"].items():
                print(f"  {k}: {h}")
            if v["body"]:
                print(f"  Body: {v['body'][:80]}{'...' if len(v['body']) > 80 else ''}")
            print()
        return 0

    stages = {}
    for v in vectors:
        stages.setdefault(v["stage"], {"total": 0, "hits": 0, "gaps": []})
        stages[v["stage"]]["total"] += 1

    hit_matrix = {r["id"]: [] for r in rules}
    for v in vectors:
        matched = [r for r in rules if _match(r, v)]
        if matched:
            stages[v["stage"]]["hits"] += 1
        else:
            stages[v["stage"]]["gaps"].append(v)
        for r in matched:
            hit_matrix[r["id"]].append(f"{v['method']} {v['uri'][:60]}")

    print("=== Rule Match Table ===")
    for r in rules:
        h = hit_matrix[r["id"]]
        print(f"  [{r['id']}] {r['desc'][:48]:48s} | {len(h)} hit(s)")
        for line in h:
            print(f"    -> {line}")
    print()

    print("=== Kill-Chain Stage Coverage ===")
    exit_code = 0
    for stage, info in stages.items():
        pct = info["hits"] / info["total"] * 100 if info["total"] else 0
        sev = next((r["severity"] for r in rules if r["stage"] == stage), "low")
        tag = "OK" if pct == 100.0 else "GAP"
        print(f"  {stage:20s}: {info['hits']}/{info['total']} ({pct:.0f}%) [{sev.upper()}] [{tag}]")
        if sev == "high" and pct < 100.0:
            exit_code = 1

    all_gaps = [v for info in stages.values() for v in info["gaps"]]
    if all_gaps:
        print("\n=== Coverage Gaps ===")
        for v in all_gaps:
            print(f"  [{v['stage']}] {v['method']} {v['uri']}")
            print(f"    Suggested: @rx {re.escape(v['uri'].split('?')[0])}")

    verdict = "READY FOR DEPLOYMENT" if exit_code == 0 else "NOT READY - high-severity stage below 100% coverage"
    print(f"\n=== Readiness Verdict: {verdict} ===")
    return exit_code


def main():
    ap = argparse.ArgumentParser(description="wp2shell WAF Detection Lab")
    ap.add_argument("mode", nargs="?", default="evaluate", choices=["generate", "simulate", "evaluate"])
    ap.add_argument("--iocs", metavar="FILE", help="JSON with user_agents, shell_filenames, exploit_uri_fragments")
    ap.add_argument("--severity", default="low", choices=["low", "medium", "high"])
    a = ap.parse_args()
    sys.exit(run_lab(a.mode, build_rules(a.iocs, a.severity), build_vectors()))

if __name__ == "__main__":
    main()