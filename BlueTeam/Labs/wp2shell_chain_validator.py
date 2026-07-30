"""
wp2shell_chain_validator.py - WAF coverage lab for the wp2shell exploit kill-chain.

Usage:
    python wp2shell_chain_validator.py
    python wp2shell_chain_validator.py --evasion
    python wp2shell_chain_validator.py --stage deploy
    python wp2shell_chain_validator.py --rules modsec_crs.conf --evasion --stage all

Exit code 1 if any evaluated stage reports zero detection coverage.
"""
import argparse, base64, re, sys

BUNDLED_RULES = [
    ("XMLRPC_MULTICALL",    r"xmlrpc\.php",                                            "HIGH"),
    ("CRED_STUFF_UA",       r"wp2shell|hydra|medusa|masscan|WPScan",                   "MEDIUM"),
    ("THEME_EDITOR_INJECT", r"/wp-admin/(?:theme|plugin)-editor\.php",                "HIGH"),
    ("PHP_EVAL_BODY",       r"eval\s*\(|base64_decode\s*\(|system\s*\(|passthru\s*\(","HIGH"),
    ("UPLOADS_PHP_DROP",    r"/wp-content/uploads/[^?\s]*\.php",                       "HIGH"),
    ("CMD_POLL",            r"\.php\?.*?(?:cmd|exec|shell|command|system|run)\s*=",    "HIGH"),
]

HARDENING = {
    "credential":  ["Disable xmlrpc.php: add <Files xmlrpc.php> Deny from all in .htaccess",
                    "Enable login rate-limiting (e.g. Limit Login Attempts Reloaded plugin)"],
    "deploy":      ["Set define('DISALLOW_FILE_EDIT', true) in wp-config.php",
                    "Restrict /wp-admin to trusted IPs via .htaccess Order/Allow directives"],
    "postexploit": ["Block PHP in uploads: <Files *.php> Deny from all in wp-content/uploads/.htaccess",
                    "Rotate WordPress secret keys in wp-config.php after any suspected compromise"],
}

CHAIN = [
    ("credential", "POST", "/xmlrpc.php",
     "<?xml version='1.0'?><methodCall><methodName>system.multicall</methodName></methodCall>"),
    ("credential", "POST", "/wp-login.php",
     "log=admin&pwd=Password1&wp-submit=Log+In"),
    ("deploy",     "POST", "/wp-admin/theme-editor.php",
     "newcontent=<?php eval(base64_decode('c3lzdGVtKCRfR0VUW2NtZF0pOw=='));?>&action=edit-theme-plugin-file"),
    ("deploy",     "POST", "/wp-admin/plugin-editor.php",
     "newcontent=<?php system($_POST['exec']); ?>&action=edit-theme-plugin-file"),
    ("deploy",     "PUT",  "/wp-content/uploads/wp_shell.php",
     "<?php passthru($_GET['cmd']); ?>"),
    ("postexploit","GET",  "/wp-content/uploads/wp_shell.php?cmd=id",   ""),
    ("postexploit","GET",  "/wp-content/uploads/c99.php?exec=whoami",   ""),
]


def load_rules(rules_file):
    if not rules_file:
        return list(BUNDLED_RULES)
    rules = []
    try:
        with open(rules_file) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.search(r'"([^"]{3,})"', line)
                pattern = m.group(1) if m else line
                sev_m = re.search(r'severity[:\s]+["\']?(\w+)["\']?', line, re.I)
                sev = sev_m.group(1).upper() if sev_m else "MEDIUM"
                id_m = re.search(r'\bid[:\s]+(\d+)', line, re.I)
                name = f"RULE_{id_m.group(1)}" if id_m else f"RULE_{len(rules)+1}"
                try:
                    re.compile(pattern)
                    rules.append((name, pattern, sev))
                except re.error:
                    pass
    except OSError as e:
        print(f"[ERROR] Cannot read rules file: {e}", file=sys.stderr)
        sys.exit(2)
    if not rules:
        print("[WARN] Rules file yielded no valid patterns; falling back to bundled rules.", file=sys.stderr)
        return list(BUNDLED_RULES)
    return rules


def _pct_encode(uri):
    # Step 1: single-encode special chars  /→%2F  .→%2E  ?→%3F  =→%3D
    single = (uri
              .replace("/", "%2F")
              .replace(".", "%2E")
              .replace("?", "%3F")
              .replace("=", "%3D"))
    # Step 2: double-encode by encoding the % prefix of each token → %25
    return (single
            .replace("%2F", "%252F")
            .replace("%2E", "%252E")
            .replace("%3F", "%253F")
            .replace("%3D", "%253D"))


def build_chain(evasion, stage):
    vectors = [v for v in CHAIN if stage == "all" or v[0] == stage]
    if not evasion:
        return vectors
    extras = []
    for stg, method, uri, body in vectors:
        extras.append((stg, method, _pct_encode(uri), body))
        if body and "<?php" in body:
            frag = base64.b64encode(body.encode()).decode()
            extras.append((stg, method, uri, f"eval(base64_decode('{frag}'));"))
    return vectors + extras


def evaluate_chain(chain, rules):
    hits, misses, gaps = {}, {}, []
    print(f"\n{'STAGE':<14}{'METHOD':<7}{'URI':<52}MATCHED RULES")
    print("-" * 110)
    for stg, method, uri, body in chain:
        target = uri + " " + body
        matched = [name for name, pat, _ in rules if _safe_match(pat, target)]
        tag = matched[0] if matched else "UNDETECTED"
        print(f"{stg:<14}{method:<7}{uri[:51]:<52}{tag}")
        bucket = hits if matched else misses
        bucket[stg] = bucket.get(stg, 0) + 1
        if not matched:
            partial = next((n for n, p, _ in rules if any(kw in p.lower() for kw in ['php', 'cmd', 'eval', 'shell'])), None)
            gaps.append((stg, uri, partial))
    print(f"\n{'STAGE':<14}{'HIT':>5}{'MISS':>6}{'COVERAGE':>11}")
    print("-" * 38)
    zero = []
    for s in sorted(set(hits) | set(misses)):
        h, m = hits.get(s, 0), misses.get(s, 0)
        pct = 100 * h // (h + m)
        print(f"{s:<14}{h:>5}{m:>6}{pct:>10}%")
        if pct == 0:
            zero.append(s)
    if gaps:
        print("\n=== GAP FINDINGS & HARDENING RECOMMENDATIONS ===")
        for stg, uri, partial in gaps:
            print(f"\n[BLIND SPOT] stage={stg}  uri={uri}")
            print(f"  Nearest partial rule : {partial or 'none'}")
            for rec in HARDENING.get(stg, ["Review WAF rules for this stage."]):
                print(f"  Hardening            : {rec}")
    print()
    if zero:
        print(f"[VERDICT] FAIL - Zero coverage in stage(s): {', '.join(zero)}")
        sys.exit(1)
    print("[VERDICT] PASS - All evaluated stages have at least partial detection coverage.")


def _safe_match(pattern, text):
    try:
        return bool(re.search(pattern, text, re.I))
    except re.error:
        return False


def main():
    ap = argparse.ArgumentParser(description="wp2shell Exploit Chain WAF Validator")
    ap.add_argument("--rules",   metavar="FILE",  help="ModSecurity rule file (default: bundled wp2shell patterns)")
    ap.add_argument("--evasion", action="store_true", help="Append percent-encoded and base64-fragmented evasion variants")
    ap.add_argument("--stage",   choices=["credential", "deploy", "postexploit", "all"], default="all",
                    help="Filter to a single kill-chain stage (default: all)")
    args = ap.parse_args()
    rules = load_rules(args.rules)
    chain = build_chain(args.evasion, args.stage)
    evaluate_chain(chain, rules)


if __name__ == "__main__":
    main()