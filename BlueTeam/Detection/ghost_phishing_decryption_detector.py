"""Ghost Phishing Client-Side Decryption Detector.

Parses proxy log exports or HTTP response body dumps for indicators of
client-side-decrypted ghost phishing pages that evade static email scanners.

Usage:
    python ghost_phishing_decryption_detector.py responses.log
    python ghost_phishing_decryption_detector.py responses.log --patterns extra.json --severity high
"""
import argparse, json, re, sys
from pathlib import Path

SEV = {"low": 0, "medium": 1, "high": 2}

RULES = [
    ("EncryptedDelivery", "large_base64_literal", "medium",
     re.compile(r'(?:var|let|const)\s+\w+\s*=\s*["\']([A-Za-z0-9+/=]{256,})["\']', re.S),
     "Large base64 literal assigned to variable — likely encrypted payload"),
    ("EncryptedDelivery", "large_hex_literal", "medium",
     re.compile(r'(?:var|let|const)\s+\w+\s*=\s*["\']([0-9a-fA-F]{256,})["\']', re.S),
     "Large hex string assigned to variable — possible hex-encoded ciphertext"),
    ("EncryptedDelivery", "content_type_mismatch", "medium",
     re.compile(r'<(?:html|body|script|div|form)\b', re.I),
     "HTML markup in non-text/html response — potential obfuscated delivery"),
    ("DecryptionLogic", "subtle_crypto_decrypt", "high",
     re.compile(r'subtle\.decrypt\s*\(', re.I),
     "SubtleCrypto.decrypt call — client-side AES/RSA decryption in progress"),
    ("DecryptionLogic", "cryptojs_aes_decrypt", "high",
     re.compile(r'CryptoJS\.AES\.decrypt\s*\(', re.I),
     "CryptoJS.AES.decrypt — common ghost phishing decryption library"),
    ("DecryptionLogic", "xor_loop_ciphertext", "high",
     re.compile(r'for\s*\([^)]*\)\s*\{[^}]*\^=?[^}]*\}', re.S),
     "XOR loop over buffer — manual ciphertext decryption pattern"),
    ("DecryptionLogic", "eval_decrypted_output", "high",
     re.compile(r'eval\s*\(\s*(?:atob|CryptoJS|subtle)', re.I),
     "eval() applied to decrypted output — payload execution after decryption"),
    ("DecryptionLogic", "atob_decode", "low",
     re.compile(r'\batob\s*\(', re.I),
     "atob() call — base64 decode often used for payload delivery"),
    ("KeyExtraction", "location_hash_read", "high",
     re.compile(r'(?:window\.)?location\.hash', re.I),
     "location.hash access — fragment-channel key delivery evades server logging"),
]

def parse_responses(path):
    try:
        text = Path(path).read_text(errors="replace")
    except OSError as e:
        sys.exit(f"ERROR: {e}")
    blocks, cur = [], []
    for line in text.splitlines():
        if line.strip():
            cur.append(line)
        elif cur:
            blocks.append(cur)
            cur = []
    if cur:
        blocks.append(cur)
    responses = []
    for block in blocks:
        url, headers, body_lines, in_body = None, {}, [], False
        for line in block:
            if line.startswith("url:"):
                url = line[4:].strip()
            elif line.startswith("header:"):
                k, _, v = line[7:].strip().partition(":")
                headers[k.strip().lower()] = v.strip()
            elif line.startswith("body:"):
                in_body = True
                body_lines.append(line[5:])
            elif in_body:
                body_lines.append(line)
        if url and body_lines:
            responses.append({"url": url, "headers": headers, "body": "\n".join(body_lines)})
    return responses

def match_ghost_indicators(response, extra_rules):
    body, ct = response["body"], response["headers"].get("content-type", "text/html")
    findings = []
    dm = re.search(r'(?:subtle\.decrypt|CryptoJS\.AES\.decrypt|atob)\s*\(', body, re.I)
    decrypt_line = body[:dm.start()].count("\n") if dm else None
    for stage, name, sev, pat, note in list(RULES) + extra_rules:
        if stage == "EncryptedDelivery" and name == "content_type_mismatch" and "html" in ct.lower():
            continue
        for m in pat.finditer(body):
            if stage == "KeyExtraction" and (
                    decrypt_line is None or abs(body[:m.start()].count("\n") - decrypt_line) > 10):
                continue
            snippet = (m.group(1) if pat.groups else m.group(0))[:120]
            findings.append((stage, sev, name, snippet, note))
            break
    return findings

def load_extra_patterns(path):
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"ERROR loading patterns: {e}")
    rules = []
    for e in data:
        try:
            rules.append((e["stage"], e["name"], e["severity"],
                          re.compile(e["pattern"], re.I | re.S), e["note"]))
        except (KeyError, re.error):
            pass
    return rules

def report_findings(all_findings, min_sev):
    seen, stage_counts, peak, any_key = set(), {}, 0, False
    for url, findings in all_findings:
        for stage, sev, name, snippet, note in findings:
            if SEV.get(sev, 0) < SEV[min_sev] or (url, name) in seen:
                continue
            seen.add((url, name))
            stage_counts[stage] = stage_counts.get(stage, 0) + 1
            peak = max(peak, SEV.get(sev, 0))
            any_key = any_key or stage == "KeyExtraction"
            print(f"[{sev.upper()}] [{stage}] {name} | {url[:80]} | {snippet} | {note}")
    if not stage_counts:
        print("No indicators found above specified severity threshold.")
        return False
    print("\n--- Summary ---")
    for stage, count in stage_counts.items():
        print(f"  {stage}: {count} hit(s)")
    print(f"  Peak severity: {next(k for k, v in SEV.items() if v == peak).upper()}")
    if any_key:
        print("  ACTION: Correlate fragment-bearing URLs against email link-click logs for KeyExtraction hits.")
    return peak == SEV["high"]

def main():
    ap = argparse.ArgumentParser(description="Detect ghost phishing client-side decryption patterns in proxy logs.")
    ap.add_argument("log_file", help="Path to proxy log or HTTP response body dump")
    ap.add_argument("--patterns", help="JSON file with supplemental detection patterns")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                    help="Minimum alert severity to emit (default: low)")
    args = ap.parse_args()
    extra_rules = load_extra_patterns(args.patterns) if args.patterns else []
    responses = parse_responses(args.log_file)
    if not responses:
        sys.exit("ERROR: No valid response blocks found in log file.")
    all_findings = [(r["url"], match_ghost_indicators(r, extra_rules)) for r in responses]
    if report_findings(all_findings, args.severity):
        sys.exit(1)

if __name__ == "__main__":
    main()