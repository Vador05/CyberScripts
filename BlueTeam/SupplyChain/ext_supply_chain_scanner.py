"""
Browser Extension Supply Chain Scanner

Statically analyzes installed browser extension source files to detect dormant
or obfuscated script-injection capabilities consistent with supply chain compromise.
Uses the Adblock for YouTube attack as the reference threat model.

Usage:
    python ext_supply_chain_scanner.py --ext-dir ~/.config/google-chrome/Default/Extensions
    python ext_supply_chain_scanner.py --ext-dir /path/to/extension --threshold 2 --verbose
    python ext_supply_chain_scanner.py --ext-dir ~/Library/Application\\ Support/Google/Chrome/Default/Extensions --verbose
"""

import argparse
import json
import os
import re
import sys


MAX_JS_FILE_BYTES = 10 * 1024 * 1024  # 10 MB — skip larger files to avoid OOM

RISK_PATTERNS = [
    ("EVAL_DYNAMIC", re.compile(r'\beval\s*\(', re.IGNORECASE), 3),
    ("FUNC_CONSTRUCTOR", re.compile(r'new\s+Function\s*\(', re.IGNORECASE), 3),
    ("OBFUSCATED_B64", re.compile(r'atob\s*\(|btoa\s*\(|base64', re.IGNORECASE), 2),
    ("OBFUSCATED_HEX", re.compile(r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}'), 2),
    ("OBFUSCATED_UNICODE", re.compile(r'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){4,}'), 2),
    ("REMOTE_FETCH", re.compile(r'fetch\s*\(\s*["\']https?://', re.IGNORECASE), 3),
    ("REMOTE_XMLHTTP", re.compile(r'XMLHttpRequest|\.open\s*\(\s*["\']GET["\']', re.IGNORECASE), 2),
    ("REMOTE_SCRIPT", re.compile(r'createElement\s*\(\s*["\']script["\']', re.IGNORECASE), 2),
    ("EXECUTE_SCRIPT", re.compile(r'chrome\.tabs\.executeScript|scripting\.executeScript', re.IGNORECASE), 2),
    ("DYNAMIC_IMPORT", re.compile(r'import\s*\(\s*(?![\'"]\./|[\'"]\.\./)', re.IGNORECASE), 2),
    ("DORMANT_TIMER", re.compile(r'setTimeout\s*\(|setInterval\s*\(', re.IGNORECASE), 1),
    ("DOCUMENT_WRITE", re.compile(r'document\.write\s*\(', re.IGNORECASE), 2),
    ("INNER_HTML_ASSIGN", re.compile(r'innerHTML\s*=(?!=)', re.IGNORECASE), 1),
    ("WEBASSEMBLY", re.compile(r'WebAssembly\.(instantiate|compile)', re.IGNORECASE), 2),
    ("ENCODED_PAYLOAD", re.compile(r'(?:fromCharCode|charCodeAt)\s*\(', re.IGNORECASE), 2),
]

PERM_PATTERNS = [
    ("PERM_ALL_URLS", re.compile(r'<all_urls>|https?://\*/\*|\*://\*/\*'), 2),
    ("PERM_TABS", re.compile(r'"tabs"'), 1),
    ("PERM_WEBNAVIGATION", re.compile(r'"webNavigation"'), 1),
    ("PERM_WEBREQUEST_BLOCK", re.compile(r'"webRequestBlocking"'), 2),
    ("PERM_COOKIES", re.compile(r'"cookies"'), 1),
    ("PERM_STORAGE", re.compile(r'"storage"'), 1),
    ("PERM_NATIVE_MSG", re.compile(r'"nativeMessaging"'), 3),
    ("PERM_EXTERNALLY_CONN", re.compile(r'"externally_connectable"'), 2),
    ("PERM_DEBUGGER", re.compile(r'"debugger"'), 3),
    ("PERM_UNSAFE_EVAL", re.compile(r'"unsafe-eval"'), 3),
    ("PERM_REMOTE_CSP", re.compile(r'script-src[^"\']*https?://'), 2),
]


def detect_risks(content):
    findings = []
    for tag, pattern, weight in RISK_PATTERNS:
        if pattern.search(content):
            findings.append((tag, weight))
    return findings


def read_manifest_signals(ext_path):
    manifest_path = os.path.join(ext_path, "manifest.json")
    if not os.path.isfile(manifest_path):
        return [], "unknown"

    try:
        with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError):
        return [], "unknown"

    name = data.get("name", os.path.basename(ext_path))
    findings = []
    for tag, pattern, weight in PERM_PATTERNS:
        if pattern.search(raw):
            findings.append((tag, weight))
    return findings, name


def scan_extension(ext_path):
    manifest_findings, name = read_manifest_signals(ext_path)
    all_findings = list(manifest_findings)

    for root, dirs, files in os.walk(ext_path):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fname in files:
            if not fname.endswith(".js"):
                continue
            fpath = os.path.join(root, fname)
            try:
                fsize = os.path.getsize(fpath)
                if fsize > MAX_JS_FILE_BYTES:
                    print(f"[WARN] Skipping oversized file ({fsize} bytes): {fpath}", file=sys.stderr)
                    continue
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except OSError:
                continue
            all_findings.extend(detect_risks(content))

    seen_tags = set()
    deduped = []
    total_score = 0
    for tag, weight in all_findings:
        if tag not in seen_tags:
            seen_tags.add(tag)
            deduped.append(tag)
            total_score += weight

    return total_score, deduped, name


def find_extension_dirs(base_path):
    if not os.path.isdir(base_path):
        return []

    has_manifest = os.path.isfile(os.path.join(base_path, "manifest.json"))
    if has_manifest:
        return [base_path]

    results = []
    try:
        for entry in os.scandir(base_path):
            if not entry.is_dir(follow_symlinks=False):
                continue
            subdir = entry.path
            if os.path.isfile(os.path.join(subdir, "manifest.json")):
                results.append(subdir)
            else:
                try:
                    for sub in os.scandir(subdir):
                        if sub.is_dir(follow_symlinks=False) and os.path.isfile(os.path.join(sub.path, "manifest.json")):
                            results.append(sub.path)
                except OSError as e:
                    print(f"[ERROR] Cannot scan {subdir}: {e}", file=sys.stderr)
    except OSError as e:
        print(f"[ERROR] Cannot scan {base_path}: {e}", file=sys.stderr)
    return results


def _safe_name(name):
    return "".join(c if c.isprintable() and c not in "\n\r" else "?" for c in name)


def main():
    parser = argparse.ArgumentParser(
        description="Browser Extension Supply Chain Scanner — static analysis for compromise indicators",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python ext_supply_chain_scanner.py --ext-dir ~/.config/google-chrome/Default/Extensions --threshold 3 --verbose"
    )
    parser.add_argument("--ext-dir", required=True, metavar="PATH",
                        help="Path to browser extensions directory or a single unpacked extension folder")
    parser.add_argument("--threshold", type=int, default=3, metavar="INT",
                        help="Minimum cumulative risk score to flag an extension (default: 3)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print all scanned extensions, including those below threshold")
    args = parser.parse_args()

    ext_dirs = find_extension_dirs(os.path.expanduser(args.ext_dir))
    if not ext_dirs:
        print(f"[ERROR] No extensions found at: {args.ext_dir}", file=sys.stderr)
        sys.exit(1)

    total_scanned = 0
    total_flagged = 0

    for ext_path in sorted(ext_dirs):
        total_scanned += 1
        try:
            score, tags, name = scan_extension(ext_path)
        except Exception as e:
            print(f"[ERROR] Failed scanning {ext_path}: {e}", file=sys.stderr)
            continue

        flagged = score >= args.threshold
        if flagged:
            total_flagged += 1

        if flagged or args.verbose:
            tag_str = ", ".join(tags) if tags else "none"
            marker = "FLAGGED" if flagged else "ok"
            safe_name = _safe_name(name)
            print(f"[{marker}] score={score:3d}  {safe_name}  ({os.path.basename(ext_path)})  tags=[{tag_str}]")

    print(f"\nSummary: scanned={total_scanned}  flagged={total_flagged}  threshold={args.threshold}")


if __name__ == "__main__":
    main()