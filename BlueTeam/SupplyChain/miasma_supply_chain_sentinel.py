"""
Miasma/Hades Supply Chain Sentinel

Scans npm/Go module metadata and GHA workflow text for Miasma/Hades malware-family
indicators using heuristic risk scoring.

Usage:
    python miasma_supply_chain_sentinel.py --file package.json --ecosystem npm --threshold 3
    python miasma_supply_chain_sentinel.py --file go.mod --ecosystem go --threshold 2
    python miasma_supply_chain_sentinel.py --file workflow.yml --ecosystem npm --threshold 1
"""

import argparse
import re
import sys
from typing import Iterator


NPM_HEURISTICS = [
    (5, "PREINSTALL_OBFUSCATION", re.compile(r'"preinstall"\s*:\s*"[^"]*(?:eval|exec|base64|Buffer\.from|atob|\\x[0-9a-f]{2})', re.I)),
    (5, "POSTINSTALL_OBFUSCATION", re.compile(r'"postinstall"\s*:\s*"[^"]*(?:eval|exec|base64|Buffer\.from|atob|\\x[0-9a-f]{2})', re.I)),
    (4, "INSTALL_HOOK_CURL", re.compile(r'"(?:pre|post)?install"\s*:\s*"[^"]*(?:curl|wget)\s+http', re.I)),
    (4, "BASE64_PAYLOAD", re.compile(r'(?:Buffer\.from|atob)\s*\(\s*["\'][A-Za-z0-9+/]{20,}={0,2}["\']', re.I)),
    (4, "ENCODED_EVAL", re.compile(r'eval\s*\(\s*(?:Buffer\.from|atob|unescape|decodeURIComponent)', re.I)),
    (3, "KNOWN_C2_FRAGMENT", re.compile(r'(?:pastebin\.com|raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/[^"\']+\.(?:sh|ps1|bat)|ngrok\.io|serveo\.net|pagekite\.me)', re.I)),
    (3, "TYPOSQUAT_LODASH", re.compile(r'"name"\s*:\s*"lod[a5@]sh|lodas[hH]|1odash"', re.I)),
    (3, "TYPOSQUAT_REACT", re.compile(r'"name"\s*:\s*"re[4@]ct|reakt|r3act"', re.I)),
    (3, "TYPOSQUAT_EXPRESS", re.compile(r'"name"\s*:\s*"expr[e3]ss|expres5|3xpress"', re.I)),
    (2, "SUSPICIOUS_AUTHOR_EMAIL", re.compile(r'"email"\s*:\s*"[^"]*@(?:protonmail|tutanota|guerrillamail|mailinator)\.', re.I)),
    (2, "ANOMALOUS_VERSION_BUMP", re.compile(r'"version"\s*:\s*"(?:0\.0\.\d{3,}|\d{3,}\.\d+\.\d+)"')),
    (2, "OBFUSCATED_SCRIPT_VAR", re.compile(r'var\s+[_$]{2,}[a-zA-Z0-9_$]*\s*=')),
    (2, "HEX_STRING_PAYLOAD", re.compile(r'(?:\\x[0-9a-fA-F]{2}){8,}')),
    (1, "MISSING_REPOSITORY", re.compile(r'"name"\s*:\s*"[^"]+"\s*(?:(?!"repository")[^}]){0,200}(?:"description"|"version")', re.DOTALL)),
]

GO_HEURISTICS = [
    (4, "REPLACE_TO_LOCAL", re.compile(r'replace\s+\S+\s+=>\s+\.\.?/')),
    (4, "REPLACE_TO_UNKNOWN_FORK", re.compile(r'replace\s+(github\.com/\S+)\s+=>\s+github\.com/(?!\1\b)\S+')),
    (3, "TYPOSQUAT_GOLANG_ORG", re.compile(r'golang\.0rg|g0lang\.org|golang\.org\.fake', re.I)),
    (3, "KNOWN_C2_FRAGMENT_GO", re.compile(r'require\s+\S*(?:ngrok|serveo|pagekite)\S*')),
    (2, "PSEUDO_VERSION_ANOMALY", re.compile(r'v0\.0\.0-\d{14}-[0-9a-f]{12}')),
    (2, "RETRACTED_MODULE_USED", re.compile(r'retract\s+v[0-9]+\.[0-9]+\.[0-9]+')),
    (1, "INDIRECT_SUSPICIOUS", re.compile(r'//\s*indirect.*(?:util|helper|tool|kit|lib)\b', re.I)),
]

GHA_HEURISTICS = [
    (5, "FORK_PR_PUBLISH", re.compile(r'on:\s*\n.*pull_request.*\n(?:.*\n){0,10}.*(?:npm publish|cargo publish|pypi|twine upload)', re.DOTALL)),
    (5, "SECRETS_TO_UNTRUSTED_ACTION", re.compile(r'with:\s*\n(?:\s+[^:]+:[^\n]*\n)*\s+[^:]*(?:token|secret|key|password)[^:]*:\s*\$\{\{\s*secrets\.')),
    (4, "CURL_EXFIL_ONELINER", re.compile(r'run:\s*[|>]?\s*\n?\s*(?:curl|wget)\s+(?:-[a-zA-Z]+\s+)*https?://\S+\s+(?:-d\s+|\|\s*)', re.I)),
    (4, "ENV_SECRET_EXFIL", re.compile(r'run:.*(?:curl|wget)[^"\']*\$(?:ENV|secrets)\.[A-Z_]+', re.I)),
    (3, "OBFUSCATED_RUN_BLOCK", re.compile(r'run:\s*[|>]\s*\n\s*(?:echo\s+["\'][A-Za-z0-9+/]{30,}={0,2}["\']|base64\s+-d\s*<<<)')),
    (3, "UNPIN_THIRD_PARTY_ACTION", re.compile(r'uses:\s+(?!actions/|github/)[^@\n]+@(?:main|master|HEAD|latest)')),
    (2, "WORKFLOW_DISPATCH_NO_APPROVAL", re.compile(r'on:\s*\[?workflow_dispatch\]?(?:(?!environment:).){0,300}(?:npm publish|deploy)', re.DOTALL)),
    (2, "POWERSHELL_DOWNLOAD", re.compile(r'pwsh|powershell.*(?:DownloadString|DownloadFile|IEX|Invoke-Expression)', re.I)),
]


def parse_lines(text: str) -> list[tuple[int, str]]:
    return [(i + 1, line) for i, line in enumerate(text.splitlines())]


def score_indicators(lines: list[tuple[int, str]], ecosystem: str) -> Iterator[tuple[int, str, str, str]]:
    heuristics = NPM_HEURISTICS if ecosystem == "npm" else GO_HEURISTICS
    for lineno, line in lines:
        for score, tag, pattern in heuristics:
            m = pattern.search(line)
            if m:
                yield (score, tag, m.group(0)[:120], f"line {lineno}: {line.strip()[:120]}")


def check_workflow_anomalies(text: str, lines: list[tuple[int, str]]) -> Iterator[tuple[int, str, str, str]]:
    for score, tag, pattern in GHA_HEURISTICS:
        m = pattern.search(text)
        if m:
            matched_text = m.group(0).replace("\n", " ")[:120]
            start_line = text[:m.start()].count("\n") + 1
            yield (score, tag, matched_text, f"line {start_line}: {lines[start_line - 1][1].strip()[:120]}" if start_line <= len(lines) else f"line {start_line}")


def is_workflow_file(text: str) -> bool:
    return bool(re.search(r'^on:\s*\n|^jobs:\s*\n|uses:\s+\S+@', text, re.MULTILINE))


def main() -> None:
    parser = argparse.ArgumentParser(description="Miasma/Hades Supply Chain Sentinel")
    parser.add_argument("--file", required=True, help="Path to manifest or log file")
    parser.add_argument("--ecosystem", choices=["npm", "go"], default="npm")
    parser.add_argument("--threshold", type=int, default=3)
    args = parser.parse_args()

    try:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        print(f"ERROR: cannot read file: {exc}", file=sys.stderr)
        sys.exit(1)

    lines = parse_lines(text)
    findings: list[tuple[int, str, str, str]] = []

    findings.extend(score_indicators(lines, args.ecosystem))

    if is_workflow_file(text):
        findings.extend(check_workflow_anomalies(text, lines))

    findings = [(s, t, p, l) for s, t, p, l in findings if s >= args.threshold]
    findings.sort(key=lambda x: x[0], reverse=True)

    seen: set[tuple[str, str]] = set()
    deduped: list[tuple[int, str, str, str]] = []
    for item in findings:
        key = (item[1], item[3])
        if key not in seen:
            seen.add(key)
            deduped.append(item)

    for score, tag, pattern, source in deduped:
        print(f"{score}\t{tag}\t{pattern}\t{source}")

    total_lines = len(lines)
    flags = len(deduped)
    print(f"SUMMARY\tscanned_lines={total_lines}\tfindings={flags}\tthreshold={args.threshold}\tecosystem={args.ecosystem}")


if __name__ == "__main__":
    main()