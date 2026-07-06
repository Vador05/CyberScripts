"""
Chrome Extension AI-Impersonation Behavioral Lab

Scans an unpacked Chrome extension directory for behavioral indicators of
AI-impersonation: address-bar keylogging via omnibox/input event listeners
and search-query proxying to non-vendor endpoints.

Usage:
    python chrome_ext_ai_impersonation_lab.py ./my_extension
    python chrome_ext_ai_impersonation_lab.py ./my_extension --severity high
    python chrome_ext_ai_impersonation_lab.py ./my_extension --vendor-domains trusted.json
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

SIZE_CAP = 256 * 1024

VENDOR_DOMAINS = {"google.com", "bing.com", "openai.com", "anthropic.com"}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

SUSPICIOUS_PERMISSIONS = {
    "tabs": ("SuspiciousPermission", "medium",
             "Restrict to activeTab; tabs grants broad browsing history access"),
    "webNavigation": ("SuspiciousPermission", "medium",
                      "Use declarativeNetRequest instead; webNavigation enables full URL surveillance"),
    "declarativeNetRequest": ("SuspiciousPermission", "low",
                               "Audit redirect rules; declarativeNetRequest can silently reroute search queries"),
}

RULES = [
    ("OmniboxKeylog", "high",
     r"chrome\.omnibox\.onInputChanged",
     "Remove omnibox API usage; legitimate AI assistants do not require address-bar input streaming"),
    ("OmniboxKeylog", "high",
     r"addEventListener\s*\(\s*['\"](?:keydown|keyup|input)['\"]",
     "Scope input listeners to extension UI only; global document/window listeners capture all keystrokes"),
    ("OmniboxKeylog", "medium",
     r"(?:location|document)\s*\.\s*(?:href|search|pathname)",
     "Avoid reading location.href on every keystroke event; access only on explicit user navigation"),
    ("SearchProxy", "high",
     r"(?:fetch|XMLHttpRequest)\s*[\(\.].*?[?&](?:q|query|search|text)\s*=",
     "Verify all search-query network calls target a domain from the vendor allowlist"),
    ("SearchProxy", "medium",
     r"new\s+URL\s*\(.*?[?&](?:q|query|search)\s*=",
     "Audit URL construction that embeds query parameters before any network call"),
]


def scan_extension(ext_dir: Path):
    manifest_path = ext_dir / "manifest.json"
    if not manifest_path.exists():
        print(f"[ERROR] No manifest.json found in {ext_dir}", file=sys.stderr)
        sys.exit(1)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        print(f"[ERROR] Failed to parse manifest.json: {exc}", file=sys.stderr)
        sys.exit(1)
    yield "manifest.json", json.dumps(manifest)
    for root, _, files in os.walk(ext_dir):
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix not in (".js", ".json"):
                continue
            try:
                if fpath.stat().st_size > SIZE_CAP:
                    continue
                rel = str(fpath.relative_to(ext_dir))
                yield rel, fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass


def _targets_outside_vendors(snippet: str, allowed: set) -> bool:
    hosts = re.findall(r"https?://([A-Za-z0-9._-]+)", snippet)
    return any(not any(h == d or h.endswith("." + d) for d in allowed) for h in hosts)


def detect_behaviors(rel_path: str, content: str, allowed_domains: set):
    findings = []
    if rel_path == "manifest.json":
        try:
            manifest = json.loads(content)
        except json.JSONDecodeError:
            return findings
        perms = manifest.get("permissions", []) + manifest.get("optional_permissions", [])
        for perm in perms:
            if perm in SUSPICIOUS_PERMISSIONS:
                btype, sev, mitigation = SUSPICIOUS_PERMISSIONS[perm]
                findings.append((rel_path, btype, sev, f'"permissions": ["{perm}"]', mitigation))
        return findings
    for btype, sev, pattern, mitigation in RULES:
        for m in re.finditer(pattern, content):
            start = max(0, m.start() - 10)
            snippet = content[start: m.end() + 60].replace("\n", " ").strip()[:120]
            if btype == "SearchProxy" and not _targets_outside_vendors(snippet, allowed_domains):
                continue
            findings.append((rel_path, btype, sev, snippet, mitigation))
    return findings


def report_findings(all_findings: list, min_severity: str):
    threshold = SEVERITY_ORDER[min_severity]
    counts: dict = {}
    peak = "low"
    emitted = 0
    for rel_path, btype, sev, snippet, mitigation in all_findings:
        if SEVERITY_ORDER[sev] < threshold:
            continue
        print(f"[{sev.upper()}] {rel_path} | {btype} | snippet: {snippet!r}")
        print(f"  -> Mitigation: {mitigation}")
        counts[btype] = counts.get(btype, 0) + 1
        if SEVERITY_ORDER[sev] > SEVERITY_ORDER[peak]:
            peak = sev
        emitted += 1
    print(f"\n--- Summary: {emitted} finding(s) ---")
    for btype, cnt in sorted(counts.items()):
        print(f"  {btype}: {cnt}")
    print(f"  Peak severity: {peak.upper()}")
    if peak == "high":
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Scan an unpacked Chrome extension for AI-impersonation behavioral indicators."
    )
    parser.add_argument("ext_dir", help="Path to the unpacked Chrome extension directory")
    parser.add_argument("--vendor-domains", dest="vendor_domains",
                        help="JSON file listing additional trusted vendor domains to merge with defaults")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum alert level to emit (default: low)")
    args = parser.parse_args()

    ext_dir = Path(args.ext_dir)
    if not ext_dir.is_dir():
        print(f"[ERROR] Directory not found: {ext_dir}", file=sys.stderr)
        sys.exit(1)

    allowed_domains = set(VENDOR_DOMAINS)
    if args.vendor_domains:
        try:
            extra = json.loads(Path(args.vendor_domains).read_text(encoding="utf-8"))
            if isinstance(extra, list):
                allowed_domains.update(extra)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[WARN] Could not load vendor domains file: {exc}", file=sys.stderr)

    all_findings = []
    for rel_path, content in scan_extension(ext_dir):
        all_findings.extend(detect_behaviors(rel_path, content, allowed_domains))

    report_findings(all_findings, args.severity)


if __name__ == "__main__":
    main()