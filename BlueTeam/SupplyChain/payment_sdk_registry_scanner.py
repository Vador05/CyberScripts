"""
Payment SDK Registry Threat Scanner

Scans npm package-lock.json, PyPI requirements files, or plain-text CI install logs
for packages that closely resemble trusted payment-processing SDKs using bigram-similarity
scoring against a curated baseline.

Usage:
    python payment_sdk_registry_scanner.py package-lock.json
    python payment_sdk_registry_scanner.py requirements.txt --threshold 0.8
    python payment_sdk_registry_scanner.py install.log --registry npm --threshold 0.7
"""

import argparse
import json
import re
import sys
from pathlib import Path

PAYMENT_SDK_BASELINE = [
    "stripe", "stripe-js", "stripe-node", "react-stripe-js", "stripe-php",
    "braintree", "braintree-web", "braintree-node",
    "square", "squareup", "square-connect",
    "paypal", "paypal-rest-sdk", "paypal-checkout", "@paypal/checkout-server-sdk",
    "paypalrestsdk", "paypal-node-sdk",
    "adyen", "adyen-node-api-library", "adyen-python-api-library",
    "authorize-net", "authorizenet",
    "plaid", "plaid-python", "plaid-node",
    "dwolla", "dwolla-node", "dwolla-python",
    "klarna", "klarna-checkout", "klarna-sdk",
    "afterpay", "afterpay-sdk",
    "checkout.com", "checkout-sdk-node", "checkout-sdk-python",
    "mollie", "mollie-api-node", "mollie-api-python",
    "recurly", "recurly-client",
    "cybersource", "cybersource-rest-client-python",
    "worldpay", "spreedly",
]


def bigram_set(s):
    s = s.lower().replace("-", "").replace("_", "").replace(".", "")
    return set(s[i:i+2] for i in range(len(s) - 1)) if len(s) > 1 else set()


def bigram_similarity(a, b):
    ba, bb = bigram_set(a), bigram_set(b)
    if not ba or not bb:
        return 0.0
    return 2 * len(ba & bb) / (len(ba) + len(bb))


def detect_registry(path: Path, override: str):
    if override and override != "auto":
        return override
    name = path.name.lower()
    if name == "package-lock.json" or name.endswith(".json"):
        return "npm"
    if "requirements" in name or name.endswith(".txt"):
        return "pypi"
    return "npm"


def parse_package_lock(content):
    data = json.loads(content)
    if not isinstance(data, dict):
        raise AttributeError("package-lock.json root is not a JSON object")
    packages = data.get("packages", data.get("dependencies", {}))
    results = []
    for name, meta in packages.items():
        if not isinstance(meta, dict):
            continue
        # rsplit handles nested paths like node_modules/foo/node_modules/bar -> bar
        clean = name.rsplit("node_modules/", 1)[-1] if "node_modules/" in name else name
        if not clean:
            continue
        version = meta.get("version", "0.0.0")
        results.append((clean, version, "npm"))
    return results


def parse_requirements(content):
    results = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line_without_extras = re.sub(r"\[[^\]]*\]", "", line)
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]+\s*([A-Za-z0-9._\-]+))?", line_without_extras)
        if m:
            name = m.group(1)
            version = m.group(2) or ""
            results.append((name, version, "pypi"))
    return results


def parse_install_log(content, registry):
    results = []
    patterns = [
        re.compile(r"(?:added|installing|install)\s+([A-Za-z0-9@/_.\-]+)@([A-Za-z0-9._\-]+)", re.IGNORECASE),
        re.compile(r"Collecting\s+([A-Za-z0-9_.\-]+)==([A-Za-z0-9._\-]+)", re.IGNORECASE),
        re.compile(r"Successfully installed\s+([A-Za-z0-9_.\-]+-[0-9][A-Za-z0-9._\-]*)", re.IGNORECASE),
    ]
    for line in content.splitlines():
        for pat in patterns:
            m = pat.search(line)
            if m:
                groups = m.groups()
                if len(groups) == 2:
                    results.append((groups[0], groups[1], registry))
                elif len(groups) == 1:
                    parts = groups[0].rsplit("-", 1)
                    if len(parts) == 2:
                        results.append((parts[0], parts[1], registry))
                break
    return results


def parse_dependencies(path: Path, registry: str):
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"ERROR: Cannot read {path}: {e}", file=sys.stderr)
        sys.exit(2)

    if path.suffix == ".json":
        try:
            return parse_package_lock(content)
        except (json.JSONDecodeError, KeyError, AttributeError) as e:
            print(f"ERROR: Invalid JSON in {path}: {e}", file=sys.stderr)
            sys.exit(2)

    deps = parse_requirements(content)
    if not deps:
        deps = parse_install_log(content, registry)
    return deps


def is_newly_published(version: str):
    return bool(version and re.match(r"^0\.\d+\.\d+", version))


def is_suspicious_version(version: str):
    return bool(re.search(r"[0-9a-f]{6,}", version.lower()) and not re.match(r"^\d+\.\d+\.\d+$", version))


def score_packages(deps, threshold):
    findings = []
    for name, version, registry in deps:
        best_match, best_score = None, 0.0
        for baseline in PAYMENT_SDK_BASELINE:
            score = bigram_similarity(name, baseline)
            if score > best_score:
                best_score, best_match = score, baseline
        if best_score == 1.0:
            continue
        flags = []
        if best_score >= threshold:
            flags.append(("Typosquat", f"similar to '{best_match}' (score={best_score:.2f})"))
        if is_newly_published(version):
            flags.append(("NewlyPublished", f"version '{version}' matches 0.x.x pattern"))
        if is_suspicious_version(version):
            flags.append(("SuspiciousVersion", f"version '{version}' contains hex-like segment"))
        if not flags:
            continue
        types = [f[0] for f in flags]
        has_typosquat = "Typosquat" in types
        has_new = "NewlyPublished" in types
        if has_typosquat and has_new:
            severity = "HIGH"
        elif has_typosquat or has_new:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        findings.append((severity, name, version, registry, flags))
    return findings


def report_findings(findings):
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda x: severity_order.get(x[0], 9))
    type_counts = {}
    peak = None

    for severity, name, version, registry, flags in findings:
        if peak is None or severity_order[severity] < severity_order.get(peak, 9):
            peak = severity
        for ftype, detail in flags:
            type_counts[ftype] = type_counts.get(ftype, 0) + 1
            display_severity = "LOW" if ftype == "SuspiciousVersion" else severity
            hint = {
                "Typosquat": "Verify package name against official documentation and remove if unrecognized.",
                "NewlyPublished": "Confirm this is a known release; newly-registered packages warrant manual review.",
                "SuspiciousVersion": "Audit version string against official release history; remove if unverifiable.",
            }.get(ftype, "Review manually.")
            print(f"[{display_severity}] {registry}/{name}@{version} | {ftype} | {detail} | {hint}")

    print(f"\nSummary: {len(findings)} finding(s) | Peak severity: {peak or 'NONE'}")
    for ftype, count in sorted(type_counts.items()):
        print(f"  {ftype}: {count}")

    if peak == "HIGH":
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Payment SDK Registry Threat Scanner")
    parser.add_argument("input_file", help="Path to package-lock.json, requirements.txt, or install log")
    parser.add_argument("--threshold", type=float, default=0.75, help="Bigram similarity threshold (default: 0.75)")
    parser.add_argument("--registry", choices=["npm", "pypi", "auto"], default="auto", help="Force registry type")
    args = parser.parse_args()

    if not (0.0 <= args.threshold <= 1.0):
        print("ERROR: --threshold must be between 0.0 and 1.0", file=sys.stderr)
        sys.exit(2)

    path = Path(args.input_file)
    if not path.exists():
        print(f"ERROR: File not found: {path}", file=sys.stderr)
        sys.exit(2)

    registry = detect_registry(path, args.registry)
    deps = parse_dependencies(path, registry)

    if not deps:
        print("No packages found in input file.", file=sys.stderr)
        sys.exit(0)

    findings = score_packages(deps, args.threshold)
    report_findings(findings)


if __name__ == "__main__":
    main()