"""
CVE Asset Correlator - Correlate CVEs against an asset inventory and emit ranked remediation tickets.

Usage:
    python cve_asset_correlator.py cves.json assets.txt
    python cve_asset_correlator.py cves.json assets.txt --top 10

cves.json format (one JSON object per line):
    {"id": "CVE-2024-1234", "cvss": 9.8, "affected_products": ["openssl", "libssl"]}

assets.txt format (one asset per line):
    webserver-01,openssl,critical
    db-server-02,postgresql,high
    workstation-03,firefox,medium
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Optional


CRITICALITY_WEIGHTS = {
    "critical": 5.0,
    "high": 4.0,
    "medium": 3.0,
    "low": 2.0,
    "info": 1.0,
}


@dataclass
class CVE:
    id: str
    cvss: float
    affected_products: list[str]


@dataclass
class Asset:
    name: str
    product: str
    criticality: str
    criticality_weight: float


@dataclass
class Match:
    asset: Asset
    cve: CVE
    risk_score: float
    ticket_id: str = field(default="")

    def __post_init__(self):
        self.ticket_id = f"REM-{self.cve.id}-{self.asset.name[:8].upper().replace('-', '')}"


def parse_inputs(cve_file: str, asset_file: str) -> tuple[list[CVE], list[Asset]]:
    cves = []
    try:
        with open(cve_file, "r") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as e:
                    sys.exit(f"Error: malformed JSON on line {lineno} of {cve_file}: {e}")
                cve_id = obj.get("id", "").strip()
                cvss = obj.get("cvss")
                products = obj.get("affected_products", [])
                if not cve_id or not re.match(r"^CVE-\d{4}-\d+$", cve_id):
                    sys.exit(f"Error: invalid or missing CVE ID on line {lineno} of {cve_file}")
                if not isinstance(cvss, (int, float)) or not (0.0 <= float(cvss) <= 10.0):
                    sys.exit(f"Error: invalid CVSS score for {cve_id} on line {lineno}")
                if not isinstance(products, list) or not products:
                    sys.exit(f"Error: affected_products must be a non-empty list for {cve_id}")
                cves.append(CVE(id=cve_id, cvss=float(cvss), affected_products=[str(p).lower() for p in products]))
    except OSError as e:
        sys.exit(f"Error: cannot read CVE file '{cve_file}': {e}")

    assets = []
    try:
        with open(asset_file, "r") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 3:
                    sys.exit(f"Error: asset line {lineno} in '{asset_file}' must have name,product,criticality")
                name, product, criticality = parts[0], parts[1].lower(), parts[2].lower()
                if not name or not product:
                    sys.exit(f"Error: empty name or product on line {lineno} of '{asset_file}'")
                weight = CRITICALITY_WEIGHTS.get(criticality)
                if weight is None:
                    sys.exit(f"Error: unknown criticality '{criticality}' on line {lineno}; use: {', '.join(CRITICALITY_WEIGHTS)}")
                assets.append(Asset(name=name, product=product, criticality=criticality, criticality_weight=weight))
    except OSError as e:
        sys.exit(f"Error: cannot read asset file '{asset_file}': {e}")

    if not cves:
        sys.exit("Error: CVE file contains no valid entries.")
    if not assets:
        sys.exit("Error: asset file contains no valid entries.")

    return cves, assets


def correlate(cves: list[CVE], assets: list[Asset]) -> list[Match]:
    matches = []
    seen = set()
    for cve in cves:
        patterns = [re.compile(re.escape(p), re.IGNORECASE) for p in cve.affected_products]
        for asset in assets:
            if any(pat.search(asset.product) for pat in patterns):
                key = (cve.id, asset.name)
                if key in seen:
                    continue
                seen.add(key)
                risk_score = round(cve.cvss * asset.criticality_weight, 2)
                matches.append(Match(asset=asset, cve=cve, risk_score=risk_score))
    return matches


def emit_tickets(matches: list[Match], top_n: Optional[int]) -> None:
    ranked = sorted(matches, key=lambda m: m.risk_score, reverse=True)
    if top_n is not None:
        ranked = ranked[:top_n]

    if not ranked:
        print("No CVE-asset correlations found.")
        return

    divider = "=" * 72
    print(divider)
    print(f"{'CVE ASSET CORRELATOR — REMEDIATION TICKETS':^72}")
    print(f"{'Total findings: ' + str(len(ranked)):^72}")
    print(divider)

    for rank, match in enumerate(ranked, 1):
        severity = "CRITICAL" if match.cve.cvss >= 9.0 else "HIGH" if match.cve.cvss >= 7.0 else "MEDIUM" if match.cve.cvss >= 4.0 else "LOW"
        action = "Patch immediately" if severity in ("CRITICAL", "HIGH") else "Schedule patch in next maintenance window" if severity == "MEDIUM" else "Track and review"
        print(f"\nRank      : #{rank}")
        print(f"Ticket ID : {match.ticket_id}")
        print(f"Asset     : {match.asset.name} (product: {match.asset.product})")
        print(f"CVE       : {match.cve.id}")
        print(f"CVSS      : {match.cve.cvss:.1f} ({severity})")
        print(f"Criticality: {match.asset.criticality} (weight: {match.asset.criticality_weight})")
        print(f"Risk Score: {match.risk_score}")
        print(f"Action    : {action}")
        print("-" * 72)


def main():
    parser = argparse.ArgumentParser(
        description="Correlate CVEs against an asset inventory and emit ranked remediation tickets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("cve_file", help="Path to newline-delimited CVE JSON file")
    parser.add_argument("asset_file", help="Path to plain-text CMDB/SBOM inventory (name,product,criticality)")
    parser.add_argument("--top", type=int, default=None, metavar="N", help="Emit only the top N tickets by risk score")
    args = parser.parse_args()

    if args.top is not None and args.top < 1:
        sys.exit("Error: --top must be a positive integer.")

    cves, assets = parse_inputs(args.cve_file, args.asset_file)
    matches = correlate(cves, assets)
    emit_tickets(matches, args.top)


if __name__ == "__main__":
    main()