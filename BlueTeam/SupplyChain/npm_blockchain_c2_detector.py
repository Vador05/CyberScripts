"""
npm Blockchain DNS & On-Chain C2 Resolver Detector

Scans npm install logs and audit output for indicators that packages resolve
C2 addresses through blockchain DNS (ENS, Unstoppable Domains, Handshake) or
direct Web3 JSON-RPC on-chain lookups.

Usage:
    python npm_blockchain_c2_detector.py install.log
    python npm_blockchain_c2_detector.py install.log --iocs extra_iocs.json --severity medium
    python npm_blockchain_c2_detector.py npm-audit.json --severity high
"""
import argparse, json, re, sys
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

BLOCKCHAIN_TLDS = re.compile(r"\b[\w\-]+\.(?:eth|crypto|zil|nft|blockchain|bitcoin|wallet|x|hns)\b", re.I)

BLOCKCHAIN_DNS_GATEWAYS = {
    "eth.link", "cloudflare-eth.com", "resolver.unstoppable.io",
    "eth.xyz", "gateway.ipfs.io", "resolve.unstoppable.io",
    "udnssdk.com", "api.unstoppable.io",
}

ETHEREUM_RPC_HOSTS = {
    "infura.io", "mainnet.infura.io", "alchemy.com", "alchemyapi.io",
    "rpc.ankr.com", "cloudflare-eth.com", "eth-mainnet.g.alchemy.com",
    "polygon-mainnet.g.alchemy.com", "rpc.infura.io",
}

IPFS_ARWEAVE_GATEWAYS = {
    "ipfs.io", "dweb.link", "arweave.net", "cloudflare-ipfs.com",
    "pinata.cloud", "nftstorage.link", "w3s.link",
}

JSONRPC_METHODS = re.compile(
    r"\b(eth_call|eth_getCode|eth_getStorageAt|eth_getLogs|eth_blockNumber|"
    r"net_version|eth_chainId|eth_sendRawTransaction|eth_getTransactionByHash)\b"
)

RULES = [
    ("C2Resolution",    "BlockchainGatewayAccess",  "high",   BLOCKCHAIN_DNS_GATEWAYS),
    ("C2Resolution",    "BlockchainTLDReference",   "medium", None),
    ("OnChainLookup",   "EthereumRPCEndpoint",       "high",   ETHEREUM_RPC_HOSTS),
    ("OnChainLookup",   "JSONRPCMethodCall",         "high",   None),
    ("BeaconDelivery",  "IPFSArweaveGatewayFetch",   "medium", IPFS_ARWEAVE_GATEWAYS),
]

PKG_RE = re.compile(r"(?:added|installing|postinstall|npm install)[:\s]+([\w\-\.@/]+)@(\d[\w.\-]+)", re.I)
HOST_RE = re.compile(r"(?:https?://|(?:GET|POST|fetch|curl|wget|connect)\s+(?:https?://)?)([a-zA-Z0-9][\w\-.]*\.[a-zA-Z]{2,})", re.I)
URL_RE = re.compile(r"https?://([a-zA-Z0-9][\w\-.]*\.[a-zA-Z]{2,})", re.I)


def load_supplemental_iocs(path):
    try:
        data = json.loads(Path(path).read_text())
        BLOCKCHAIN_DNS_GATEWAYS.update(data.get("blockchain_dns_gateways", []))
        ETHEREUM_RPC_HOSTS.update(data.get("ethereum_rpc_hosts", []))
        IPFS_ARWEAVE_GATEWAYS.update(data.get("ipfs_arweave_gateways", []))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[WARN] Failed to load supplemental IOCs from {path}: {exc}", file=sys.stderr)


def parse_log_entries(log_path):
    current_pkg = "unknown"
    try:
        lines = Path(log_path).read_text(errors="replace").splitlines()
    except OSError as exc:
        print(f"[ERROR] Cannot read log file: {exc}", file=sys.stderr)
        sys.exit(2)

    try:
        data = json.loads("\n".join(lines))
        lines = []
        if isinstance(data, dict):
            for vuln in data.get("vulnerabilities", {}).values():
                for via in vuln.get("via", []):
                    if isinstance(via, dict):
                        lines.append(f"postinstall {via.get('name','unknown')}@0.0.0 {via.get('url','')}")
    except (json.JSONDecodeError, AttributeError):
        pass

    entries = []
    for line in lines:
        pkg_match = PKG_RE.search(line)
        if pkg_match:
            current_pkg = f"{pkg_match.group(1)}@{pkg_match.group(2)}"
        hosts = {m.group(1).lower() for m in HOST_RE.finditer(line)}
        hosts.update(m.group(1).lower() for m in URL_RE.finditer(line))
        jsonrpc_hits = JSONRPC_METHODS.findall(line)
        tld_hits = BLOCKCHAIN_TLDS.findall(line)
        entries.append({
            "pkg": current_pkg,
            "line": line,
            "hosts": hosts,
            "jsonrpc": jsonrpc_hits,
            "tld_hits": tld_hits,
        })
    return entries


def match_rules(entry):
    hits = []
    hosts = entry["hosts"]

    for host in hosts:
        parts = set()
        parts.add(host)
        segments = host.split(".")
        for i in range(len(segments) - 1):
            parts.add(".".join(segments[i:]))

        if parts & BLOCKCHAIN_DNS_GATEWAYS:
            hits.append(("C2Resolution", "BlockchainGatewayAccess", "high"))
        if parts & ETHEREUM_RPC_HOSTS:
            hits.append(("OnChainLookup", "EthereumRPCEndpoint", "high"))
        if parts & IPFS_ARWEAVE_GATEWAYS:
            hits.append(("BeaconDelivery", "IPFSArweaveGatewayFetch", "medium"))

    if entry["jsonrpc"]:
        hits.append(("OnChainLookup", "JSONRPCMethodCall", "high"))
    if entry["tld_hits"]:
        hits.append(("C2Resolution", "BlockchainTLDReference", "medium"))

    return hits


def report_findings(entries, min_severity):
    ts = lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    seen = set()
    stage_counts = {"C2Resolution": 0, "OnChainLookup": 0, "BeaconDelivery": 0}
    peak = "low"
    any_high = False

    for entry in entries:
        for stage, rule, sev in match_rules(entry):
            if SEVERITY_RANK[sev] < SEVERITY_RANK[min_severity]:
                continue
            key = (entry["pkg"], rule)
            if key in seen:
                continue
            seen.add(key)

            stage_counts[stage] = stage_counts.get(stage, 0) + 1
            if SEVERITY_RANK[sev] > SEVERITY_RANK[peak]:
                peak = sev
            if sev == "high":
                any_high = True

            src = entry["line"].strip()[:120]
            print(f"[{ts()}] {stage} | {sev.upper():6s} | {rule:30s} | pkg={entry['pkg']:40s} | {src}")

    print("\n--- Summary ---")
    for stage, count in stage_counts.items():
        print(f"  {stage}: {count} hit(s)")
    print(f"  Peak severity: {peak.upper()}")

    if any_high:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Detect npm packages using blockchain DNS or Web3 RPC to locate C2 infrastructure."
    )
    parser.add_argument("log_file", help="Path to npm install log or npm audit JSON output")
    parser.add_argument("--iocs", metavar="PATH", help="Supplemental JSON file with additional IOCs")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum alert severity to emit (default: low)")
    args = parser.parse_args()

    if args.iocs:
        load_supplemental_iocs(args.iocs)

    entries = parse_log_entries(args.log_file)
    report_findings(entries, args.severity)


if __name__ == "__main__":
    main()