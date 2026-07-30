"""
Shadow AI Agent Discovery and Governance Scanner

Usage:
    python shadow_ai_agent_scanner.py config_file [--provider openai,anthropic] [--severity low]

Examples:
    python shadow_ai_agent_scanner.py claude_desktop_config.json
    python shadow_ai_agent_scanner.py oauth_grants.jsonl --provider openai,anthropic --severity medium
    python shadow_ai_agent_scanner.py .mcp.json --severity high
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone

AI_HOSTNAMES = {"api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
                "api.cohere.ai", "api.mistral.ai", "api-inference.huggingface.co",
                "cognitiveservices.azure.com"}
AI_TOOL_PREFIXES = ("openai-", "claude-", "gemini-", "mistral-", "cohere-", "huggingface-")
TOOL_PREFIX_TO_PROVIDER = {
    "openai": "openai",
    "claude": "anthropic",
    "gemini": "google",
    "mistral": "mistral",
    "cohere": "cohere",
    "huggingface": "huggingface",
}
MCP_SERVER_KEYS = ("mcpServers", "servers", "mcp_servers")
AI_OAUTH_SCOPES = ("cloud-platform", "generative-language", "model", "inference", "completion", "embedding")
TOKEN_KEY_RE = re.compile(r"(?i)(_api_key|_token|^openai_|^anthropic_|^google_|^azure_openai_|^cohere_|^hf_)")
TOKEN_PATTERNS = [
    ("openai", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("anthropic", re.compile(r"sk-ant-[A-Za-z0-9\-]{20,}")),
    ("google", re.compile(r"AIza[A-Za-z0-9_\-]{35}")),
]
PROVIDER_HOSTS = {"openai": "api.openai.com", "anthropic": "api.anthropic.com",
                  "google": "generativelanguage.googleapis.com", "azure": "cognitiveservices.azure.com",
                  "cohere": "api.cohere.ai", "mistral": "api.mistral.ai", "huggingface": "api-inference.huggingface.co"}
SEV_RANK = {"low": 0, "medium": 1, "high": 2}
GOVERNED_MCP = set()
GOVERNED_CLIENTS = set()


def redact(val, is_token=False):
    s = str(val)
    if is_token and len(s) > 6:
        return s[:6] + "*" * min(len(s) - 6, 10)
    return s[:80]


def tag_provider(text):
    t = str(text).lower()
    for name, host in PROVIDER_HOSTS.items():
        if host in t or name in t:
            return name
    for prefix in AI_TOOL_PREFIXES:
        if t.startswith(prefix):
            raw = prefix.rstrip("-")
            return TOOL_PREFIX_TO_PROVIDER.get(raw, raw)
    return "unknown"


def walk(obj, path="$"):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk(v, f"{path}[{i}]")
    else:
        yield path, obj


def parse_entries(config_file):
    dropped = 0
    try:
        with open(config_file, encoding="utf-8", errors="replace") as fh:
            raw = fh.read().strip()
    except OSError as e:
        print(f"[ERROR] Cannot open {config_file}: {e}", file=sys.stderr)
        sys.exit(2)

    records = []
    jsonlines_mode = False
    try:
        records = [json.loads(raw)]
    except json.JSONDecodeError:
        jsonlines_mode = True
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                dropped += 1

    mcp_entries, oauth_entries, kv_entries = [], [], []
    for rec_idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            continue
        rec_root = f"$[{rec_idx}]" if jsonlines_mode else "$"

        for mcp_key in MCP_SERVER_KEYS:
            if mcp_key in rec:
                servers = rec[mcp_key]
                if isinstance(servers, dict):
                    for name, defn in servers.items():
                        if isinstance(defn, dict):
                            mcp_entries.append((f"{rec_root}.{mcp_key}.{name}", name,
                                                defn.get("command", ""), defn.get("args", []),
                                                defn.get("env", {})))
                elif isinstance(servers, list):
                    for i, defn in enumerate(servers):
                        if isinstance(defn, dict):
                            mcp_entries.append((f"{rec_root}.{mcp_key}[{i}]", defn.get("name", str(i)),
                                                defn.get("command", ""), defn.get("args", []),
                                                defn.get("env", {})))
        if "scopes" in rec or "scope" in rec:
            scopes = rec.get("scopes") or rec.get("scope", [])
            if isinstance(scopes, str):
                scopes = scopes.split()
            oauth_entries.append((f"{rec_root}.oauth", rec.get("principal", ""), scopes, rec.get("client_id", "")))
        for path, val in walk(rec, rec_root):
            if isinstance(val, (str, int, float)):
                kv_entries.append((path, path.rsplit(".", 1)[-1].lstrip("$"), val))

    return mcp_entries, oauth_entries, kv_entries, dropped


def detect_shadow_agents(mcp_entries, oauth_entries, kv_entries, providers):
    findings = []
    for path, name, command, args, env in mcp_entries:
        searchable = " ".join([str(command)] + [str(a) for a in (args or [])] +
                               [f"{k}={v}" for k, v in (env or {}).items()])
        matched_host = next((h for h in AI_HOSTNAMES if h in searchable), None)
        matched_prefix = next((p for p in AI_TOOL_PREFIXES if name.lower().startswith(p)), None)
        if (matched_host or matched_prefix) and name not in GOVERNED_MCP:
            prov = tag_provider(matched_host or matched_prefix or name)
            if not providers or prov in providers:
                findings.append(("MCPServerPresence", "low", prov, path, redact(name)))
        if isinstance(env, dict):
            for k, v in env.items():
                if TOKEN_KEY_RE.search(k):
                    for prov, pat in TOKEN_PATTERNS:
                        if (not providers or prov in providers) and pat.search(str(v)):
                            findings.append(("APITokenExposure", "high", prov, f"{path}.env.{k}", redact(v, True)))

    for path, principal, scopes, client_id in oauth_entries:
        if client_id in GOVERNED_CLIENTS:
            continue
        for scope in (scopes or []):
            if any(ai_scope in scope.lower() for ai_scope in AI_OAUTH_SCOPES):
                prov = tag_provider(scope)
                if not providers or prov in providers:
                    sev = "high" if "cloud-platform" in scope.lower() else "medium"
                    findings.append(("OAuthScopeAnomaly", sev, prov, f"{path}.scopes", redact(scope)))

    for path, key, val in kv_entries:
        if TOKEN_KEY_RE.search(str(key)):
            for prov, pat in TOKEN_PATTERNS:
                if (not providers or prov in providers) and pat.search(str(val)):
                    findings.append(("APITokenExposure", "high", prov, path, redact(val, True)))

    return findings


def report_findings(findings, dropped, min_sev):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    seen = set()
    has_critical_findings = False
    counts = {"MCPServerPresence": {"providers": set(), "total": 0},
              "APITokenExposure": {"providers": set(), "total": 0},
              "OAuthScopeAnomaly": {"providers": set(), "total": 0}}

    for signal, sev, prov, path, preview in findings:
        if SEV_RANK.get(sev, 0) < SEV_RANK.get(min_sev, 0):
            continue
        dedup_key = (signal, path)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        print(f"[{ts}] {signal} severity={sev} provider={prov} path={path} value={preview}")
        counts[signal]["providers"].add(prov)
        counts[signal]["total"] += 1
        if signal in ("APITokenExposure", "OAuthScopeAnomaly"):
            has_critical_findings = True

    print(f"\n--- Governance Summary ---")
    for cls, data in counts.items():
        print(f"  {cls}: {data['total']} ungoverned | providers={','.join(sorted(data['providers'])) or 'none'}")
    if dropped:
        print(f"  Dropped malformed lines: {dropped}")

    if has_critical_findings:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Shadow AI Agent Discovery and Governance Scanner")
    parser.add_argument("config_file", help="Path to MCP config, OAuth grant export, or JSON-lines audit file")
    parser.add_argument("--provider", default="", help="Comma-separated providers to match (default: all)")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low",
                        help="Minimum severity to emit (default: low)")
    args = parser.parse_args()

    providers = {p.strip().lower() for p in args.provider.split(",") if p.strip()} if args.provider else set()
    mcp_entries, oauth_entries, kv_entries, dropped = parse_entries(args.config_file)
    findings = detect_shadow_agents(mcp_entries, oauth_entries, kv_entries, providers)
    report_findings(findings, dropped, args.severity)


if __name__ == "__main__":
    main()