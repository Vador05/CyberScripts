"""Supabase RLS Cross-Tenant Bypass Lab — scans SQL schema for RLS misconfigs.

Usage:
    python supabase_rls_bypass_lab.py schema.sql
    python supabase_rls_bypass_lab.py schema.sql --severity high
    python supabase_rls_bypass_lab.py schema.sql --patterns extra.json
"""
import argparse, json, re, sys
from collections import defaultdict

TENANT_IDS = {"organization_id", "tenant_id", "account_id", "workspace_id", "company_id"}
OPERATIONS = ("SELECT", "INSERT", "UPDATE", "DELETE")
SEV = {"low": 0, "medium": 1, "high": 2}


def parse_schema(path):
    with open(path) as f:
        sql = f.read()
    sql = re.sub(r'--[^\n]*', '', sql)
    sql = re.sub(r'/\*.*?\*/', '', sql, flags=re.DOTALL)
    sql = re.sub(r'\$\$.*?\$\$', '', sql, flags=re.DOTALL)
    tables = list(dict.fromkeys(
        m.group(1).lower()
        for m in re.finditer(r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:\w+\.)?(\w+)', sql, re.I)
    ))
    rls_enabled = {
        m.group(1).lower()
        for m in re.finditer(r'ALTER\s+TABLE\s+(?:\w+\.)?(\w+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY', sql, re.I)
    }
    policies = []
    for stmt in re.findall(r'CREATE\s+POLICY\b[^;]+;', sql, re.I | re.DOTALL):
        tm = re.search(r'\bON\s+(?:\w+\.)?(\w+)', stmt, re.I)
        om = re.search(r'\bFOR\s+(SELECT|INSERT|UPDATE|DELETE|ALL)\b', stmt, re.I)
        if not tm:
            continue
        mu = re.search(r'\b(using|with\s+check)\b', stmt, re.I)
        expr = stmt[mu.start():] if mu else ""
        policies.append({
            "table": tm.group(1).lower(),
            "op": (om.group(1) if om else "ALL").upper(),
            "expr": expr,
            "sec_def": bool(re.search(r'SECURITY\s+DEFINER', stmt, re.I)),
            "snippet": (expr or stmt).strip()[:120],
        })
    return tables, rls_enabled, policies


def detect_bypasses(tables, rls_enabled, policies, tenant_ids, min_sev):
    findings, min_level = [], SEV[min_sev]
    pmap = defaultdict(list)
    for p in policies:
        pmap[p["table"]].append(p)

    def emit(sev, table, tech, snippet, fix):
        if SEV[sev] >= min_level:
            findings.append({"sev": sev, "table": table, "tech": tech, "snippet": snippet[:120], "fix": fix})

    for table in tables:
        if table not in rls_enabled:
            emit("high", table, "NoRLS", f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
                 f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
            continue
        pols = pmap.get(table, [])
        if not pols:
            emit("high", table, "EmptyPolicy", "No policies defined",
                 f"CREATE POLICY tenant_iso ON {table} USING (tenant_id = auth.uid());")
            continue
        covered = set()
        for p in pols:
            ops = OPERATIONS if p["op"] == "ALL" else (p["op"],)
            covered.update(ops)
            if not any(t in p["expr"].lower() for t in tenant_ids):
                emit("high", table, "MissingTenantFilter", p["snippet"],
                     "Add USING (tenant_id = current_setting('app.tenant_id')::uuid) to the policy.")
            if p["sec_def"]:
                emit("medium", table, "SecurityDefiner", p["snippet"],
                     "Remove SECURITY DEFINER; enforce tenant isolation inside the function.")
        for op in OPERATIONS:
            if op not in covered:
                emit("medium", table, "OperationGap", f"{op} not covered",
                     f"CREATE POLICY {table}_{op.lower()} ON {table} FOR {op} USING (tenant_id = auth.uid());")
    return findings


def render_grid(tables, rls_enabled, policies):
    pmap = defaultdict(set)
    for p in policies:
        for op in (OPERATIONS if p["op"] == "ALL" else (p["op"],)):
            pmap[p["table"]].add(op)
    w = 9
    hdr = f"{'TABLE':<24} {'RLS':<5}" + "".join(f"{o:^{w}}" for o in OPERATIONS)
    print("\n=== RLS Coverage Grid ===")
    print(hdr)
    print("-" * len(hdr))
    for t in tables:
        row = f"{t:<24} {'YES' if t in rls_enabled else 'NO':<5}"
        row += "".join(f"{'COVERED' if op in pmap[t] else 'MISSING':^{w}}" for op in OPERATIONS)
        print(row)
    print()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("schema_file")
    parser.add_argument("--severity", choices=["low", "medium", "high"], default="low")
    parser.add_argument("--patterns")
    args = parser.parse_args()
    tids = set(TENANT_IDS)
    if args.patterns:
        try:
            with open(args.patterns) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise TypeError(f"expected a JSON object, got {type(data).__name__}")
            extra = data.get("tenant_identifiers", [])
            if isinstance(extra, str):
                raise TypeError(f"'tenant_identifiers' must be a list, got str")
            if not isinstance(extra, (list, tuple)):
                raise TypeError(f"'tenant_identifiers' must be a list, got {type(extra).__name__}")
            for item in extra:
                if not isinstance(item, str):
                    raise TypeError(f"'tenant_identifiers' entries must be strings, got {type(item).__name__}")
            tids.update(extra)
        except (OSError, json.JSONDecodeError, AttributeError, TypeError) as e:
            print(f"Warning: --patterns load failed: {e}", file=sys.stderr)
    try:
        tables, rls_enabled, policies = parse_schema(args.schema_file)
    except OSError as e:
        sys.exit(f"Error: {e}")
    if not tables:
        sys.exit("No CREATE TABLE statements found.")
    render_grid(tables, rls_enabled, policies)
    findings = detect_bypasses(tables, rls_enabled, policies, tids, args.severity)
    print("=== Bypass Findings ===")
    for f in findings:
        print(f"[{f['sev'].upper():<6}] {f['table']:<24} {f['tech']:<22} {f['snippet']}")
        print(f"  FIX: {f['fix']}")
    by_tech = defaultdict(int)
    peak = "low"
    for f in findings:
        by_tech[f["tech"]] += 1
        if SEV[f["sev"]] > SEV[peak]:
            peak = f["sev"]
    print(f"\n=== Summary ({len(findings)} findings | peak: {peak.upper()}) ===")
    for tech, cnt in sorted(by_tech.items()):
        print(f"  {tech}: {cnt}")
    if any(f["sev"] == "high" for f in findings):
        sys.exit(1)


if __name__ == "__main__":
    main()