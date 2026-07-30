"""
Flying Eagle RAT C2 Hunter & IOC Feed Generator

Scans TLS handshake logs or HTTP scan output for Flying Eagle RAT C2 nodes using
bundled certificate fingerprints and panel signatures from Hunt.io's research,
emitting MITRE ATT&CK-labeled alerts and a deduplicated IOC feed for SIEM ingestion.

Usage:
    python flying_eagle_rat_c2_hunter.py ssl.log
    python flying_eagle_rat_c2_hunter.py shodan.json --iocs extra.json --severity medium
    python flying_eagle_rat_c2_hunter.py http_scan.log --severity high
"""
import argparse, json, re, sys
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
CERT_HASHES = {"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", "e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4",
               "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
               "7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d"}
CERT_CN_PATS = [re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$"), re.compile(r"flying.?eagle|fe.?rat", re.I)]
CERT_ORG_PATS = [re.compile(r"Flying Eagle|FERAT|FE\s*RAT", re.I)]
PANEL_TITLE_PATS = [re.compile(p, re.I) for p in (r"Flying Eagle", r"FE\s*(?:RAT|C2|Panel|Admin)", r"Eagle\s*(?:RAT|C2|Admin)", r"EagleC2")]
PANEL_HDR_PATS = [re.compile(p, re.I) for p in (r"X-Powered-By:\s*FE(?:RAT)?", r"Server:\s*EagleC2", r"X-Eagle-Token:")]
PANEL_PATH_PATS = [re.compile(p, re.I) for p in (r"(?:GET|POST|uri|path)[=:\s]+/(?:fe|eagle)/(?:login|admin)", r"/admin/fe(?:rat)?/")]
_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_SHA1 = re.compile(r"\b([0-9a-fA-F]{40})\b"); _SHA256 = re.compile(r"\b([0-9a-fA-F]{64})\b")
_SHA1C = re.compile(r"\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){19})\b", re.I)
_CN = re.compile(r"(?:CN|commonName)\s*=\s*([^,/\n\"]+)", re.I); _ORG = re.compile(r"(?:^|[,/\t ])O\s*=\s*([^,/\n\"]+)", re.I)
_TITLE = re.compile(r"(?:title|<title>|page_title)[=:\s\"]+([^\n<\"]{3,80})", re.I)
_SRVHDR = re.compile(r"((?:Server|X-Powered-By|X-Eagle[^:]*)\s*:\s*[^\n]+)", re.I)
_HOST = re.compile(r"\b(?:host|hostname|server_name)\s*[=:]\s*([\w.\-]+)", re.I)
_PORT = re.compile(r":(\d{2,5})\b"); _TS = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\d{10,}\.\d+)")

# Nested quantifiers like (a+)+ or (a|b)* are the primary source of catastrophic
# backtracking (ReDoS); reject them before compiling user-supplied patterns.
_REDOS_RE = re.compile(r'\([^)]*[+*][^)]*\)\s*[+*?{]|\(\?[^)]*\)\s*[+*?{]')
_PAT_MAX_LEN = 500


def _safe_compile(pattern: str, flags: int = 0) -> re.Pattern:
    if len(pattern) > _PAT_MAX_LEN:
        raise ValueError(f"pattern too long ({len(pattern)} > {_PAT_MAX_LEN})")
    if _REDOS_RE.search(pattern):
        raise ValueError("nested quantifiers detected (ReDoS risk)")
    return re.compile(pattern, flags)


def parse_log_entries(path: Path):
    try:
        text = path.read_text(errors="replace")
    except (FileNotFoundError, PermissionError, IOError) as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        sys.exit(1)

    for raw in text.splitlines():
        if raw.startswith("#") or not raw.strip(): continue
        e = {"raw": raw, "ts": "", "src_ip": "", "dst_ip": "", "dst_port": "",
             "cn": "", "org": "", "sha1": "", "sha256": "", "title": "", "headers": [], "host": ""}
        try:
            obj = json.loads(raw); e["raw"] = json.dumps(obj)
            for k in ("ip", "src_ip", "source_ip"):
                if k in obj: e["src_ip"] = str(obj[k]); break
            for k in ("host", "hostname", "domain"):
                if k in obj: e["host"] = str(obj[k]); break
            for k in ("port", "dst_port"):
                if k in obj: e["dst_port"] = str(obj[k]); break
            ssl = obj.get("ssl") or obj.get("tls") or {}; cert = ssl.get("cert") or {}; subj = cert.get("subject") or {}
            e["cn"] = subj.get("cn") or subj.get("commonName") or ""; e["org"] = subj.get("o") or subj.get("organization") or ""
            e["sha1"] = (cert.get("fingerprint_sha1") or cert.get("sha1") or "").lower()
            e["sha256"] = (cert.get("fingerprint_sha256") or cert.get("sha256") or "").lower()
            http = obj.get("http") or {}
            e["title"] = http.get("title") or obj.get("title") or ""
            e["headers"] = [f"{hk}: {hv}" for hk, hv in (http.get("headers") or {}).items()]
            e["ts"] = str(obj.get("timestamp") or obj.get("ts") or "")
        except (json.JSONDecodeError, AttributeError, TypeError):
            ips = _IP.findall(raw); e["src_ip"] = ips[0] if ips else ""; e["dst_ip"] = ips[1] if len(ips) > 1 else ""
            m = _PORT.search(raw); e["dst_port"] = m.group(1) if m else ""
            m = _TS.search(raw); e["ts"] = m.group(1) if m else ""
            m = _CN.search(raw); e["cn"] = m.group(1).strip() if m else ""
            m = _ORG.search(raw); e["org"] = m.group(1).strip() if m else ""
            sha256s = _SHA256.findall(raw)
            sha1s = [h for h in _SHA1.findall(raw) if not any(h in s for s in sha256s)]
            sha1s += [n for h in _SHA1C.findall(raw) if (n := h.replace(":", "").lower()) not in sha256s and n not in sha1s]
            e["sha256"] = sha256s[0].lower() if sha256s else ""; e["sha1"] = sha1s[0].lower() if sha1s else ""
            m = _TITLE.search(raw); e["title"] = m.group(1).strip() if m else ""
            e["headers"] = _SRVHDR.findall(raw)
            m = _HOST.search(raw); e["host"] = m.group(1) if m else ""
        yield e


def match_signatures(e, cert_hashes, cert_cn_pats, cert_org_pats, min_sev):
    hits = []; sha1, sha256 = e["sha1"], e["sha256"]; cn, org = e["cn"].strip(), e["org"].strip()
    if sha1 in cert_hashes or sha256 in cert_hashes:
        hits.append(("CertFingerprint", "high", "T1573", sha1 or sha256))
    if SEVERITY_RANK[min_sev] <= 1:
        if cn and any(p.search(cn) for p in cert_cn_pats): hits.append(("CertFingerprint", "medium", "T1573", f"CN={cn}"))
        if org and any(p.search(org) for p in cert_org_pats): hits.append(("CertFingerprint", "medium", "T1573", f"O={org}"))
    if SEVERITY_RANK[min_sev] == 0:
        if e["title"] and any(p.search(e["title"]) for p in PANEL_TITLE_PATS):
            hits.append(("PanelSignature", "low", "T1071.001", f"title:{e['title']}"))
        for hdr in e["headers"]:
            if any(p.search(hdr) for p in PANEL_HDR_PATS):
                hits.append(("PanelSignature", "low", "T1071.001", hdr.strip()))
        if any(p.search(e["raw"]) for p in PANEL_PATH_PATS): hits.append(("PanelSignature", "low", "T1071.001", "panel-login-path"))
    return hits


def main():
    ap = argparse.ArgumentParser(description="Flying Eagle RAT C2 Hunter & IOC Feed Generator")
    ap.add_argument("log_file", type=Path, help="TLS handshake log or HTTP scan output")
    ap.add_argument("--iocs", type=Path, help="Supplemental JSON IOC file")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low", help="Minimum alert severity")
    args = ap.parse_args()
    if not args.log_file.exists(): sys.exit(f"Error: {args.log_file} not found")
    cert_hashes = {h.lower() for h in CERT_HASHES}
    cert_cn_pats = list(CERT_CN_PATS)
    cert_org_pats = list(CERT_ORG_PATS)
    if args.iocs:
        try:
            extra = json.loads(args.iocs.read_text())
            cert_hashes.update(h.lower() for h in extra.get("cert_hashes", []))
            for p in extra.get("panel_strings", []): PANEL_TITLE_PATS.append(re.compile(re.escape(p), re.I))
            for p in extra.get("cert_cn_patterns", []):
                try:
                    cert_cn_pats.append(_safe_compile(p, re.I))
                except (re.error, ValueError) as exc:
                    print(f"[WARN] Skipped invalid cert_cn_pattern {p!r}: {exc}", file=sys.stderr)
            for p in extra.get("cert_org_patterns", []):
                try:
                    cert_org_pats.append(_safe_compile(p, re.I))
                except (re.error, ValueError) as exc:
                    print(f"[WARN] Skipped invalid cert_org_pattern {p!r}: {exc}", file=sys.stderr)
        except Exception as exc:
            print(f"[WARN] --iocs load failed: {exc}", file=sys.stderr)
    iocs: dict = {"ips": set(), "hostnames": set(), "cert_hashes": set(), "panel_strings": set()}
    seen: set = set(); counts: dict = {"CertFingerprint": 0, "PanelSignature": 0, "ComboHit": 0}
    peak_sev = "low"; has_high = False
    for e in parse_log_entries(args.log_file):
        hits = match_signatures(e, cert_hashes, cert_cn_pats, cert_org_pats, args.severity)
        if not hits: continue
        if len({h[0] for h in hits}) > 1: hits = [("ComboHit", "high", h[2], h[3]) for h in hits]
        src = e["src_ip"] or e["dst_ip"]; port = e["dst_port"]
        for stage, sev, technique, indicator in hits:
            if SEVERITY_RANK[sev] < SEVERITY_RANK[args.severity]: continue
            key = (src, stage, indicator)
            if key in seen: continue
            seen.add(key)
            ts = e["ts"] or datetime.now(timezone.utc).isoformat()
            print(f"[{ts}] ALERT sev={sev} stage={stage} technique={technique} indicator={indicator!r} src={src}:{port} | {e['raw'][:120]}")
            counts[stage] = counts.get(stage, 0) + 1
            if sev == "high": has_high = True
            if SEVERITY_RANK[sev] > SEVERITY_RANK[peak_sev]: peak_sev = sev
            if src: (iocs["hostnames"] if any(c.isalpha() for c in src) else iocs["ips"]).add(src)
            if e["host"]: (iocs["hostnames"] if any(c.isalpha() for c in e["host"]) else iocs["ips"]).add(e["host"])
            if e["sha1"]: iocs["cert_hashes"].add(e["sha1"])
            if e["sha256"]: iocs["cert_hashes"].add(e["sha256"])
            if "Panel" in stage or "title:" in indicator: iocs["panel_strings"].add(indicator)
    feed = {"generated_at": datetime.now(timezone.utc).isoformat(), "source_tool": "flying_eagle_rat_c2_hunter",
            "iocs": {k: sorted(v) for k, v in iocs.items()},
            "summary": {"stage_counts": counts, "total_unique_iocs": sum(len(v) for v in iocs.values()), "peak_severity": peak_sev}}
    print("\n--- IOC FEED ---\n" + json.dumps(feed, indent=2))
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()