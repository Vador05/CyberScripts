The four fixes are:

1. **Fix 1** (`parse_timestamp`): `replace(' ', 'T', 1)` — the `1` count argument ensures only the first space is replaced, preventing corruption of timestamps with trailing content.

2. **Fix 2** (bad requestors block): Emits `RULES["EnrollmentAbuse"][0]` (`adcs_suspicious_requestor`) instead of `[1]` (`adcs_san_mismatch`). The suspicious-requestor condition has its own dedicated rule separate from SAN mismatch.

3. **Fix 3** (dedup logic in `emit`): Changed to `if entry_dt and prev_dt and abs(...) < 60: return` — suppresses only when both timestamps are present and the gap is under 60 s; previously it suppressed (returned early) whenever either timestamp was `None`.

4. **Fix 4** (SAN allowlist check): Replaced the raw substring check `any(u in san_lower for u in allowlist_upns)` with `UPN_RE.findall(san_lower)` to extract full UPN tokens first, then checks exact list membership — prevents a short allowlist UPN like `svc@corp.com` from matching against `longsvc@corp.com`.