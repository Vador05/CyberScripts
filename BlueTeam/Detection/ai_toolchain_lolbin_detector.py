"""
AI Toolchain LOLBin Abuse Detector

Scans process execution or shell audit logs for legitimate AI toolchain binaries
being abused as living-off-the-land binaries across ReconStaging and Impact
kill-chain stages using Sandworm_Mode behavioral signatures.

Usage:
    python ai_toolchain_lolbin_detector.py audit.log
    python ai_toolchain_lolbin_detector.py bash_history.log --iocs extra.json --severity medium
    python ai_toolchain_lolbin_detector.py syslog.log --severity high
"""
import argparse, json, re, sys
from collections import defaultdict
from pathlib import Path

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
AI_BINS = {"python", "python3", "pip", "pip3", "jupyter", "ollama", "huggingface-cli", "hf"}

RECON_RULES = [
    ("EnvEnumeration",    re.compile(r"python3?\s+-c\s+.{0,200}os\.environ", re.I | re.S), "medium"),
    ("SocketProbe",       re.compile(r"python3?\s+-c\s+.{0,200}socket\.", re.I | re.S), "medium"),
    ("PipDownloadNonStd", re.compile(r"pip3?\s+download\s+.*-d\s+\S+", re.I), "medium"),
    ("HFEnvProbe",        re.compile(r"huggingface-cli\s+env\b", re.I), "low"),
    ("HFWhoami",          re.compile(r"huggingface-cli\s+whoami\b", re.I), "low"),
    ("JupyterExecute",    re.compile(r"jupyter\s+nbconvert\s+.*--execute", re.I), "medium"),
    ("OllamaPullNonReg",  re.compile(r"ollama\s+pull\s+[a-zA-Z0-9][\w\-]+\.[a-zA-Z]{2,}/", re.I), "medium"),
    ("SysInfoGather",     re.compile(r"python3?\s+-c\s+.{0,150}(?:platform\.|sys\.version|sys\.path)", re.I | re.S), "low"),
    ("PipListJSON",       re.compile(r"pip3?\s+list\s+.*--format=json", re.I), "low"),
]

IMPACT_RULES = [
    ("CredSSH",            re.compile(r"python3?.{0,300}\.ssh[/\\](?:id_rsa|id_ed25519|authorized_keys|config)\b", re.I | re.S), "high"),
    ("CredAWS",            re.compile(r"python3?.{0,300}\.aws[/\\]credentials\b", re.I | re.S), "high"),
    ("CredNetrc",          re.compile(r"python3?.{0,300}\.netrc\b", re.I | re.S), "high"),
    ("AttackerRegistry",   re.compile(r"pip3?\s+.*--index-url\s+https?://(?!pypi\.org|files\.pythonhosted\.org)\S+", re.I), "high"),
    ("ExtraIndexAttacker", re.compile(r"pip3?\s+.*--extra-index-url\s+https?://(?!pypi\.org|files\.pythonhosted\.org)\S+", re.I), "medium"),
    ("HFUpload",           re.compile(r"huggingface-cli\s+upload\b", re.I), "high"),
    ("JupyterPublicBind",  re.compile(r"jupyter\s+\S+\s+.*--ip[= ]0\.0\.0\.0", re.I), "high"),
    ("OllamaServeExposed", re.compile(r"ollama\s+serve\b", re.I), "medium"),
    ("PersistAIDaemon",    re.compile(r"(?:systemctl|launchctl|crontab)\s+.*(?:jupyter|ollama|python3?)\b", re.I), "high"),
    ("ShellFromAIParent",  re.compile(r"(?:jupyter|ollama)\b.{0,200}(?:bash|sh|zsh|/bin/sh|cmd\.exe)\b", re.I | re.S), "high"),
]

TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d+\.\d+)")
EXECVE_RE = re.compile(r"EXECVE.*?argc=\d+\s+(.*)", re.I)
AQPAIR_RE = re.compile(r'a\d+="([^"]*)"')


def load_iocs(path):
    try:
        data = json.loads(Path(path).read_text())
        extra_bins = set(data.get("ai_binaries", []))
        extra_recon = [(f"IOC_Recon_{i}", re.compile(p, re.I), "medium") for i, p in enumerate(data.get("recon_patterns", []))]
        extra_impact = [(f"IOC_Impact_{i}", re.compile(p, re.I), "high") for i, p in enumerate(data.get("impact_patterns", []))]
        return extra_bins, extra_recon, extra_impact
    except Exception as e:
        print(f"[WARN] IOC load failed: {e}", file=sys.stderr)
        return set(), [], []


def parse_log_entry(line):
    ts_m = TS_RE.search(line)
    ts = ts_m.group(1) if ts_m else "unknown"
    exe_m = EXECVE_RE.search(line)
    cmd = " ".join(AQPAIR_RE.findall(exe_m.group(1))) if exe_m else line.strip()
    pid_m = re.search(r"\bpid=(\d+)", line, re.I)
    ppid_m = re.search(r"\bppid=(\d+)", line, re.I)
    return {"ts": ts, "pid": pid_m.group(1) if pid_m else None,
            "ppid": ppid_m.group(1) if ppid_m else None, "cmd": cmd, "raw": line.rstrip()}


def implicated_bin(cmd, bins):
    tok = cmd.split()[0].split("/")[-1].lower() if cmd.split() else ""
    if tok in bins:
        return tok
    return next((b for b in bins if re.search(rf"(?<!\w){re.escape(b)}(?!\w)", cmd, re.I)), None)


def run(log_path, ioc_path, min_sev):
    extra_bins, extra_recon, extra_impact = load_iocs(ioc_path) if ioc_path else (set(), [], [])
    all_rules = [("ReconStaging", RECON_RULES + extra_recon), ("Impact", IMPACT_RULES + extra_impact)]
    bins = AI_BINS | extra_bins
    counts, bin_hits, seen, peak, exit_code = defaultdict(int), defaultdict(lambda: {"count": 0, "peak": "low"}), set(), "low", 0
    try:
        lines = Path(log_path).read_text(errors="replace").splitlines()
    except Exception as e:
        print(f"[ERROR] Cannot read log: {e}", file=sys.stderr)
        sys.exit(2)
    for line in lines:
        if not line.strip():
            continue
        entry = parse_log_entry(line)
        for stage, rules in all_rules:
            for name, pat, sev in rules:
                if SEVERITY_RANK[sev] < SEVERITY_RANK[min_sev]:
                    continue
                if not pat.search(entry["cmd"]):
                    continue
                ab = implicated_bin(entry["cmd"], bins)
                if not ab:
                    continue
                key = (name, entry["pid"] or entry["raw"][:60])
                if key in seen:
                    continue
                seen.add(key)
                counts[stage] += 1
                bstat = bin_hits[ab]
                bstat["count"] += 1
                if SEVERITY_RANK[sev] > SEVERITY_RANK[bstat["peak"]]:
                    bstat["peak"] = sev
                if SEVERITY_RANK[sev] > SEVERITY_RANK[peak]:
                    peak = sev
                if sev == "high":
                    exit_code = 1
                print(f"[{entry['ts']}] {stage} | {sev.upper():6} | {name:25} | bin={ab:20} | {entry['raw'][:100]}")
    print("\n--- Summary ---")
    for stage, cnt in counts.items():
        print(f"  {stage}: {cnt} hit(s)")
    if not counts:
        print("  No matches found.")
    print(f"  Peak severity: {peak}")
    if bin_hits:
        print("\n--- LOLBin Frequency ---")
        for b, stat in sorted(bin_hits.items(), key=lambda x: -x[1]["count"]):
            print(f"  {b:22} hits={stat['count']}  peak={stat['peak']}")
    return exit_code


def main():
    ap = argparse.ArgumentParser(description="AI Toolchain LOLBin Abuse Detector")
    ap.add_argument("log_file", help="Path to process execution or shell audit log")
    ap.add_argument("--iocs", metavar="FILE", help="Supplemental IOC JSON file")
    ap.add_argument("--severity", choices=["low", "medium", "high"], default="low", help="Minimum alert severity")
    args = ap.parse_args()
    sys.exit(run(args.log_file, args.iocs, args.severity))


if __name__ == "__main__":
    main()