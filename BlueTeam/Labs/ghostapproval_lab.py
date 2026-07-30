"""
GhostApproval Symlink Attack Lab

Demonstrates symlink-based sandbox escape against a naive AI coding agent
write path, then shows how os.path.realpath canonicalization blocks the attack.

Usage:
    python ghostapproval_lab.py /tmp/ghost_target.txt
    python ghostapproval_lab.py /tmp/ghost_target.txt --mode attack
    python ghostapproval_lab.py /tmp/ghost_target.txt --mode harden
    python ghostapproval_lab.py /tmp/ghost_target.txt --sandbox /tmp/my_sandbox
"""

import argparse
import datetime
import os
import shutil
import sys
import tempfile


def setup_attack(target_file: str, sandbox: str | None) -> dict:
    if not os.path.exists(target_file):
        raise FileNotFoundError(f"target_file does not exist: {target_file}")
    if not os.access(target_file, os.W_OK):
        raise PermissionError(f"target_file is not writable: {target_file}")

    created_sandbox = False
    if sandbox is None:
        sandbox = tempfile.mkdtemp(prefix="ghostapproval_")
        created_sandbox = True
    else:
        os.makedirs(sandbox, exist_ok=True)

    symlink_path = os.path.join(sandbox, "agent_output.txt")
    if os.path.lexists(symlink_path):
        os.remove(symlink_path)
    os.symlink(os.path.abspath(target_file), symlink_path)

    return {
        "sandbox_path": os.path.realpath(sandbox),
        "symlink_path": symlink_path,
        "target_path": os.path.abspath(target_file),
        "created_sandbox": created_sandbox,
    }


def run_agent(ctx: dict, mode: str) -> dict:
    sandbox_path = ctx["sandbox_path"]
    symlink_path = ctx["symlink_path"]
    target_path = ctx["target_path"]

    intended_write = symlink_path
    canonical = os.path.realpath(intended_write)
    resolution_chain = f"{symlink_path} -> {canonical}"

    result = {
        "mode": mode.upper(),
        "sandbox_path": sandbox_path,
        "symlink_path": symlink_path,
        "resolution_chain": resolution_chain,
        "intended_write": intended_write,
        "canonical": canonical,
    }

    if mode == "attack":
        payload = f"[GhostApproval payload written at {datetime.datetime.utcnow().isoformat()}Z]\n"
        try:
            with open(intended_write, "w") as f:
                f.write(payload)
        except (IOError, OSError) as e:
            result["outcome"] = "ERROR"
            result["escaped"] = False
            result["explanation"] = f"File write failed: {e}"
            return result
        escaped = not canonical.startswith(sandbox_path + os.sep) and canonical != sandbox_path
        result["outcome"] = "ESCAPED" if escaped else "CONTAINED"
        result["escaped"] = escaped
        result["explanation"] = (
            "Naive agent wrote through symlink without canonicalizing path; "
            "write landed outside sandbox root."
            if escaped
            else "Write stayed inside sandbox (unexpected; check symlink target)."
        )
    else:
        try:
            try:
                common = os.path.commonpath([canonical, sandbox_path])
            except ValueError:
                common = ""
            if common != sandbox_path:
                raise ValueError(
                    f"Symlink escape detected: '{intended_write}' resolves to "
                    f"'{canonical}' which is outside sandbox '{sandbox_path}'"
                )
            payload = f"[Hardened write at {datetime.datetime.utcnow().isoformat()}Z]\n"
            with open(canonical, "w") as f:
                f.write(payload)
            result["outcome"] = "ALLOWED"
            result["escaped"] = False
            result["explanation"] = "Canonical path is inside sandbox; write permitted."
        except (IOError, OSError) as e:
            result["outcome"] = "ERROR"
            result["escaped"] = False
            result["explanation"] = f"File write failed: {e}"
        except ValueError as exc:
            result["outcome"] = "BLOCKED"
            result["escaped"] = False
            result["block_reason"] = str(exc)
            result["explanation"] = (
                "os.path.realpath revealed the symlink target is outside the sandbox; "
                "write aborted."
            )

    return result


def report(results: list[dict]) -> int:
    divider = "=" * 72

    for r in results:
        print(divider)
        print(f"  PHASE: {r['mode']}")
        print(f"  Sandbox root   : {r['sandbox_path']}")
        print(f"  Planted symlink: {r['symlink_path']}")
        print(f"  Resolution     : {r['resolution_chain']}")
        print(f"  Intended write : {r['intended_write']}")
        print(f"  Canonical path : {r['canonical']}")
        print(f"  Outcome        : {r['outcome']}")
        print(f"  Explanation    : {r['explanation']}")
        if "block_reason" in r:
            print(f"  Block reason   : {r['block_reason']}")
        print()

    print(divider)
    print(f"  {'PHASE':<12} {'SANDBOX ESCAPED?':<20} {'MITIGATION'}")
    print(f"  {'-'*12} {'-'*20} {'-'*30}")
    for r in results:
        escaped_label = "YES (vulnerable)" if r.get("escaped") else "NO"
        mitigation = "None (raw path used)" if r["mode"] == "ATTACK" else "os.path.realpath check"
        print(f"  {r['mode']:<12} {escaped_label:<20} {mitigation}")
    print(divider)

    any_escape = any(r.get("escaped") for r in results)
    if any_escape:
        print("\n[!] Attack phase confirmed sandbox escape is present in this environment.")
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="GhostApproval Symlink Attack Lab: attack-then-defend demonstration.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("target_file", help="Existing writable file the symlink will resolve to.")
    parser.add_argument(
        "--mode",
        choices=["attack", "harden", "both"],
        default="both",
        help="Phases to run (default: both).",
    )
    parser.add_argument(
        "--sandbox",
        default=None,
        help="Sandbox directory path; a fresh tempdir is used if omitted.",
    )
    args = parser.parse_args()

    try:
        ctx = setup_attack(args.target_file, args.sandbox)
    except (FileNotFoundError, PermissionError) as exc:
        print(f"[ERROR] Setup failed: {exc}", file=sys.stderr)
        sys.exit(2)

    phases = []
    if args.mode in ("attack", "both"):
        phases.append("attack")
    if args.mode in ("harden", "both"):
        phases.append("harden")

    results = []
    try:
        for phase in phases:
            try:
                ctx = setup_attack(args.target_file, ctx["sandbox_path"])
            except Exception as exc:
                print(f"[ERROR] Re-setup for phase '{phase}' failed: {exc}", file=sys.stderr)
                sys.exit(2)
            result = run_agent(ctx, phase)
            results.append(result)
    finally:
        if ctx.get("created_sandbox") and args.sandbox is None:
            shutil.rmtree(ctx["sandbox_path"], ignore_errors=True)

    exit_code = report(results)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()