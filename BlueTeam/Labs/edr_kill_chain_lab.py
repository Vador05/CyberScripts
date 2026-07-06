"""
EDR Kill Chain Lab - Blue-team training tool for macOS non-admin EDR-disable chain detection.

Replays ordered TTP steps with telemetry signatures and scans unified log exports
to validate detection coverage.

Usage:
    # Simulate attack chain with detection hints:
    python edr_kill_chain_lab.py --mode simulate

    # Hunt for kill-chain indicators in a unified log export:
    python edr_kill_chain_lab.py --mode hunt /path/to/unified.log

    # Hunt with full matching line output:
    python edr_kill_chain_lab.py --mode hunt --verbose /path/to/unified.log
"""

import argparse
import re
import sys

KILL_CHAIN = [
    {
        "stage": 1,
        "ttp": "T1562.001 / TCC-DB-WRITE",
        "name": "TCC Database Modification",
        "description": "Attacker writes to TCC.db directly or via sqlite3 to grant FDA without consent prompt.",
        "pattern": r"(TCC\.db|kTCCService|tcc\.db|com\.apple\.TCC.*sqlite|INSERT.*kTCCService)",
        "detection_query": "process == \"tccd\" OR (message CONTAINS \"TCC.db\" AND message CONTAINS \"INSERT\")",
        "hint": "Monitor tccd process for unexpected DB writes; alert on sqlite3 accessing /Library/Application Support/com.apple.TCC/",
    },
    {
        "stage": 2,
        "ttp": "T1543.004 / LAUNCH-DAEMON-UNLOAD",
        "name": "LaunchDaemon EDR Agent Unload",
        "description": "Attacker calls launchctl unload or bootout on EDR LaunchDaemon plist without admin rights via non-admin path.",
        "pattern": r"(launchctl.*(unload|bootout)|com\.crowdstrike|com\.sentinelone|com\.cylance|com\.carbonblack|com\.jamf|com\.vmware\.carbon|LaunchDaemons.*\.plist.*(unload|remove|disable))",
        "detection_query": "process == \"launchctl\" AND (message CONTAINS \"unload\" OR message CONTAINS \"bootout\")",
        "hint": "Alert on launchctl unload/bootout for any /Library/LaunchDaemons/ entry; baseline expected unloads from MDM processes only.",
    },
    {
        "stage": 3,
        "ttp": "T1562.001 / PPPC-BYPASS",
        "name": "PPPC / Privacy Preference Bypass",
        "description": "Attacker abuses PPPC profile or TCC API to suppress consent for Accessibility or Full Disk Access.",
        "pattern": r"(PPPC|Privacy Preferences|kTCCServiceAccessibility|kTCCServiceSystemPolicyAllFiles|AXIsProcessTrusted|SecTaskCopyValueForEntitlement.*com\.apple\.private\.tcc)",
        "detection_query": "message CONTAINS \"kTCCServiceAccessibility\" OR message CONTAINS \"kTCCServiceSystemPolicyAllFiles\"",
        "hint": "Baseline approved PPPC profiles via MDM; alert on TCC grants not matching the MDM payload allowlist.",
    },
    {
        "stage": 4,
        "ttp": "T1562.001 / SIP-BYPASS-PROBE",
        "name": "SIP / NVRAM Bypass Probe",
        "description": "Attacker probes SIP status or attempts csrutil disable / nvram manipulation to weaken kernel protections.",
        "pattern": r"(csrutil|nvram.*boot-args|csr-active-config|SIP.*disabled|System Integrity Protection.*disable)",
        "detection_query": "process == \"csrutil\" OR (message CONTAINS \"nvram\" AND message CONTAINS \"boot-args\")",
        "hint": "Alert immediately on any csrutil invocation outside Apple's recoveryOS; nvram boot-args writes outside MDM are high fidelity.",
    },
    {
        "stage": 5,
        "ttp": "T1070.002 / EDR-PROCESS-EXIT",
        "name": "EDR Agent Process Termination",
        "description": "EDR sensor process exits unexpectedly after manipulation chain completes — kill signal, crash, or graceful shutdown forced by attacker.",
        "pattern": r"(falcon-sensor|SentinelAgent|CylanceSvc|CbDefense|CarbonBlack|JamfProtect|EPSecurityExtension).*(exit|killed|terminated|crash|signal|SIGKILL|SIGTERM)",
        "detection_query": "message CONTAINS[c] \"falcon\" OR message CONTAINS[c] \"sentinelagent\" AND (message CONTAINS \"exit\" OR message CONTAINS \"terminated\")",
        "hint": "Use EDR self-protection telemetry or OS process-exit events; absence of expected heartbeat beacons is also a detection vector.",
    },
]


def load_lines(path: str) -> list:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return [(i + 1, line.rstrip()) for i, line in enumerate(f) if line.strip()]
    except OSError as e:
        print(f"[ERROR] Cannot open log file: {e}", file=sys.stderr)
        sys.exit(1)


def simulate_chain() -> None:
    print("=" * 72)
    print("EDR KILL CHAIN LAB — Simulate Mode (Blue-Team Training Reference)")
    print("=" * 72)
    print("WARNING: This chain targets non-admin macOS weaknesses. Run only in isolated lab VMs.\n")
    for step in KILL_CHAIN:
        print(f"[Stage {step['stage']}] {step['name']}")
        print(f"  TTP        : {step['ttp']}")
        print(f"  Description: {step['description']}")
        print(f"  Log Pattern: {step['pattern']}")
        print(f"  Query Hint : {step['detection_query']}")
        print(f"  Defender   : {step['hint']}")
        print()
    print(f"Total stages: {len(KILL_CHAIN)}  |  Full chain coverage required to detect complete bypass.")


def hunt_kill_chain(lines: list, verbose: bool) -> None:
    compiled = [(s, re.compile(s["pattern"], re.IGNORECASE)) for s in KILL_CHAIN]
    hits: dict[int, list] = {}

    for lineno, raw in lines:
        for step, rx in compiled:
            if rx.search(raw):
                stage = step["stage"]
                hits.setdefault(stage, []).append((lineno, raw))

    print("=" * 72)
    print("EDR KILL CHAIN LAB — Hunt Mode Results")
    print("=" * 72)

    hit_stages = []
    miss_stages = []

    for step in KILL_CHAIN:
        stage = step["stage"]
        matches = hits.get(stage, [])
        if matches:
            hit_stages.append(stage)
            print(f"[PASS] Stage {stage}: {step['name']}  ({step['ttp']})")
            print(f"       Pattern : {step['pattern']}")
            print(f"       Matches : {len(matches)}")
            for lineno, raw in matches[:3]:
                ts_match = re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", raw)
                ts = ts_match.group(0) if ts_match else "unknown-timestamp"
                print(f"         Line {lineno:>6}  [{ts}]  pattern={step['ttp']}")
                if verbose:
                    print(f"                {raw[:200]}")
            if len(matches) > 3:
                print(f"         ... and {len(matches) - 3} more")
        else:
            miss_stages.append(stage)
            print(f"[MISS] Stage {stage}: {step['name']}  ({step['ttp']})")
            print(f"       Pattern : {step['pattern']}")
            print(f"       Hint    : {step['hint']}")
        print()

    total = len(KILL_CHAIN)
    covered = len(hit_stages)
    print("=" * 72)
    print(f"COVERAGE SUMMARY: {covered}/{total} stages detected  ({100 * covered // total}%)")
    if miss_stages:
        names = [KILL_CHAIN[s - 1]["name"] for s in miss_stages]
        print(f"MISSED STAGES   : {', '.join(str(s) for s in miss_stages)}")
        for name in names:
            print(f"  - {name}")
        print("ACTION: Review log source completeness and update regex patterns for missed stages.")
    else:
        print("RESULT: Full kill-chain coverage confirmed in provided log export.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EDR Kill Chain Lab: blue-team training for macOS non-admin EDR-disable detection.",
        epilog="Example: %(prog)s --mode hunt --verbose /tmp/unified.log",
    )
    parser.add_argument(
        "log_file",
        nargs="?",
        help="Path to plain-text macOS unified log export (required in hunt mode).",
    )
    parser.add_argument(
        "--mode",
        choices=["simulate", "hunt"],
        default="simulate",
        help="'simulate' prints the attack chain; 'hunt' scans a log file (default: simulate).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="In hunt mode, print the full matching log line alongside each stage hit.",
    )
    args = parser.parse_args()

    if args.mode == "hunt":
        if not args.log_file:
            parser.error("log_file is required in hunt mode.")
        lines = load_lines(args.log_file)
        hunt_kill_chain(lines, args.verbose)
    else:
        simulate_chain()


if __name__ == "__main__":
    main()