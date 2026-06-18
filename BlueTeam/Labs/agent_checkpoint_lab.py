"""
AI Agent Human-in-the-Loop Checkpoint Lab

Simulates an AI security agent executing tasks with explicit human approval
gates at privilege escalation and data access decision points.

Usage examples:
    python agent_checkpoint_lab.py --scenario recon
    python agent_checkpoint_lab.py --scenario escalate --log-file audit.jsonl
    python agent_checkpoint_lab.py --scenario exfiltrate --auto-approve
    python agent_checkpoint_lab.py --scenario escalate --auto-approve --log-file unsafe_audit.jsonl
"""

import argparse
import json
import sys
from datetime import datetime, timezone


SCENARIOS = {
    "recon": [
        {"name": "enumerate_hosts", "desc": "Scan local subnet for active hosts", "risk": 2, "checkpoint": False},
        {"name": "port_scan", "desc": "Run port scan on discovered hosts", "risk": 4, "checkpoint": False},
        {"name": "service_fingerprint", "desc": "Fingerprint services on open ports", "risk": 5, "checkpoint": True},
        {"name": "vuln_lookup", "desc": "Query CVE database for identified service versions", "risk": 3, "checkpoint": False},
        {"name": "credential_spray", "desc": "Attempt default credentials on discovered services", "risk": 9, "checkpoint": True},
    ],
    "escalate": [
        {"name": "local_enum", "desc": "Enumerate local user privileges and groups", "risk": 3, "checkpoint": False},
        {"name": "suid_search", "desc": "Search for SUID binaries on filesystem", "risk": 5, "checkpoint": True},
        {"name": "sudo_abuse", "desc": "Exploit misconfigured sudo rule to gain root shell", "risk": 10, "checkpoint": True},
        {"name": "shadow_read", "desc": "Read /etc/shadow to extract password hashes", "risk": 10, "checkpoint": True},
        {"name": "persist_cron", "desc": "Install cron job for persistence as root", "risk": 10, "checkpoint": True},
    ],
    "exfiltrate": [
        {"name": "dir_traverse", "desc": "Traverse home directories for sensitive files", "risk": 4, "checkpoint": False},
        {"name": "db_dump", "desc": "Dump application database tables", "risk": 8, "checkpoint": True},
        {"name": "key_harvest", "desc": "Collect SSH keys and API tokens from disk", "risk": 9, "checkpoint": True},
        {"name": "compress_stage", "desc": "Archive harvested data into encrypted zip", "risk": 7, "checkpoint": True},
        {"name": "dns_tunnel", "desc": "Exfiltrate data via DNS tunnel to external host", "risk": 10, "checkpoint": True},
    ],
}

RISK_LABELS = {range(1, 4): "LOW", range(4, 7): "MEDIUM", range(7, 10): "HIGH", range(10, 11): "CRITICAL"}


def risk_label(score: int) -> str:
    for r, label in RISK_LABELS.items():
        if score in r:
            return label
    return "UNKNOWN"


def evaluate_action(action_meta: dict) -> dict:
    score = action_meta["risk"]
    label = risk_label(score)
    justifications = {
        "CRITICAL": "Action directly enables system compromise or data breach — gate required.",
        "HIGH": "Action significantly expands attacker capability — operator review needed.",
        "MEDIUM": "Action is intrusive but recoverable — checkpoint recommended.",
        "LOW": "Routine reconnaissance — no gate required.",
    }
    return {
        "action": action_meta["name"],
        "risk_score": score,
        "risk_label": label,
        "requires_checkpoint": action_meta["checkpoint"],
        "justification": justifications.get(label, "Unknown risk level."),
    }


def write_audit_log(events: list, log_file: str) -> None:
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
    except OSError as e:
        print(f"[WARN] Could not write audit log: {e}", file=sys.stderr)


def prompt_operator(action_meta: dict, gate_info: dict) -> bool:
    print(f"\n{'='*60}")
    print(f"  CHECKPOINT: {action_meta['name']}")
    print(f"  Description : {action_meta['desc']}")
    print(f"  Risk Score  : {gate_info['risk_score']}/10 [{gate_info['risk_label']}]")
    print(f"  Justification: {gate_info['justification']}")
    print(f"{'='*60}")
    try:
        answer = input("  Operator approval required. Allow? [y/N]: ").strip().lower()
        return answer == "y"
    except (EOFError, KeyboardInterrupt):
        print("\n[INFO] Input interrupted — defaulting to BLOCK.")
        return False


def run_scenario(scenario: str, auto_approve: bool, log_file: str | None) -> None:
    actions = SCENARIOS.get(scenario)
    if not actions:
        print(f"[ERROR] Unknown scenario '{scenario}'. Choose: {', '.join(SCENARIOS)}", file=sys.stderr)
        sys.exit(1)

    mode_banner = "[AUTO-APPROVE MODE — INSECURE PATH SIMULATION]" if auto_approve else "[HUMAN-IN-THE-LOOP MODE — SECURE PATH]"
    print(f"\n{'#'*60}")
    print(f"  Scenario: {scenario.upper()}   {mode_banner}")
    print(f"{'#'*60}\n")

    audit_events = []
    blocked_count = 0
    allowed_count = 0

    for action in actions:
        gate_info = evaluate_action(action)
        ts = datetime.now(timezone.utc).isoformat()
        event = {
            "timestamp": ts,
            "scenario": scenario,
            "action": action["name"],
            "description": action["desc"],
            "risk_score": gate_info["risk_score"],
            "risk_label": gate_info["risk_label"],
            "checkpoint": gate_info["requires_checkpoint"],
            "mode": "auto-approve" if auto_approve else "human-in-the-loop",
        }

        if not gate_info["requires_checkpoint"]:
            print(f"  [EXEC]  {action['name']:<22} risk={gate_info['risk_score']:>2}/10 [{gate_info['risk_label']:<8}]  → AUTO-ALLOWED (no gate)")
            event["decision"] = "ALLOWED"
            event["gate_fired"] = False
            allowed_count += 1
        elif auto_approve:
            print(f"  [EXEC]  {action['name']:<22} risk={gate_info['risk_score']:>2}/10 [{gate_info['risk_label']:<8}]  → AUTO-APPROVED ⚠ (checkpoint bypassed)")
            event["decision"] = "ALLOWED"
            event["gate_fired"] = False
            event["bypass_warning"] = "Checkpoint skipped by auto-approve flag"
            allowed_count += 1
        else:
            approved = prompt_operator(action, gate_info)
            if approved:
                print(f"  [EXEC]  {action['name']:<22} risk={gate_info['risk_score']:>2}/10 [{gate_info['risk_label']:<8}]  → ALLOWED by operator")
                event["decision"] = "ALLOWED"
                event["gate_fired"] = True
                allowed_count += 1
            else:
                print(f"  [BLOCK] {action['name']:<22} risk={gate_info['risk_score']:>2}/10 [{gate_info['risk_label']:<8}]  → BLOCKED by operator")
                event["decision"] = "BLOCKED"
                event["gate_fired"] = True
                blocked_count += 1
                audit_events.append(event)
                if log_file:
                    write_audit_log(audit_events, log_file)
                    audit_events = []
                print(f"\n[INFO] Agent halted at '{action['name']}'. Remaining actions skipped.\n")
                break

        audit_events.append(event)
        if log_file:
            write_audit_log(audit_events, log_file)
            audit_events = []

    total = allowed_count + blocked_count
    print(f"\n{'='*60}")
    print(f"  AUDIT SUMMARY — Scenario: {scenario}")
    print(f"  Mode     : {'AUTO-APPROVE (insecure)' if auto_approve else 'Human-in-the-loop (secure)'}")
    print(f"  Actions  : {total} total | {allowed_count} allowed | {blocked_count} blocked")
    if log_file:
        print(f"  Audit log: {log_file}")
    print(f"{'='*60}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI Agent Human-in-the-Loop Checkpoint Lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Scenarios: recon, escalate, exfiltrate",
    )
    parser.add_argument("--scenario", required=True, choices=list(SCENARIOS), help="Attack scenario to simulate")
    parser.add_argument("--auto-approve", action="store_true", help="Bypass all checkpoints (demonstrates insecure path)")
    parser.add_argument("--log-file", metavar="PATH", help="Append JSONL audit records to this file")
    args = parser.parse_args()

    run_scenario(args.scenario, args.auto_approve, args.log_file)


if __name__ == "__main__":
    main()