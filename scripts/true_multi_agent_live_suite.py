from __future__ import annotations

import os as _sitina_os
import pwd as _sitina_pwd
import sys as _sitina_sys
_SITINA_ACCOUNT_HOME = _sitina_pwd.getpwuid(_sitina_os.getuid()).pw_dir

import json
import os
import sys
import time
from pathlib import Path

from sitina.orchestrator.true_multi_agent import TrueMultiAgentProductionRuntime


HOME = Path((_SITINA_ACCOUNT_HOME + '/SitinaHub'))


CONTROL_GOAL = (
    "Create a concise, low-risk, read-only plan to verify semantic checksum stability across two deterministic "
    "replays. Use one proposal and an independent review scored on a 0-100 scale. No handoff, debate, "
    "Blackboard write, arbitration, lease, or restart is needed."
)


CASES = (
    (
        "formal-v11-01-capability-control-atlas",
        CONTROL_GOAL,
        {
            "proposal_count": 1,
            "required_protocols": ["proposal", "review"],
            "prohibited_protocols": ["debate", "rework", "handoff", "blackboard", "arbitration", "lease", "checkpoint"],
            "remove_capabilities": {
                "agent-borealis": ["proposal"],
                "agent-cirrus": ["proposal"],
                "agent-forge": ["proposal"],
            },
        },
    ),
    (
        "formal-v11-02-capability-and-independence-control-delta",
        CONTROL_GOAL,
        {
            "proposal_count": 1,
            "required_protocols": ["proposal", "review"],
            "prohibited_protocols": ["debate", "rework", "handoff", "blackboard", "arbitration", "lease", "checkpoint"],
            "add_capabilities": {"agent-delta": ["proposal"]},
            "remove_capabilities": {
                "agent-atlas": ["proposal"],
                "agent-borealis": ["proposal"],
                "agent-cirrus": ["proposal"],
                "agent-forge": ["proposal"],
            },
        },
    ),
    (
        "formal-v11-03-proposal-competition-arbitration",
        "Compare two independently reasoned architectures for a read-only evidence index, have an independent "
        "reviewer score both on a 0-100 scale, and use binding arbitration to prevent dispatch of the losing "
        "technical option. Do not use a lease, handoff, Blackboard, or restart.",
        {
            "proposal_count": 2,
            "required_protocols": ["proposal", "review", "arbitration"],
            "prohibited_protocols": ["debate", "rework", "handoff", "blackboard", "lease", "checkpoint"],
            "budget_filtered_agents": ["agent-cirrus"],
        },
    ),
    (
        "formal-v11-04-two-round-negotiation",
        "Develop competing plans for deterministic evidence compaction. Two proposal authors must inspect the "
        "other proposal, answer concrete objections in a second bounded round with immutable parent hashes, then "
        "receive fresh independent reviews on a 0-100 scale. No handoff, lease, Blackboard, or restart.",
        {
            "proposal_count": 2,
            "required_protocols": ["proposal", "review", "debate"],
            "prohibited_protocols": ["arbitration", "handoff", "blackboard", "lease", "checkpoint"],
        },
    ),
    (
        "formal-v11-05-rework-handoff-accept",
        "Prepare a read-only verification procedure, require the independent reviewer to request one concrete "
        "repair and approve only a new immutable revision, then hand the selected revision to a capable receiver "
        "under a complete contract for execution and independent verification. The first handoff generation is "
        "complete and should be accepted. Score reviews on a 0-100 scale.",
        {
            "proposal_count": 1,
            "required_protocols": ["proposal", "review", "rework", "handoff"],
            "prohibited_protocols": ["debate", "arbitration", "blackboard", "lease", "checkpoint"],
            "force_rework": True,
        },
    ),
    (
        "formal-v11-06-handoff-reject-new-generation-restart",
        "Create a read-only plan and transfer it under a Handoff contract whose first generation deliberately "
        "contains an unresolved mandatory question. The receiver must reject generation 1; a corrected generation "
        "2 must be freshly accepted, executed, independently verified, checkpointed, and resumed without repeating "
        "settled Provider calls. Score review on a 0-100 scale.",
        {
            "proposal_count": 1,
            "required_protocols": ["proposal", "review", "handoff", "checkpoint"],
            "prohibited_protocols": ["debate", "rework", "arbitration", "blackboard", "lease"],
            "force_handoff_reject": True,
            "force_checkpoint_restart": True,
        },
    ),
    (
        "formal-v11-07-blackboard-conflict-arbitration",
        "Produce two competing technical proposals for shared evidence state, independently review both on a "
        "0-100 scale, bind the losing option through arbitration, then have two agents continue through a versioned "
        "Blackboard where the second also attempts a stale-base patch that must conflict and be explicitly merged. "
        "No handoff, lease, or restart.",
        {
            "proposal_count": 2,
            "required_protocols": ["proposal", "review", "arbitration", "blackboard"],
            "prohibited_protocols": ["debate", "rework", "handoff", "lease", "checkpoint"],
            "force_conflict": True,
            "force_stale_blackboard_base": True,
        },
    ),
    (
        "formal-v11-08-rework-lease-reassignment-arbitration",
        "Compare two execution proposals, require a repairable reviewer rejection and immutable rework, arbitrate "
        "the competing technical conclusion, then demonstrate authoritative lease ownership: the first owner fails "
        "before send, scheduling recomputes, a different owner completes under a new fence, and the stale fence is "
        "rejected. Reviews use a 0-100 scale.",
        {
            "proposal_count": 2,
            "required_protocols": ["proposal", "review", "rework", "arbitration", "lease"],
            "prohibited_protocols": ["debate", "handoff", "blackboard", "checkpoint"],
            "force_rework": True,
            "force_reassignment": True,
        },
    ),
    (
        "formal-v11-09-provider-ack-loss-lease-restart",
        "Create a read-only proposal whose Provider acknowledgement is deliberately lost after one physical send; "
        "reconcile it from authoritative remote observation with zero retry. Also demonstrate a pre-send worker loss, "
        "lease reassignment to a different Agent with a fresh fence, then checkpoint and resume without duplicate "
        "Provider calls. Use an independent 0-100 review.",
        {
            "proposal_count": 1,
            "required_protocols": ["proposal", "review", "lease", "checkpoint"],
            "prohibited_protocols": ["debate", "rework", "handoff", "blackboard", "arbitration"],
            "force_provider_unknown": True,
            "force_reassignment": True,
            "force_checkpoint_restart": True,
        },
    ),
    (
        "formal-v11-10-high-risk-handoff-arbitration-provider-unknown",
        "For a security-sensitive but read-only recovery design, obtain two independent proposals and a security "
        "reviewer using a 0-100 score, enforce binding arbitration, then require Handoff generation 1 rejection and "
        "fresh generation 2 verification. Finally inject worker loss after InvocationStarted: preserve "
        "OUTCOME_UNKNOWN, perform no retry, transfer monitoring authority, fail the Run rather than claim success, "
        "and verify checkpoint restart does not repeat settled calls.",
        {
            "proposal_count": 2,
            "required_protocols": ["proposal", "review", "arbitration", "handoff", "checkpoint"],
            "prohibited_protocols": ["debate", "rework", "blackboard", "lease"],
            "force_handoff_reject": True,
            "force_after_start_worker_loss": True,
            "force_checkpoint_restart": True,
        },
    ),
)


def main() -> int:
    runtime = TrueMultiAgentProductionRuntime(HOME)
    failures = 0
    start_index = int(os.environ.get("SITINA_SUITE_START", "1"))
    for index, (label, goal, overrides) in enumerate(CASES, 1):
        if index < start_index:
            continue
        started = time.time()
        print(json.dumps({"suite_event": "case_started", "index": index, "label": label, "started_at": started}), flush=True)
        try:
            result = runtime.execute(goal, label=label, overrides=overrides)
        except Exception as error:
            failures += 1
            print(
                json.dumps(
                    {
                        "suite_event": "case_process_error",
                        "index": index,
                        "label": label,
                        "error_type": type(error).__name__,
                        "error": str(error),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                flush=True,
            )
            continue
        if result["terminal_state"] not in {"SUCCEEDED", "FAILED"}:
            failures += 1
        if result.get("execution_failed_closed") and label != "formal-v11-10-high-risk-handoff-arbitration-provider-unknown":
            failures += 1
        print(
            json.dumps(
                {
                    "suite_event": "case_completed",
                    "index": index,
                    "label": label,
                    "elapsed_seconds": round(time.time() - started, 3),
                    "result": result,
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            flush=True,
        )
    print(json.dumps({"suite_event": "suite_completed", "case_count": len(CASES) - start_index + 1, "failure_count": failures}), flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
