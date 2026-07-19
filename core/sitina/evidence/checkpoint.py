from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


@dataclass(frozen=True)
class PreTerminalCheckpoint:
    run_id: str
    section_hashes: Mapping[str, str]
    checkpoint_hash: str

    @classmethod
    def build(
        cls,
        *,
        run_id: str,
        task_graph: Mapping[str, object],
        blackboard: Mapping[str, object],
        protocols: Mapping[str, object],
        obligations: Mapping[str, object],
        effects: Mapping[str, object],
        eligibility: Mapping[str, object],
        object_manifest: Mapping[str, object],
    ) -> "PreTerminalCheckpoint":
        validate_identifier(run_id, field="run_id")
        sections = {
            "task_graph": task_graph,
            "blackboard": blackboard,
            "protocols": protocols,
            "obligations": obligations,
            "effects": effects,
            "eligibility": eligibility,
            "object_manifest": object_manifest,
        }
        hashes = {
            name: domain_hash("PRETERMINAL_CHECKPOINT_SECTION", canonical_json_bytes({"name": name, "value": dict(value)}))
            for name, value in sections.items()
        }
        checkpoint_hash = domain_hash(
            "PRETERMINAL_CHECKPOINT",
            canonical_json_bytes({"schema": "PRETERMINAL_CHECKPOINT_V1", "run_id": run_id, "section_hashes": hashes}),
        )
        return cls(run_id, hashes, checkpoint_hash)

