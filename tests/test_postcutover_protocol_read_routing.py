from __future__ import annotations

import argparse
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sitina import cli
from sitina.journal.model import EventEnvelope
from sitina.orchestrator.bplus_production import ProductionRuntimeContext
from sitina.legacy.retirement import LegacyRuntimePolicy


def event(event_type: str, payload: dict, position: int = 1) -> EventEnvelope:
    return EventEnvelope(
        f"event-{position}",
        event_type,
        "default",
        f"run/{payload['run_id']}",
        position,
        position,
        "2026-07-15T00:00:00Z",
        payload,
    )


class ExplodingLegacy:
    manifest_sha256 = "a" * 64

    def get_run(self, _run_id: str):
        raise AssertionError("native run must never consult Legacy")

    def timeline(self, _run_id: str):
        raise AssertionError("native run must never consult Legacy")

    def list_runs(self, *, limit=None):
        raise AssertionError("native run must never consult Legacy")


class LegacyFixture:
    manifest_sha256 = "b" * 64

    def get_run(self, run_id: str):
        return {"run_id": run_id} if run_id == "legacy-run" else None

    def timeline(self, run_id: str):
        if run_id != "legacy-run":
            return []
        return [
            {
                "event_type": "proposal_submitted",
                "payload_json": {"proposal_id": "legacy-proposal"},
            }
        ]


def context(events: tuple[EventEnvelope, ...], legacy) -> ProductionRuntimeContext:
    return ProductionRuntimeContext(
        Path("/controlled"),
        None,
        {},
        None,
        SimpleNamespace(events=events),
        legacy,
        LegacyRuntimePolicy(True, True, True, False, False, False, None, False),
    )


class PostCutoverProtocolReadRoutingTests(unittest.TestCase):
    def test_native_protocol_read_never_consults_legacy(self) -> None:
        run_id = "native-run"
        ctx = context(
            (
                event("run.created", {"run_id": run_id}, 1),
                event(
                    "protocol.proposal.submitted",
                    {"run_id": run_id, "proposal_id": "proposal-native"},
                    2,
                ),
            ),
            ExplodingLegacy(),
        )
        result = ctx.protocol_view(run_id, "proposals")
        self.assertEqual(result["storage_class"], "NATIVE_JOURNAL")
        self.assertEqual(result["reader_generation"], "bplus-journal-v1")
        self.assertFalse(result["legacy_adapter_used"])
        self.assertFalse(result["fallback_used"])
        self.assertEqual(result["event_count"], 1)

    def test_legacy_protocol_read_is_explicit_frozen_snapshot(self) -> None:
        result = context((), LegacyFixture()).protocol_view("legacy-run", "proposals")
        self.assertEqual(result["storage_class"], "LEGACY_SNAPSHOT")
        self.assertEqual(result["reader_generation"], "legacy-frozen-snapshot-v1")
        self.assertTrue(result["legacy_adapter_used"])
        self.assertFalse(result["fallback_used"])
        self.assertEqual(result["event_count"], 1)

    def test_unknown_run_does_not_claim_fallback(self) -> None:
        result = context((), LegacyFixture()).protocol_view("absent", "effects")
        self.assertEqual(result["status"], "not_found")
        self.assertEqual(result["storage_class"], "NOT_FOUND")
        self.assertFalse(result["legacy_adapter_used"])
        self.assertFalse(result["fallback_used"])

    def test_native_entity_lookup_never_consults_legacy(self) -> None:
        run_id = "native-run"
        ctx = context(
            (
                event(
                    "protocol.handoff.offered",
                    {"run_id": run_id, "handoff_id": "handoff-native"},
                    1,
                ),
            ),
            ExplodingLegacy(),
        )
        result = ctx.find_protocol_entity(
            "handoff", "handoff-native", id_fields=("handoff_id",)
        )
        self.assertEqual(result["storage_class"], "NATIVE_JOURNAL")
        self.assertFalse(result["legacy_adapter_used"])

    def test_cli_proposals_uses_bplus_protocol_reader(self) -> None:
        expected = {
            "status": "ok",
            "run_exists": True,
            "storage_class": "NATIVE_JOURNAL",
            "events": [],
        }
        fake = SimpleNamespace(protocol_view=lambda run_id, family: expected)
        args = argparse.Namespace(proposals_cmd="list", run_id="native-run")
        with patch.object(cli, "_bplus_installed", return_value=True), patch.object(
            cli, "_bplus_context", return_value=fake
        ):
            self.assertEqual(cli.cmd_proposals(args), 0)
        self.assertEqual(cli._LAST_PRINTED_JSON, expected)

    def test_replay_fails_closed_when_a_journal_cas_reference_is_missing(self) -> None:
        run_id = "native-run"
        created = event("run.created", {"run_id": run_id}, 1)
        referenced = EventEnvelope(
            "event-2",
            "protocol.external.result.pipeline.published",
            "default",
            f"run/{run_id}",
            2,
            2,
            "2026-07-15T00:00:00Z",
            {"run_id": run_id},
            ("cas:" + "a" * 64,),
        )
        ctx = context((created, referenced), ExplodingLegacy())
        with patch.object(
            ProductionRuntimeContext,
            "_verify_cas_reference",
            side_effect=FileNotFoundError("missing"),
        ):
            result = ctx.replay_run(run_id)
        self.assertEqual(result["status"], "replay_failed_closed")
        self.assertEqual(result["external_call_count"], 0)
        self.assertEqual(result["effect_execution_count"], 0)
        self.assertEqual(result["legacy_read_count"], 0)
        self.assertFalse(result["fallback_used"])


if __name__ == "__main__":
    unittest.main()
