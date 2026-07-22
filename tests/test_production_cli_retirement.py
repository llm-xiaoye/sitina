from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sitina import cli


class ProductionCliRetirementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name)
        (self.home / ".sitina-clean-acceptance-v1").write_text("protected\n", encoding="utf-8")
        (self.home / "config").mkdir()
        (self.home / "config/sitina.yaml").write_text(
            json.dumps(
                {
                    "state_source_of_truth": "canonical_journal",
                    "storage_authority": {
                        "canonical_source": "journal",
                        "content_source": "cas",
                        "projection_role": "disposable_rebuildable_view",
                        "legacy_enabled": False,
                        "legacy_read_enabled": False,
                        "legacy_fallback_enabled": False,
                        "legacy_write_enabled": False,
                        "active_business_jsonl_enabled": False,
                        "missing_legacy_is_valid": True,
                    },
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_protected_home_blocks_every_cli_surface_that_depends_on_retired_state(self) -> None:
        # `agent` is intentionally NOT here: the current `sitina agent` builds
        # the Journal/CAS-native AutonomousRuntime and depends on no retired
        # Legacy state, so it is the supported production coder entry (M1.6).
        commands = (
            ["goal", "list"],
            ["backlog", "list"],
            ["plan", "show", "goal-old"],
            ["obsidian", "search", "needle"],
            ["worktree", "prepare"],
            ["run", "graph", "run-old"],
            ["mcp", "invoke", "server", "tool", "--mock"],
        )
        retired_files = (
            "active_conversation.json",
            "autonomy.json",
            "blackboard.json",
            "handoffs.json",
            "leases.json",
            "run_state.json",
            "side_effects.json",
        )
        with patch.object(cli, "SITINA_HOME", self.home):
            for command in commands:
                with self.subTest(command=command):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        code = cli.main(list(command))
                    payload = json.loads(output.getvalue())
                    self.assertEqual(code, 3)
                    self.assertEqual(payload["status"], "blocked")
                    self.assertFalse(payload["legacy_read_enabled"])
                    self.assertFalse(payload["legacy_write_enabled"])
                    self.assertFalse(payload["fallback_attempted"])
        self.assertFalse((self.home / "data/sitina.db").exists())
        for name in retired_files:
            self.assertFalse((self.home / "state" / name).exists())


if __name__ == "__main__":
    unittest.main()
