from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from sitina.cas.local import LocalCAS
from sitina.runtime.tool_output import ToolOutputCoordinator
from sitina.security.key_provider import InMemoryKeyProvider


class ToolOutputLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
        self.cas = LocalCAS.open(self.home, InMemoryKeyProvider())
        self.events: list[dict[str, object]] = []

    def _append(self, event: dict[str, object]) -> int:
        for reference in event["_object_refs"]:
            self.cas.open_verified(self.cas.resolve_reference(str(reference)))
        self.events.append(dict(event))
        return len(self.events)

    def test_runtime_chunks_publish_before_one_terminal_event_then_are_removed(self) -> None:
        outputs = ToolOutputCoordinator(self.home, self.cas, max_capture_bytes=12)
        outputs.begin(tool_call_id="tool-call-1", run_id="run-1", started_at="2026-07-18T00:00:00Z")
        outputs.append("tool-call-1", channel="stdout", data=b"hello ")
        outputs.append("tool-call-1", channel="stderr", data=b"warn")
        outputs.append("tool-call-1", channel="stdout", data=b" world")
        stream = outputs._stream_root("tool-call-1")
        self.assertEqual(len(tuple(stream.glob("*.chunk"))), 3)

        receipt = outputs.complete(
            "tool-call-1",
            status="SUCCEEDED",
            exit_code=0,
            completed_at="2026-07-18T00:00:01Z",
            append_event=self._append,
        )
        self.assertEqual(receipt["state"], "CLEANED")
        self.assertFalse(stream.exists())
        self.assertEqual(len(self.events), 1)
        event = self.events[0]
        self.assertEqual(event["event_type"], "tool.completed")
        self.assertNotIn("stdout", event)
        self.assertNotIn("stderr", event)
        self.assertTrue(event["truncated"])
        self.assertEqual(event["captured_bytes"], 12)
        self.assertEqual(event["dropped_bytes"], 4)

        restored = outputs.open_result(str(receipt["result_manifest_ref"]))
        self.assertEqual(restored["stdout"], b"hello  w")
        self.assertEqual(restored["stderr"], b"warn")
        self.assertTrue(restored["truncated"])

    def test_journal_failure_retains_runtime_stream_and_retry_reuses_cas(self) -> None:
        outputs = ToolOutputCoordinator(self.home, self.cas)
        outputs.begin(tool_call_id="tool-call-retry", run_id="run-2", started_at="2026-07-18T00:00:00Z")
        outputs.append("tool-call-retry", channel="stdout", data=b"durable result")
        first_refs: list[str] = []

        def reject(event: dict[str, object]) -> int:
            first_refs.extend(str(item) for item in event["_object_refs"])
            raise RuntimeError("injected Journal outage")

        with self.assertRaisesRegex(RuntimeError, "Journal outage"):
            outputs.complete(
                "tool-call-retry",
                status="FAILED",
                exit_code=9,
                completed_at="2026-07-18T00:00:02Z",
                append_event=reject,
            )
        receipt = outputs.load("tool-call-retry")
        self.assertEqual(receipt["state"], "CAS_PUBLISHED")
        self.assertTrue(outputs._stream_root("tool-call-retry").is_dir())
        self.assertEqual(first_refs, receipt["chunk_refs"])

        completed = outputs.complete(
            "tool-call-retry",
            status="FAILED",
            exit_code=9,
            completed_at="2026-07-18T00:00:02Z",
            append_event=self._append,
        )
        self.assertEqual(completed["state"], "CLEANED")
        self.assertEqual(completed["chunk_refs"], first_refs)
        self.assertEqual(self.events[0]["terminal_status"], "FAILED")

    def test_crash_after_journal_cleans_on_retry_without_second_event(self) -> None:
        crashed = False

        def fault(boundary: str) -> None:
            nonlocal crashed
            if boundary == "after_tool_completed_journal" and not crashed:
                crashed = True
                raise RuntimeError("injected post-Journal crash")

        outputs = ToolOutputCoordinator(self.home, self.cas, fault_injector=fault)
        outputs.begin(tool_call_id="tool-call-crash", run_id="run-3", started_at="2026-07-18T00:00:00Z")
        outputs.append("tool-call-crash", channel="stdout", data=b"complete")
        with self.assertRaisesRegex(RuntimeError, "post-Journal"):
            outputs.complete(
                "tool-call-crash",
                status="SUCCEEDED",
                exit_code=0,
                completed_at="2026-07-18T00:00:03Z",
                append_event=self._append,
            )
        self.assertEqual(outputs.load("tool-call-crash")["state"], "JOURNAL_COMMITTED")
        self.assertEqual(len(self.events), 1)
        completed = outputs.complete(
            "tool-call-crash",
            status="SUCCEEDED",
            exit_code=0,
            completed_at="2026-07-18T00:00:03Z",
            append_event=self._append,
        )
        self.assertEqual(completed["state"], "CLEANED")
        self.assertEqual(len(self.events), 1)


if __name__ == "__main__":
    unittest.main()
