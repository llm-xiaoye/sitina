from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path

from sitina.orchestrator.managed_processes import ManagedProcessError, ManagedProcessManager


class ManagedProcessTests(unittest.TestCase):
    def test_start_status_log_stop_and_cross_manager_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            home = root / "home"
            workspace = root / "workspace"
            home.mkdir()
            workspace.mkdir()
            audit: list[tuple[str, dict[str, object]]] = []
            manager = ManagedProcessManager(
                home,
                workspace=workspace,
                run_id="managed-run",
                audit=lambda event, payload: audit.append((event, dict(payload))),
            )
            quick = manager.start([sys.executable, "-c", "print('API_KEY=hidden')"])
            quick_id = str(quick["process_id"])
            for _ in range(30):
                if manager.status(quick_id)["state"] == "stopped":
                    break
                time.sleep(0.05)
            self.assertEqual(manager.status(quick_id)["state"], "stopped")
            self.assertIn("<redacted>", manager.log(quick_id)["text"])

            long_running = manager.start([sys.executable, "-c", "import time; time.sleep(30)"])
            process_id = str(long_running["process_id"])
            restarted = ManagedProcessManager(
                home,
                workspace=workspace,
                run_id="managed-run",
                audit=lambda event, payload: audit.append((event, dict(payload))),
            )
            self.assertEqual(restarted.status(process_id)["state"], "running")
            stopped = restarted.stop(process_id, timeout_seconds=0.5)
            self.assertEqual(stopped["state"], "stopped")
            cleanup = restarted.cleanup()
            self.assertIn(quick_id, cleanup["stopped"])
            self.assertEqual(cleanup["failures"], [])
            self.assertTrue(any(event == "managed_process_cleanup" for event, _ in audit))

    def test_keep_requires_explicit_authorization_and_is_not_cleaned(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            home = root / "home"
            workspace = root / "workspace"
            home.mkdir()
            workspace.mkdir()
            manager = ManagedProcessManager(home, workspace=workspace, run_id="keep-run")
            with self.assertRaises(ManagedProcessError):
                manager.start([sys.executable, "-c", "import time; time.sleep(30)"], keep=True)
            authorized = ManagedProcessManager(
                home, workspace=workspace, run_id="keep-run", allow_keep=True
            )
            started = authorized.start(
                [sys.executable, "-c", "import time; time.sleep(30)"], keep=True
            )
            process_id = str(started["process_id"])
            cleanup = authorized.cleanup()
            self.assertIn(process_id, cleanup["kept"])
            self.assertNotIn(process_id, cleanup["stopped"])
            authorized.stop(process_id)


if __name__ == "__main__":
    unittest.main()
