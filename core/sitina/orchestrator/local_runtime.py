from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from sitina.constants import SITINA_HOME
from sitina.orchestrator.bplus_production import BPlusProductionRuntime, ProductionRuntimeContext


class JournalNativeLocalRuntime:
    """Provider-free local execution backed only by Production Journal and CAS."""

    def __init__(
        self,
        home: Path = SITINA_HOME,
        *,
        keychain_backend: object | None = None,
        now: int | None = None,
    ) -> None:
        self.home = Path(home).expanduser().resolve(strict=True)
        self.keychain_backend = keychain_backend
        self.now = int(time.time()) if now is None else int(now)

    def execute(
        self,
        goal: str,
        *,
        parent_goal_id: str | None = None,
        backlog_item_id: str | None = None,
    ) -> dict[str, Any]:
        context = ProductionRuntimeContext.load(
            self.home,
            now=self.now,
            keychain_backend=self.keychain_backend,
            allow_simulation=(self.home / ".sitina-bplus-disposable-v1").is_file(),
        )
        journal = context.open_runtime_writer()
        try:
            runtime = BPlusProductionRuntime(
                self.home,
                journal,
                context.authority.resolution,
                now=self.now,
            )
            return dict(
                runtime.create_local_run(
                    goal,
                    cas=context.open_cas(),
                    provider=context.provider,
                    parent_goal_id=parent_goal_id,
                    backlog_item_id=backlog_item_id,
                )
            )
        finally:
            journal.close()


__all__ = ["JournalNativeLocalRuntime"]
