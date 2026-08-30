"""Independent Journal/CAS state for ordinary conversation lifecycle.

This is deliberately separate from both Code Mode execution authority and
Legacy B+ production state.  It stores session history and mode changes only;
it cannot authorize file mutation, Provider canaries, or deployment.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from sitina.authority.model import AuthorityResolution, AuthorityState
from sitina.cas.local import LocalCAS
from sitina.journal.local import LocalJournal
from sitina.journal.model import canonical_json_bytes
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider
from sitina.storage import SitinaStore


class SessionRuntimeContext:
    """Current ordinary-session state, independent of Legacy B+ and Code Mode."""

    namespace_kind = "session"
    epoch_root = "session-epoch-1"

    def __init__(
        self,
        home: Path,
        provider: Any,
        *,
        source_root: Path,
        source_manifest_hash: str,
        session_instance_id: str | None = None,
    ):
        self.home = Path(home).expanduser().resolve(strict=True)
        root_stat = os.stat(self.home, follow_symlinks=False)
        self.provider = provider
        self.session_instance_id = str(session_instance_id or ("session-instance-" + secrets.token_hex(16)))
        if not self.session_instance_id.strip():
            raise ValueError("session runtime requires a session instance identity")
        self.source_root = source_root
        self.source_manifest_hash = source_manifest_hash
        self.journal_id = "session-journal-" + hashlib.sha256(str(self.home).encode()).hexdigest()[:24]
        self.genesis_hash = hashlib.sha256(
            canonical_json_bytes({
                "schema": "SITINA_SESSION_RUNTIME_IDENTITY_V1",
                "home": str(self.home),
                "root_identity": f"{root_stat.st_dev}:{root_stat.st_ino}",
                "journal_id": self.journal_id,
                "epoch_root": self.epoch_root,
                "source_manifest_hash": source_manifest_hash,
            })
        ).hexdigest()
        self.genesis = SimpleNamespace(
            journal_id=self.journal_id,
            epoch_root=self.epoch_root,
            genesis_hash=self.genesis_hash,
        )
        now = int(time.time())
        self.authority = SimpleNamespace(
            resolution=AuthorityResolution(
                AuthorityState.JOURNAL_WRITER_AUTHORIZED,
                resolution_id=self.genesis_hash,
                input_frontier_hash=self.genesis_hash,
                input_hash=self.genesis_hash,
                resolver_binary_hash=hashlib.sha256(b"sitina-session-runtime-v1").hexdigest(),
                resolver_profile="sitina-session-runtime-v1",
                issued_at=now - 1,
                expires_at=now + 3600,
                reason="independent ordinary session state",
            ),
            events=(),
        )

    @classmethod
    def open(
        cls,
        home: Path,
        *,
        provider: Any | None = None,
        source_root: Path | None = None,
        session_instance_id: str | None = None,
    ) -> "SessionRuntimeContext":
        root = Path(home).expanduser().resolve(strict=True)
        (root / ".sitina-session-runtime-v1").touch(exist_ok=True)
        SitinaStore(root).init_db()
        source = Path(source_root).expanduser().resolve(strict=True) if source_root is not None else Path(__file__).resolve().parents[3]
        identity_paths = (
            "core/sitina/conversation/context.py",
            "core/sitina/conversation/fast_runtime.py",
            "core/sitina/conversation/models.py",
            "core/sitina/conversation/persistence.py",
            "core/sitina/conversation/runtime.py",
            "core/sitina/conversation/session_runtime.py",
            "core/sitina/conversation/state.py",
            "core/sitina/conversation/router.py",
            "config/context_policy.json",
            "config/conversation_router.json",
        )
        records: list[dict[str, str]] = []
        for relative in identity_paths:
            path = source / relative
            if path.is_file() and not path.is_symlink():
                records.append({
                    "path": relative,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                })
            else:
                records.append({"path": relative, "sha256": "absent"})
        source_manifest_hash = hashlib.sha256(canonical_json_bytes(records)).hexdigest()
        if provider is None:
            from sitina.security.macos_keychain import MacOSKeychainProvider
            namespace = hashlib.sha256(str(root).encode()).hexdigest()[:24]
            provider = MacOSKeychainProvider(environment="sitina-session", namespace=namespace)
        return cls(
            root,
            provider,
            source_root=source,
            source_manifest_hash=source_manifest_hash,
            session_instance_id=session_instance_id,
        )

    @property
    def events(self) -> tuple[Any, ...]:
        return ()

    def open_runtime_writer(self) -> LocalJournal:
        return LocalJournal.open(
            self.home,
            JournalAuthProvider(self.provider),
            journal_id=self.journal_id,
            epoch=1,
            namespace_kind=self.namespace_kind,
            authority_resolution=self.authority.resolution,
            genesis_hash=self.genesis_hash,
        )

    def open_runtime_state_reader(self) -> LocalJournal:
        return self.open_runtime_writer()

    def open_verified_journal_reader(self) -> LocalJournal:
        return self.open_runtime_state_reader()

    def open_cas(self) -> LocalCAS:
        return LocalCAS.open(
            self.home,
            self.provider,
            namespace_kind=self.namespace_kind,
            authority_resolution=self.authority.resolution,
            genesis_hash=self.genesis_hash,
        )

    def open_cas_reader(self) -> LocalCAS:
        return self.open_cas()
