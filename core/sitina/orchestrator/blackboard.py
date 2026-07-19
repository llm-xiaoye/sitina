from __future__ import annotations

import fcntl
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from sitina.constants import SITINA_HOME
from sitina.orchestrator.ledger import RunLedger
from sitina.storage import SitinaStore
from sitina.utils import iso_now, new_id, read_json, redact_text, sha256_text, stable_json, write_json


SAFETY_FIELDS = {"risk_level", "approval_required", "denylist", "permissions", "verification_status", "allowed_scope"}


class BlackboardPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    target_path: str
    op: str
    value: Any
    author_agent: str
    trace_id: str


class BlackboardDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    doc_id: str
    run_id: str
    task_id: str
    author_agent: str
    doc_type: str
    content_summary: str
    artifact_refs: list[str] = Field(default_factory=list)
    related_docs: list[str] = Field(default_factory=list)
    sensitive_redacted: bool = True
    version: int = 1
    created_at: str
    updated_at: str | None = None


class BlackboardVersionConflict(RuntimeError):
    """A compare-and-swap write used a stale document or partition version."""


class Blackboard:
    DOC_TYPES = {
        "claim",
        "evidence",
        "question",
        "conflict",
        "proposal",
        "decision",
        "gate_note",
        "lease_note",
        "arbitration_note",
        "risk_note",
        "test_note",
        "review_note",
        "backlog_candidate",
    }

    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.path = home / "state" / "blackboard.json"
        self.runs_directory = home / "state" / "blackboard_runs"

    def apply(self, patch: dict[str, Any]) -> dict[str, Any]:
        parsed = BlackboardPatch.model_validate(patch)
        pieces = parsed.target_path.split(".")
        if any(piece in SAFETY_FIELDS for piece in pieces):
            raise ValueError("blackboard patch cannot write safety fields")
        if pieces[:2] != ["state", "blackboard"]:
            raise ValueError("blackboard patch target must start with state.blackboard")
        doc = read_json(self.path, default={}) or {}
        cursor = doc
        for piece in pieces[2:-1]:
            cursor = cursor.setdefault(piece, {})
            if not isinstance(cursor, dict):
                raise ValueError("blackboard target traverses non-object")
        leaf = pieces[-1]
        if parsed.op == "set":
            cursor[leaf] = parsed.value
        elif parsed.op == "append":
            cursor.setdefault(leaf, [])
            if not isinstance(cursor[leaf], list):
                raise ValueError("append target must be a list")
            cursor[leaf].append(parsed.value)
        else:
            raise ValueError("blackboard op must be set or append")
        write_json(self.path, doc)
        return doc

    def record_document(
        self,
        *,
        run_id: str,
        task_id: str,
        author_agent: str,
        doc_type: str,
        content_summary: str,
        artifact_refs: list[str] | None = None,
        related_docs: list[str] | None = None,
        expected_version: int | None = None,
    ) -> BlackboardDocument:
        if doc_type not in self.DOC_TYPES:
            raise ValueError(f"blackboard document doc_type not allowed: {doc_type}")
        raw = str(content_summary or "")
        redacted = redact_text(raw).strip()
        sensitive_redacted = redacted != raw
        doc = BlackboardDocument(
            doc_id="bb_" + new_id(),
            run_id=run_id,
            task_id=task_id,
            author_agent=author_agent,
            doc_type=doc_type,
            content_summary=(redacted or "<redacted>")[:1000],
            artifact_refs=artifact_refs or [],
            related_docs=related_docs or [],
            sensitive_redacted=True,
            version=1,
            created_at=iso_now(),
        )
        with self._run_lock(run_id):
            state = self._partition(run_id)
            current_version = int(state.get("version", 0))
            if expected_version is not None and int(expected_version) != current_version:
                self._record_version_conflict(
                    run_id=run_id,
                    task_id=task_id,
                    author_agent=author_agent,
                    doc_id=doc.doc_id,
                    expected_version=int(expected_version),
                    actual_version=current_version,
                )
                raise BlackboardVersionConflict(f"blackboard partition version conflict: expected={expected_version} actual={current_version}")
            documents = state.setdefault("documents", [])
            documents.append(doc.model_dump())
            state.update({"schema_version": "1.0", "run_id": run_id, "version": current_version + 1, "updated_at": iso_now()})
            write_json(self.run_path(run_id), state)
        RunLedger(self.home, self.store).record(
            "blackboard_doc_created",
            run_id=run_id,
            task_id=task_id,
            task_type="chat",
            agent_id=author_agent,
            status="ok",
            reason=f"blackboard {doc_type} document recorded",
            payload=doc.model_dump(),
        )
        self.store.record_audit(
            "blackboard_doc_created",
            doc.model_dump(),
            run_id=run_id,
            trace_id=f"{run_id}:blackboard:{doc.doc_id}",
            agent=author_agent,
            exit_status="ok",
            output_hash=sha256_text(stable_json(doc.model_dump())),
        )
        return doc

    def update_document(
        self,
        *,
        run_id: str,
        doc_id: str,
        author_agent: str,
        expected_version: int,
        content_summary: str | None = None,
        artifact_refs: list[str] | None = None,
        related_docs: list[str] | None = None,
    ) -> BlackboardDocument:
        with self._run_lock(run_id):
            state = self._partition(run_id)
            documents = [item for item in state.get("documents", []) if isinstance(item, dict)]
            index = next((index for index, item in enumerate(documents) if item.get("doc_id") == doc_id), None)
            if index is None:
                raise KeyError(f"blackboard document not found: {doc_id}")
            current = BlackboardDocument.model_validate(documents[index])
            if current.version != int(expected_version):
                self._record_version_conflict(
                    run_id=run_id,
                    task_id=current.task_id,
                    author_agent=author_agent,
                    doc_id=doc_id,
                    expected_version=int(expected_version),
                    actual_version=current.version,
                )
                raise BlackboardVersionConflict(f"blackboard document version conflict: expected={expected_version} actual={current.version}")
            raw_summary = current.content_summary if content_summary is None else str(content_summary)
            redacted = redact_text(raw_summary).strip() or "<redacted>"
            updated = current.model_copy(
                update={
                    "author_agent": author_agent,
                    "content_summary": redacted[:1000],
                    "artifact_refs": list(current.artifact_refs if artifact_refs is None else artifact_refs),
                    "related_docs": list(current.related_docs if related_docs is None else related_docs),
                    "sensitive_redacted": True,
                    "version": current.version + 1,
                    "updated_at": iso_now(),
                }
            )
            documents[index] = updated.model_dump()
            state["documents"] = documents
            state["version"] = int(state.get("version", 0)) + 1
            state["updated_at"] = iso_now()
            write_json(self.run_path(run_id), state)
        RunLedger(self.home, self.store).record(
            "blackboard_doc_updated",
            run_id=run_id,
            task_id=updated.task_id,
            task_type="chat",
            agent_id=author_agent,
            status="ok",
            reason=f"blackboard {updated.doc_type} document updated with CAS",
            payload=updated.model_dump(),
        )
        self.store.record_audit(
            "blackboard_doc_updated",
            updated.model_dump(),
            run_id=run_id,
            trace_id=f"{run_id}:blackboard:{doc_id}:v{updated.version}",
            agent=author_agent,
            exit_status="ok",
            output_hash=sha256_text(stable_json(updated.model_dump())),
        )
        return updated

    def documents(self, run_id: str | None = None, doc_type: str | None = None) -> list[dict[str, Any]]:
        docs: list[dict[str, Any]] = []
        if run_id is not None:
            docs.extend(item for item in self._partition(run_id).get("documents", []) if isinstance(item, dict))
        elif self.runs_directory.exists():
            for path in sorted(self.runs_directory.glob("*.json")):
                state = read_json(path, default={}) or {}
                docs.extend(item for item in state.get("documents", []) if isinstance(item, dict))
        legacy = read_json(self.path, default={}) or {}
        legacy_docs = [item for item in legacy.get("documents", []) if isinstance(item, dict)] if isinstance(legacy, dict) else []
        docs.extend(item for item in legacy_docs if run_id is None or item.get("run_id") == run_id)
        unique: dict[str, dict[str, Any]] = {}
        for item in docs:
            key = str(item.get("doc_id") or sha256_text(stable_json(item)))
            unique.setdefault(key, item)
        docs = list(unique.values())
        if doc_type is not None:
            docs = [item for item in docs if item.get("doc_type") == doc_type]
        return docs

    def run_path(self, run_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", str(run_id)) or ".." in str(run_id):
            raise ValueError("invalid blackboard run_id")
        return self.runs_directory / f"{run_id}.json"

    def partition_version(self, run_id: str) -> int:
        return int(self._partition(run_id).get("version", 0))

    def _partition(self, run_id: str) -> dict[str, Any]:
        value = read_json(self.run_path(run_id), default=None)
        if not isinstance(value, dict):
            return {"schema_version": "1.0", "run_id": run_id, "version": 0, "documents": []}
        if value.get("run_id") not in {None, run_id}:
            raise ValueError("blackboard partition run_id mismatch")
        return value

    @contextmanager
    def _run_lock(self, run_id: str):
        lock_path = self.runs_directory / ".locks" / f"{self.run_path(run_id).stem}.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _record_version_conflict(
        self,
        *,
        run_id: str,
        task_id: str,
        author_agent: str,
        doc_id: str,
        expected_version: int,
        actual_version: int,
    ) -> None:
        payload = {
            "run_id": run_id,
            "doc_id": doc_id,
            "expected_version": expected_version,
            "actual_version": actual_version,
            "conflict_hash": sha256_text(stable_json({"run_id": run_id, "doc_id": doc_id, "expected_version": expected_version, "actual_version": actual_version})),
        }
        RunLedger(self.home, self.store).record(
            "blackboard_version_conflict",
            run_id=run_id,
            task_id=task_id,
            task_type="chat",
            agent_id=author_agent,
            status="blocked",
            reason="blackboard compare-and-swap version conflict",
            payload=payload,
        )
        self.store.record_audit(
            "blackboard_version_conflict",
            payload,
            run_id=run_id,
            trace_id=f"{run_id}:blackboard:{doc_id}:version_conflict",
            agent=author_agent,
            exit_status="blocked",
        )

    def summary(self, run_id: str, max_items: int = 10, doc_type: str | None = None) -> list[dict[str, Any]]:
        docs = self.documents(run_id=run_id, doc_type=doc_type)
        docs.sort(key=lambda item: str(item.get("created_at") or ""))
        out: list[dict[str, Any]] = []
        for doc in docs[-max(1, int(max_items)) :]:
            summary = self._redact_summary(str(doc.get("content_summary") or ""))
            out.append(
                {
                    "document_id": str(doc.get("doc_id") or ""),
                    "author": str(doc.get("author_agent") or ""),
                    "type": str(doc.get("doc_type") or ""),
                    "summary": summary[:1000] if summary else "<redacted>",
                    "created_at": str(doc.get("created_at") or ""),
                    "run_id": str(doc.get("run_id") or ""),
                }
            )
        return out

    def conflicts(self, run_id: str | None = None) -> list[dict[str, Any]]:
        docs = self.documents(run_id, "conflict")
        claim_ids = {doc.get("doc_id") for doc in self.documents(run_id, "claim")}
        return [
            doc
            for doc in docs
            if not doc.get("related_docs") or set(doc.get("related_docs", [])) & claim_ids
        ]

    def _looks_sensitive(self, value: str) -> bool:
        lower = value.lower()
        return any(marker in lower for marker in ("password", "secret", "token", "private key", "api_key", "apikey"))

    def _redact_summary(self, value: str) -> str:
        redacted = redact_text(value)
        markers = ("hunter2", ".env", "anthropic", "openai", "deepseek")
        for marker in markers:
            redacted = redacted.replace(marker, "<redacted>").replace(marker.upper(), "<redacted>").replace(marker.title(), "<redacted>")
        return redacted
