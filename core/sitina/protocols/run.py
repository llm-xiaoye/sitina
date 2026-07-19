from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from enum import Enum

from sitina.journal.model import validate_identifier

from .permits import AdmissionPermit, PermitError, PermitPurpose


class RunProtocolError(RuntimeError):
    pass


class RunState(str, Enum):
    ACTIVE = "ACTIVE"
    CLOSING = "CLOSING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


TERMINAL = frozenset({RunState.SUCCEEDED, RunState.FAILED, RunState.CANCELLED})


@dataclass(frozen=True)
class RunAggregate:
    run_id: str
    state: RunState
    stream_version: int
    admission_generation: int
    permits: tuple[AdmissionPermit, ...] = ()
    blocking_facts: tuple[str, ...] = ()
    pending_creation_processes: tuple[str, ...] = ()

    @classmethod
    def open(cls, run_id: str) -> tuple["RunAggregate", dict]:
        validate_identifier(run_id, field="run_id")
        return cls(run_id, RunState.ACTIVE, 1, 1), {"schema": "RUN_OPENED_V1", "run_id": run_id, "admission_generation": 1}

    def _expected(self, expected_stream_version: int) -> None:
        if self.stream_version != expected_stream_version:
            raise RunProtocolError("Run stream CAS conflict")

    def grant_permit(
        self,
        *,
        expected_stream_version: int,
        purpose: PermitPurpose,
        scope: str,
        count: int,
        max_depth: int,
        expires_at: str,
        permit_id: str | None = None,
    ) -> tuple["RunAggregate", AdmissionPermit, dict]:
        self._expected(expected_stream_version)
        if self.state in TERMINAL:
            raise RunProtocolError("terminal Run cannot grant Permit")
        if self.state is RunState.CLOSING and purpose is not PermitPurpose.CLOSING_ENTITY_CREATE:
            raise RunProtocolError("Closing permits require the Closing-specific purpose")
        if self.state is RunState.ACTIVE and purpose is PermitPurpose.CLOSING_ENTITY_CREATE:
            raise RunProtocolError("Closing Permit cannot be granted while ACTIVE")
        if count < 1:
            raise PermitError("Permit count must be positive")
        permit = AdmissionPermit(permit_id or f"permit-{uuid.uuid4().hex}", self.run_id, self.admission_generation, purpose, scope, count, max_depth, expires_at)
        updated = replace(self, stream_version=self.stream_version + 1, permits=self.permits + (permit,))
        return updated, permit, {"schema": "PERMIT_GRANTED_V1", "permit_commitment": permit.commitment, "run_id": self.run_id, "stream_version": updated.stream_version}

    def begin_closing(self, *, expected_stream_version: int) -> tuple["RunAggregate", dict]:
        self._expected(expected_stream_version)
        if self.state is not RunState.ACTIVE:
            raise RunProtocolError("BeginClosing requires ACTIVE")
        updated = replace(self, state=RunState.CLOSING, stream_version=self.stream_version + 1, admission_generation=self.admission_generation + 1)
        return updated, {"schema": "RUN_CLOSING_BEGAN_V1", "run_id": self.run_id, "admission_generation": updated.admission_generation}

    def abort_closing(self, *, expected_stream_version: int) -> tuple["RunAggregate", dict]:
        self._expected(expected_stream_version)
        if self.state is not RunState.CLOSING:
            raise RunProtocolError("AbortClosing requires CLOSING")
        updated = replace(self, state=RunState.ACTIVE, stream_version=self.stream_version + 1, admission_generation=self.admission_generation + 1)
        return updated, {"schema": "RUN_CLOSING_ABORTED_V1", "run_id": self.run_id, "admission_generation": updated.admission_generation}

    def add_blocker(self, fact_ref: str) -> "RunAggregate":
        validate_identifier(fact_ref, field="blocking_fact_ref")
        return self if fact_ref in self.blocking_facts else replace(self, blocking_facts=self.blocking_facts + (fact_ref,))

    def remove_blocker(self, fact_ref: str) -> "RunAggregate":
        return replace(self, blocking_facts=tuple(item for item in self.blocking_facts if item != fact_ref))

    def terminal(self, state: RunState, *, expected_stream_version: int) -> tuple["RunAggregate", dict]:
        self._expected(expected_stream_version)
        if state not in TERMINAL or self.state is not RunState.CLOSING:
            raise RunProtocolError("terminal transition requires CLOSING and a terminal target")
        if self.blocking_facts or self.pending_creation_processes:
            raise RunProtocolError("Run has authoritative terminal blockers")
        updated = replace(self, state=state, stream_version=self.stream_version + 1)
        return updated, {"schema": "RUN_TERMINAL_V1", "run_id": self.run_id, "terminal_state": state.value}

