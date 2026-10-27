from __future__ import annotations

"""Recovery orchestration for the persistent Loop host."""

import json
import os
import re
from typing import Any, Callable, Mapping

from .coordinator import LoopBackend
from .model import ControlIntent, PersistenceFenced, RecoveryNotConnected, TaskConflict, TaskStatus


def validate_recovery_descriptor_identity(
    descriptor: Mapping[str, Any],
    host_descriptor_context: Mapping[str, str],
    *,
    provider_response_disposition: Mapping[str, Any] | None = None,
    software_update_transition: Mapping[str, Any] | None = None,
    assisted_diagnostic_root: str | None = None,
    cancel_reconciliation: Mapping[str, Any] | None = None,
) -> str | None:
    """Keep source changes bound to a durable, explicitly confirmed transition."""
    assisted = (
        isinstance(assisted_diagnostic_root, str)
        and os.path.isabs(assisted_diagnostic_root)
        and os.environ.get("SITINA_ASSISTED_DIAGNOSTIC_ROOT") == assisted_diagnostic_root
    )
    original_source = descriptor.get("software_identity")
    current_source = host_descriptor_context["software_identity"]
    if cancel_reconciliation is not None:
        receipt = cancel_reconciliation
        request = receipt.get('request')
        if (provider_response_disposition is not None or software_update_transition is not None
                or receipt.get('schema') != 'SITINA_LOOP_CANCEL_RECONCILIATION_V1'
                or receipt.get('authorization_source') != 'native_control_cancel'
                or receipt.get('decision') != 'CANCEL_WITHOUT_REPLAY'
                or receipt.get('successor') != 'CANCEL_ONLY'
                or receipt.get('business_dispatch_allowed') is not False
                or receipt.get('host_descriptor_context') != dict(host_descriptor_context)
                or not isinstance(request, Mapping) or request.get('confirm_cancel') is not True
                or request.get('from_software_identity') != original_source
                or request.get('to_software_identity') != current_source
                or any(not isinstance(value, str) or re.fullmatch(r'source:[0-9a-f]{64}', value) is None
                       for value in (original_source, current_source))):
            raise ValueError('cancel-only source transition is incompatible with this Host')
        for key in ('provider_identity', 'environment_ref', 'capability_snapshot_id', 'config_identity'):
            if descriptor.get(key) != host_descriptor_context[key]:
                raise ValueError('cancel-only transition cannot change ' + key)
        return 'explicit_cancel_without_business_replay'
    if software_update_transition is not None:
        update = software_update_transition
        request = update.get("request")
        if (
            update.get("schema") != "SITINA_LOOP_SOFTWARE_UPDATE_TRANSITION_V1"
            or update.get("authorization_source") != "native_control_resume"
            or update.get("original_software_identity") != original_source
            or update.get("host_descriptor_context") != dict(host_descriptor_context)
            or not isinstance(request, Mapping)
            or set(request) != {"decision", "from_software_identity", "to_software_identity"}
            or request.get("decision") != "CONTINUE_ON_UPDATED_SOFTWARE"
            or request.get("to_software_identity") != current_source
            or request.get("from_software_identity") == current_source
            or any(not isinstance(value, str) or re.fullmatch(r"source:[0-9a-f]{64}", value) is None
                   for value in (original_source, current_source, request.get("from_software_identity")))
        ):
            raise ValueError("software update transition is incompatible with this host")
    if assisted:
        if any(not isinstance(value, str) or re.fullmatch(r"source:[0-9a-f]{64}", value) is None
               for value in (original_source, current_source)):
            raise ValueError("assisted diagnostic source identity is invalid")
    if provider_response_disposition is not None:
        request = provider_response_disposition.get("request")
        recorded_context = provider_response_disposition.get("host_descriptor_context")
        expected_context = dict(host_descriptor_context)
        if (assisted or software_update_transition is not None) and isinstance(recorded_context, Mapping):
            # The old UNKNOWN disposition keeps its original authorized source pair.
            # A later diagnostic code change does not renew or rewrite that decision.
            historical_source = recorded_context.get("software_identity")
            if (not isinstance(historical_source, str)
                    or re.fullmatch(r"source:[0-9a-f]{64}", historical_source) is None):
                raise ValueError("Provider recovery source transition is incompatible with this host")
            expected_context["software_identity"] = historical_source
        if (
            provider_response_disposition.get("authorization_source") != "native_control_resume"
            or provider_response_disposition.get("decision") != "ABANDON_MISSING_PROVIDER_RESPONSE"
            or not isinstance(request, Mapping)
            or request.get("from_software_identity") != original_source
            or request.get("to_software_identity") != expected_context["software_identity"]
            or recorded_context != expected_context
        ):
            raise ValueError("Provider recovery source transition is incompatible with this host")
    for key in ("provider_identity", "environment_ref", "capability_snapshot_id", "software_identity", "config_identity"):
        if key == "capability_snapshot_id" and isinstance(descriptor.get("capability_binding"), Mapping):
            binding = descriptor["capability_binding"]
            if descriptor.get(key) != binding.get("snapshot_id"):
                raise ValueError("task descriptor capability snapshot differs from its binding")
            continue
        if key == "software_identity" and (
            assisted or provider_response_disposition is not None or software_update_transition is not None
        ):
            continue
        if descriptor.get(key) != host_descriptor_context[key]:
            raise ValueError(f"task descriptor {key} is incompatible with this host")
    if software_update_transition is not None:
        return "software_update_recovery:" + json.dumps(
            {"resume_request_id": software_update_transition["resume_request_id"],
             "descriptor_software_identity": original_source,
             "host_software_identity": current_source,
             "original_descriptor_retained": True},
            sort_keys=True, separators=(",", ":"),
        )
    if assisted:
        return "assisted_diagnostic_recovery:" + json.dumps(
            {"source_root": assisted_diagnostic_root,
             "descriptor_software_identity": original_source,
             "host_software_identity": current_source,
             "source_changed_from_descriptor": original_source != current_source,
             "original_descriptor_retained": True,
             "independent_acceptance_credit": "NONE"},
            sort_keys=True, separators=(",", ":"),
        )
    return None

class RecoveryCoordinator:
    def __init__(
        self,
        backend: LoopBackend,
        *,
        descriptor_validator: Callable[..., str | None] | None = None,
    ) -> None:
        self.backend = backend
        self.descriptor_validator = descriptor_validator

    def bootstrap_candidates(self) -> tuple[str, ...]:
        # Cold replay shares the Backend cache with background obligation scans.
        # Keep the event snapshot and the whole projection in one state boundary.
        with self.backend._state_lock:
            candidates: list[str] = []
            for task_id in self.backend.task_ids():
                task = self.backend._project(task_id, self.backend.store.task_events(task_id))
                if task.is_terminal or task.run_instance_id == self.backend.run_instance_id:
                    continue
                if (
                    task.resume_request_id
                    or task.control_intent in {ControlIntent.RUN, ControlIntent.CANCEL}
                    or not task.descriptor_ref
                ):
                    candidates.append(task_id)
            return tuple(sorted(candidates))

    def recover(self, task_id: str, *, explicit_resume: bool = False):
        try:
            return self.backend.recover_task(
                task_id,
                explicit_resume=explicit_resume,
                descriptor_validator=self.descriptor_validator,
            )
        except (PersistenceFenced, RecoveryNotConnected, TaskConflict, ValueError, KeyError) as error:
            with self.backend._state_lock:
                task = self.backend._project(task_id, self.backend.store.task_events(task_id))
                if task.is_terminal:
                    return task
                return self.backend._append_recovery_blocked(
                    task,
                    blocker_id="RECOVERY_VALIDATION_FAILED",
                    reason=f"recovery could not establish a safe boundary: {type(error).__name__}: {error}",
                )
