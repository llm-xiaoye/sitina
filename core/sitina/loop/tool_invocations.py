"""Authenticated bindings between Provider invocations and actual operation results."""
from __future__ import annotations
from typing import Any, Mapping
from .model import EffectStatus, OperationMode, OperationRejected
from .operations import OperationOutcome

INVOCATION_RECEIPT_SCHEMA = "SITINA_TOOL_INVOCATION_RECEIPT_V1"

def bind_tool_invocation(adapter: Any, run_id: str, call: Any, result: Any, before: int) -> None:
    """Record a real returned reply only when its effect receipt cannot restore it."""
    if adapter.request_assembler is None:
        return
    from .task_runtime import _canonical_safe
    ids = adapter.operation_ids[before:]
    if not ids:
        raise OperationRejected("tool invocation returned without a committed operation binding")
    actual_id = ids[-1]
    task = adapter.backend.get_task(adapter.task_id)
    actual = task.operations.get(actual_id)
    if actual is None or not actual.result_ref:
        raise OperationRejected("tool invocation has no authenticated actual result")
    document = adapter.backend.context_memory.read(actual.result_ref)
    raw = document.get("result")
    reply = _canonical_safe({"tool": call.name, "status": result.status, "value": result.value})
    logical = actual.logical_operation_id
    if (logical.startswith(run_id + ":") and logical.endswith(":" + call.call_id)
            and isinstance(raw, Mapping) and raw.get("tool") == reply["tool"]
            and raw.get("status") == reply["status"] and raw.get("value") == reply["value"]):
        return
    source = adapter.request_assembler.source_ref_for_operation(actual_id)
    entry = next(item for item in adapter.request_assembler.index.entries if item.source_ref == source)
    binding = {"schema": INVOCATION_RECEIPT_SCHEMA, "run_id": run_id,
        "call_id": call.call_id, "tool": call.name, "arguments": _canonical_safe(dict(call.arguments)),
        "actual_operation_id": actual_id, "actual_result_ref": actual.result_ref,
        "actual_result_hash": entry.content_hash, "effect_dispatched_by_receipt": False}
    logical_id = run_id + ":tool-invocation:" + call.call_id
    existing = [item for item in task.operations.values() if item.logical_operation_id == logical_id]
    if existing:
        if len(existing) != 1 or not existing[0].result_ref:
            raise OperationRejected("invocation receipt is unresolved or ambiguous")
        saved = adapter.backend.context_memory.read(existing[0].result_ref)["result"]
        if saved.get("invocation_binding") != binding or any(saved.get(key) != value for key, value in reply.items()):
            raise OperationRejected("invocation receipt cannot be rebound to a different result")
        return
    intent = adapter._intent(category="tool-invocation", logical_id=logical_id,
        mode=OperationMode.READ, description="bind an actual tool reply to its authenticated operation result")
    payload = {**reply, "invocation_binding": binding}
    outcome = adapter.backend.execute_operation(adapter.task_id, intent,
        lambda: OperationOutcome(EffectStatus.SUCCEEDED, payload))
    if outcome.status is not EffectStatus.SUCCEEDED:
        raise OperationRejected("actual effect is retained but invocation receipt could not be committed")

def bound_invocation_result(*, call: Mapping[str, Any], run_id: str, receipt: Mapping[str, Any],
                            result_docs: Mapping[str, Mapping[str, Any]],
                            result_bindings: Mapping[str, tuple[str, str]]) -> str:
    """Validate the alias against exact proposal bytes and the saved original result."""
    binding = receipt.get("invocation_binding")
    if not isinstance(binding, Mapping) or binding.get("schema") != INVOCATION_RECEIPT_SCHEMA:
        raise ValueError("invalid invocation receipt schema")
    if any(binding.get(key) != expected for key, expected in
           (("run_id", run_id), ("call_id", call["id"]), ("tool", call["name"]), ("arguments", call["arguments"]))):
        raise ValueError("invocation receipt differs from the committed Provider call")
    actual_id = binding.get("actual_operation_id")
    actual = result_docs.get(actual_id)
    if not isinstance(actual, Mapping):
        raise ValueError("invocation receipt has no original committed result")
    observed = result_bindings.get(actual_id)
    if observed != (binding.get("actual_result_ref"), binding.get("actual_result_hash")):
        raise ValueError("invocation receipt lost its original result identity")
    if binding.get("effect_dispatched_by_receipt") is not False:
        raise ValueError("invocation receipt cannot claim execution")
    return str(actual_id)
