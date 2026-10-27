from __future__ import annotations

import base64
import hashlib
import json
import threading
from typing import Any, Mapping


def request_body_bytes(document: Mapping[str, Any]) -> bytes:
    """Decode private transport bytes without canonical-JSON text conversion.

    Legacy records remain readable only through their original V1 format;
    consumers must still verify the recorded byte hash and length.
    """
    if document.get("schema") == "SITINA_PRIVATE_PROVIDER_REQUEST_BODY_V1":
        body = document.get("body_utf8")
        if not isinstance(body, str):
            raise ValueError("legacy request body is not UTF-8 text")
        return body.encode("utf-8")
    if (document.get("schema") != "SITINA_PRIVATE_PROVIDER_REQUEST_BODY_V2"
            or document.get("body_encoding") != "base64"
            or not isinstance(document.get("body_base64"), str)):
        raise ValueError("unsupported private request body encoding")
    try:
        raw = base64.b64decode(document["body_base64"], validate=True)
        raw.decode("utf-8", errors="strict")
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid private request body bytes") from exc
    if base64.b64encode(raw).decode("ascii") != document["body_base64"]:
        raise ValueError("noncanonical private request body encoding")
    return raw


class NativeRequestDelivery:
    """One native model operation's private, exact transport evidence.

    Main and child execution routes use the same recorder. It grants no
    file, tool, network or memory capability to any model.
    """

    def __init__(self, memory: Any, binding: Mapping[str, Any]) -> None:
        main = binding.get("agent_role") == "MAIN"
        if (not binding.get("task_id") or not binding.get("operation_id")
                or (main and binding.get("execution_owner") is not None)
                or (not main and not binding.get("execution_owner"))):
            raise ValueError("request evidence requires a native task/role/operation binding")
        self.schema = "SITINA_MAIN_REQUEST_DELIVERY_V1" if main else "SITINA_CHILD_REQUEST_DELIVERY_V1"
        self.memory = memory
        self.binding = dict(binding)
        self._attempts: dict[str, Any] = {}
        self._lock = threading.Lock()

    def persist(self, body: bytes, transport: Mapping[str, Any]) -> Mapping[str, Any]:
        body.decode("utf-8", errors="strict")
        digest = hashlib.sha256(body).hexdigest()
        if transport.get("request_body_hash") != digest or transport.get("request_body_bytes") != len(body):
            raise ValueError("serialized request evidence identity mismatch")
        document = {
            "schema": "SITINA_PRIVATE_PROVIDER_REQUEST_BODY_V2",
            "binding": dict(self.binding), "transport": dict(transport),
            "body_encoding": "base64", "body_base64": base64.b64encode(body).decode("ascii"),
            "observation_source": "serialized_http_request_argument_before_send",
        }
        stored = self.memory.persist(document, purpose="provider-request-body")
        if self.memory.read(stored.reference_id, expected_hash=stored.content_hash) != document:
            raise ValueError("request evidence durable read-back mismatch")
        return {"body_ref": stored.reference_id, "content_hash": stored.content_hash,
                "request_body_hash": digest, "request_body_bytes": len(body),
                "transport_request_id": transport["transport_request_id"]}

    def observe(self, snapshot: Mapping[str, Any]) -> None:
        request_id = snapshot.get("transport_request_id")
        if not isinstance(request_id, str):
            return
        with self._lock:
            self._attempts[request_id] = json.loads(json.dumps(dict(snapshot)))

    def as_record(self) -> Mapping[str, Any]:
        with self._lock:
            attempts = json.loads(json.dumps(list(self._attempts.values())))
        return {"schema": self.schema, "binding": dict(self.binding),
                "attempts": attempts,
                "proof_boundary": "local serialized HTTP argument and observed transport phases; not remote model attention"}


def delivery_publication_proofs(memory: Any, record: Mapping[str, Any], *,
                                task_id: str, operation_id: str, owner: str | None) -> tuple[Any, ...]:
    """Register body objects as ordinary Journal roots for backup/retention.

    A nested reference string alone is not a published dependency. Re-open
    and bind each body before issuing the same CAS proof used by all other
    native event objects.
    """
    binding = record.get("binding")
    expected_schema = "SITINA_MAIN_REQUEST_DELIVERY_V1" if owner is None else "SITINA_CHILD_REQUEST_DELIVERY_V1"
    if (record.get("schema") != expected_schema
            or not isinstance(binding, Mapping)
            or (owner is None and binding.get("agent_role") != "MAIN")
            or (owner is not None and binding.get("agent_role") == "MAIN")
            or binding.get("task_id") != task_id or binding.get("operation_id") != operation_id
            or binding.get("execution_owner") != owner):
        raise ValueError("request body publication has a different native operation binding")
    attempts = record.get("attempts")
    if not isinstance(attempts, list):
        raise ValueError("request body attempts must be an array")
    proofs = []
    seen = set()
    for attempt in attempts:
        if not isinstance(attempt, Mapping):
            raise ValueError("request body attempt is not an object")
        descriptor = attempt.get("request_body_evidence")
        if descriptor is None and attempt.get("body_evidence_status") == "PERSISTENCE_FAILED_NOT_SENT":
            if "request_started" in attempt.get("phases", {}):
                raise ValueError("failed body persistence cannot authorize a send")
            continue
        if not isinstance(descriptor, Mapping):
            raise ValueError("request body publication has no descriptor")
        reference = descriptor["body_ref"]
        document = memory.read(reference, expected_hash=descriptor["content_hash"])
        transport = document.get("transport")
        if (document.get("binding") != binding
                or not isinstance(transport, Mapping)
                or transport.get("transport_request_id") != attempt.get("transport_request_id")):
            raise ValueError("request body document differs from its operation/attempt")
        raw = request_body_bytes(document)
        digest = hashlib.sha256(raw).hexdigest()
        if (digest != descriptor.get("request_body_hash") or digest != attempt.get("request_body_hash")
                or len(raw) != descriptor.get("request_body_bytes") or len(raw) != attempt.get("request_body_bytes")):
            raise ValueError("request body publication byte identity mismatch")
        if reference not in seen:
            proofs.append(memory.store.cas.verify_existing(memory.store.cas.resolve_reference(reference)))
            seen.add(reference)
    return tuple(proofs)
