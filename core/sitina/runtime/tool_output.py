from __future__ import annotations

import hashlib
import os
import shutil
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping

from sitina.cas.local import LocalCAS
from sitina.journal.model import canonical_json_bytes, parse_canonical_json


class ToolOutputError(RuntimeError):
    pass


class ToolOutputCoordinator:
    """Bounded Runtime streaming followed by CAS-before-Journal finalization."""

    TENANT = "sitina-tool-output"
    MAX_APPEND_BYTES = 1024 * 1024

    def __init__(
        self,
        home: str | Path,
        cas: LocalCAS,
        *,
        max_capture_bytes: int = 8 * 1024 * 1024,
        fault_injector: Callable[[str], None] | None = None,
    ):
        self.home = Path(home).resolve(strict=True)
        self.cas = cas
        if max_capture_bytes < 1:
            raise ToolOutputError("tool output capture limit must be positive")
        self.max_capture_bytes = max_capture_bytes
        self.fault_injector = fault_injector
        self.runtime_root = self.home / "runtime" / "tool-streams"
        self.receipt_root = self.home / "state" / "tool-output-receipts"
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        self.receipt_root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _key(tool_call_id: str) -> str:
        if not isinstance(tool_call_id, str) or not tool_call_id or len(tool_call_id.encode("utf-8")) > 255:
            raise ToolOutputError("invalid tool_call_id")
        return hashlib.sha256(tool_call_id.encode("utf-8")).hexdigest()

    def _receipt_path(self, tool_call_id: str) -> Path:
        return self.receipt_root / (self._key(tool_call_id) + ".json")

    def _stream_root(self, tool_call_id: str) -> Path:
        return self.runtime_root / self._key(tool_call_id)

    @staticmethod
    def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, canonical_json_bytes(dict(value)))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def load(self, tool_call_id: str) -> dict[str, Any] | None:
        path = self._receipt_path(tool_call_id)
        if path.is_symlink():
            raise ToolOutputError("tool output receipt rejects symlinks")
        if not path.is_file():
            return None
        value = parse_canonical_json(path.read_bytes())
        if value.get("schema") != "SITINA_TOOL_OUTPUT_RECEIPT_V1" or value.get("tool_call_id") != tool_call_id:
            raise ToolOutputError("tool output receipt identity mismatch")
        return dict(value)

    def begin(self, *, tool_call_id: str, run_id: str, started_at: str) -> dict[str, Any]:
        current = self.load(tool_call_id)
        if current is not None:
            if current.get("run_id") != run_id:
                raise ToolOutputError("tool output identity conflicts with an existing capture")
            return current
        stream = self._stream_root(tool_call_id)
        stream.mkdir(parents=True, exist_ok=False)
        receipt = {
            "schema": "SITINA_TOOL_OUTPUT_RECEIPT_V1",
            "tool_call_id": tool_call_id,
            "run_id": run_id,
            "state": "CAPTURING",
            "started_at": started_at,
            "next_sequence": 0,
            "captured_bytes": 0,
            "dropped_bytes": 0,
            "result_manifest_ref": None,
            "chunk_refs": [],
            "journal_position": None,
        }
        self._atomic_json(self._receipt_path(tool_call_id), receipt)
        return receipt

    def append(self, tool_call_id: str, *, channel: str, data: bytes) -> dict[str, Any]:
        if channel not in {"stdout", "stderr"} or not isinstance(data, bytes):
            raise ToolOutputError("tool output chunk requires stdout/stderr bytes")
        if len(data) > self.MAX_APPEND_BYTES:
            raise ToolOutputError("Runtime tool output chunks must not exceed 1 MiB")
        receipt = self.load(tool_call_id)
        if receipt is None or receipt["state"] != "CAPTURING":
            raise ToolOutputError("tool output capture is not active")
        remaining = max(0, self.max_capture_bytes - int(receipt["captured_bytes"]))
        retained = data[:remaining]
        dropped = len(data) - len(retained)
        if retained:
            sequence = int(receipt["next_sequence"])
            target = self._stream_root(tool_call_id) / f"{sequence:012d}-{channel}.chunk"
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                os.write(descriptor, retained)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            receipt["next_sequence"] = sequence + 1
            receipt["captured_bytes"] = int(receipt["captured_bytes"]) + len(retained)
        receipt["dropped_bytes"] = int(receipt["dropped_bytes"]) + dropped
        self._atomic_json(self._receipt_path(tool_call_id), receipt)
        return receipt

    def _publish_runtime_stream(self, receipt: Mapping[str, Any]) -> tuple[str, list[str]]:
        tool_call_id = str(receipt["tool_call_id"])
        chunks: list[dict[str, Any]] = []
        references: list[str] = []
        stream = self._stream_root(tool_call_id)
        for expected_sequence, path in enumerate(sorted(stream.glob("*.chunk"))):
            if path.is_symlink() or not path.is_file():
                raise ToolOutputError("Runtime tool stream rejects symlinks and special files")
            prefix, separator, suffix = path.name.partition("-")
            channel = suffix.removesuffix(".chunk") if separator else ""
            if int(prefix) != expected_sequence or channel not in {"stdout", "stderr"}:
                raise ToolOutputError("Runtime tool stream is not contiguous")
            raw = path.read_bytes()
            publication = self.cas.publish_plaintext(
                raw,
                tenant_id=self.TENANT,
                purpose_class="tool-output-chunk",
                compression="auto",
                media_type="text/plain",
            )
            reference = publication.receipt.object_ref.reference_id
            references.append(reference)
            chunks.append(
                {
                    "sequence": expected_sequence,
                    "channel": channel,
                    "content_ref": reference,
                    "content_sha256": hashlib.sha256(raw).hexdigest(),
                    "size": len(raw),
                }
            )
        if sum(int(item["size"]) for item in chunks) != int(receipt["captured_bytes"]):
            raise ToolOutputError("Runtime stream byte accounting mismatch")
        manifest = {
            "schema": "SITINA_TOOL_OUTPUT_MANIFEST_V1",
            "tool_call_id": tool_call_id,
            "run_id": receipt["run_id"],
            "chunks": chunks,
            "captured_bytes": receipt["captured_bytes"],
            "dropped_bytes": receipt["dropped_bytes"],
            "truncated": bool(receipt["dropped_bytes"]),
        }
        published = self.cas.publish_plaintext(
            canonical_json_bytes(manifest),
            tenant_id=self.TENANT,
            purpose_class="tool-output-manifest",
            compression="auto",
            media_type="application/json",
        )
        manifest_ref = published.receipt.object_ref.reference_id
        return manifest_ref, sorted(set([manifest_ref, *references]))

    def _fault(self, boundary: str) -> None:
        if self.fault_injector is not None:
            self.fault_injector(boundary)

    def complete(
        self,
        tool_call_id: str,
        *,
        status: str,
        exit_code: int | None,
        completed_at: str,
        append_event: Callable[[Mapping[str, Any]], int],
    ) -> dict[str, Any]:
        if status not in {"SUCCEEDED", "FAILED", "CANCELLED", "BLOCKED"}:
            raise ToolOutputError("invalid terminal tool status")
        receipt = self.load(tool_call_id)
        if receipt is None:
            raise ToolOutputError("tool output capture is missing")
        if receipt["state"] == "CAPTURING":
            manifest_ref, references = self._publish_runtime_stream(receipt)
            receipt = {
                **receipt,
                "state": "CAS_PUBLISHED",
                "result_manifest_ref": manifest_ref,
                "chunk_refs": references,
                "terminal_status": status,
                "exit_code": exit_code,
                "completed_at": completed_at,
            }
            self._atomic_json(self._receipt_path(tool_call_id), receipt)
            self._fault("after_tool_output_cas_publish")
        elif receipt.get("terminal_status") != status or receipt.get("exit_code") != exit_code:
            raise ToolOutputError("tool completion retry conflicts with the published result")
        if receipt["state"] == "CAS_PUBLISHED":
            event = {
                "schema": "SITINA_TOOL_COMPLETED_V1",
                "event_type": "tool.completed",
                "tool_call_id": tool_call_id,
                "run_id": receipt["run_id"],
                "terminal_status": status,
                "exit_code": exit_code,
                "result_manifest_ref": receipt["result_manifest_ref"],
                "captured_bytes": receipt["captured_bytes"],
                "dropped_bytes": receipt["dropped_bytes"],
                "truncated": bool(receipt["dropped_bytes"]),
                "idempotency_key": "tool-output-complete:" + tool_call_id,
                "_object_refs": receipt["chunk_refs"],
            }
            position = append_event(event)
            receipt = {**receipt, "state": "JOURNAL_COMMITTED", "journal_position": position}
            self._atomic_json(self._receipt_path(tool_call_id), receipt)
            self._fault("after_tool_completed_journal")
        if receipt["state"] == "JOURNAL_COMMITTED":
            stream = self._stream_root(tool_call_id)
            if stream.exists():
                if stream.is_symlink():
                    raise ToolOutputError("Runtime stream cleanup rejects symlinks")
                resolved = stream.resolve(strict=True)
                if resolved.parent != self.runtime_root.resolve(strict=True):
                    raise ToolOutputError("Runtime stream cleanup target escaped its root")
                shutil.rmtree(resolved)
            receipt = {**receipt, "state": "CLEANED", "runtime_stream_deleted": True}
            self._atomic_json(self._receipt_path(tool_call_id), receipt)
        return receipt

    def open_result(self, manifest_ref: str) -> dict[str, bytes | bool | int]:
        raw = self.cas.open_verified(self.cas.resolve_reference(manifest_ref))
        value = parse_canonical_json(raw)
        if value.get("schema") != "SITINA_TOOL_OUTPUT_MANIFEST_V1":
            raise ToolOutputError("invalid tool output manifest")
        output = {"stdout": bytearray(), "stderr": bytearray()}
        for sequence, item in enumerate(value.get("chunks", [])):
            if item.get("sequence") != sequence or item.get("channel") not in output:
                raise ToolOutputError("tool output manifest sequence is invalid")
            content = self.cas.open_verified(self.cas.resolve_reference(str(item["content_ref"])))
            if len(content) != item.get("size") or hashlib.sha256(content).hexdigest() != item.get("content_sha256"):
                raise ToolOutputError("tool output chunk commitment mismatch")
            output[str(item["channel"])].extend(content)
        return {
            "stdout": bytes(output["stdout"]),
            "stderr": bytes(output["stderr"]),
            "captured_bytes": int(value["captured_bytes"]),
            "dropped_bytes": int(value["dropped_bytes"]),
            "truncated": bool(value["truncated"]),
        }


__all__ = ["ToolOutputCoordinator", "ToolOutputError"]
