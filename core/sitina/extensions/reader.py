from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping
import hashlib
import json

from sitina.journal.model import parse_canonical_json
from sitina.loop.status_reader import read_authenticated_journal
from .authority import AUTHORITY_BINDING_SCHEMA, STREAM_PREFIX, ExtensionAuthority, ExtensionAuthorityError
from .spec import read_json_object


class _ReadBridge:
    def __init__(self, context, events, read_json):
        self.context, self.events, self.read_json = context, tuple(events), read_json
        self.closed = False

    def extension_events(self, stream_id):
        if self.closed:
            raise ExtensionAuthorityError("extension authority reader is closed")
        return tuple(event for event in self.events if event.stream_id == stream_id)

    def read_extension_json(self, reference, *, expected_hash=None):
        if self.closed:
            raise ExtensionAuthorityError("extension authority reader is closed")
        return self.read_json(reference, expected_hash=expected_hash)


class ReadOnlyExtensionAuthority(ExtensionAuthority):
    """One authenticated existing global authority position, with no writer.

    A fresh instance observes new defaults.  Existing task bindings continue
    to reference their immutable candidates, independently of later defaults.
    """

    def __init__(self, extension_root: Path, *, sitina_home: Path, keychain_backend: Any | None = None):
        self._set_paths(extension_root, sitina_home)
        self._keychain_backend = keychain_backend
        self._refresh_source = None
        binding = read_json_object(self.binding_path)
        state = binding.get("state_root")
        if not isinstance(state, str) or not Path(state).is_absolute():
            raise ExtensionAuthorityError("global extension authority state binding is unavailable")
        self.state_root = Path(state).resolve(strict=True)
        context, cas, events = read_authenticated_journal(self.state_root, keychain_backend=keychain_backend)
        def read_json(reference, *, expected_hash=None):
            raw = cas.open_verified(cas.resolve_reference(reference))
            if expected_hash is not None and hashlib.sha256(raw).hexdigest() != expected_hash:
                raise ExtensionAuthorityError("extension CAS bytes differ from their authenticated binding")
            value = parse_canonical_json(raw)
            if not isinstance(value, dict):
                raise ExtensionAuthorityError("extension CAS document is not an object")
            return value
        self.backend = _ReadBridge(context, events, read_json)
        self._check_binding(binding)

    @classmethod
    def from_authority(cls, authority: ExtensionAuthority):
        """Freeze an already authenticated authority without rebinding it."""
        instance = cls.__new__(cls)
        instance._set_paths(authority.extension_root, authority.sitina_home)
        instance.state_root = authority.state_root
        instance._keychain_backend = getattr(authority, "_keychain_backend", None)
        instance._refresh_source = (getattr(authority, "_refresh_source", None)
                                    if isinstance(authority, cls) else authority)
        instance.backend = _ReadBridge(authority.backend.context, authority._journal_events(),
                                      authority.backend.read_extension_json)
        instance._check_binding(read_json_object(instance.binding_path))
        return instance

    def _set_paths(self, extension_root, sitina_home):
        self.extension_root = Path(extension_root).expanduser().resolve(strict=True)
        self.sitina_home = Path(sitina_home).expanduser().resolve(strict=True)
        self.binding_path = self.extension_root / ".sitina-extension-authority-v1.json"
        self.lock_path = self.extension_root / ".sitina-extension-authority.lock"
        self.stream_id = STREAM_PREFIX + hashlib.sha256(str(self.extension_root).encode("utf-8")).hexdigest()[:32]

    def _check_binding(self, value):
        if (value.get("schema") != AUTHORITY_BINDING_SCHEMA
                or value.get("extension_root") != str(self.extension_root)
                or value.get("state_root") != str(self.state_root)
                or value.get("stream_id") != self.stream_id
                or value.get("journal_id") != self.backend.context.journal_id
                or Path(self.backend.context.home) != self.state_root):
            raise ExtensionAuthorityError("global extension authority binding differs from its authenticated Journal")

    def load_projection(self):
        return self._projection_from_events(self._journal_events())

    def rebuild_projection(self):
        return self.load_projection()

    def _projection_at_read_position(self):
        events = self._journal_events()
        return self._projection_from_events(events), self._stream_position(events), events

    def refreshed(self):
        if self._refresh_source is not None:
            return self.from_authority(self._refresh_source)
        return type(self)(self.extension_root, sitina_home=self.sitina_home,
                          keychain_backend=self._keychain_backend)

    def at_position(self, position: Mapping[str, Any]):
        """Authenticate an earlier task pin against this committed history."""
        if not isinstance(position, Mapping) or type(position.get("stream_version")) is not int:
            raise ExtensionAuthorityError("task Skill authority position is invalid")
        version = position["stream_version"]
        if version < 0:
            raise ExtensionAuthorityError("task Skill authority position is invalid")
        selected = tuple(event for event in self._journal_events() if event.stream_version <= version)
        if self._stream_position(selected) != dict(position):
            raise ExtensionAuthorityError("task Skill authority position is not authenticated")
        view = self.from_authority(self)
        view.backend.events = selected
        return view

    def close(self):
        self.backend.closed = True

    def _record_resolution_failure(self, *_args, **_kwargs):
        # Read-only consumers must preserve the resolver's original exception.
        # Recording a durable failure is the writer's responsibility; attempting
        # it here masks a concrete candidate failure with an authority error.
        return None

    @staticmethod
    def _deny_mutation(*_args, **_kwargs):
        raise ExtensionAuthorityError("read-only global extension authority cannot perform management or publication")

    _writer_lock = _deny_mutation
    _append_fact = _deny_mutation
    _persist_projection_at = _deny_mutation
    _skill_management_write = _deny_mutation
    create_preparation_context = _deny_mutation
    prepare_skill = _deny_mutation
    prepare_plugin = _deny_mutation
    manage_skill = _deny_mutation
    manage_mcp = _deny_mutation
    publish_candidate = _deny_mutation
    commit_publication = _deny_mutation
    record_publication_intent = _deny_mutation
    record_trial_fact = _deny_mutation
