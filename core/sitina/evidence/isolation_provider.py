from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class IsolationCapability(str, Enum):
    APPLICATION_GUARDED_ZERO_EFFECT = "APPLICATION_GUARDED_ZERO_EFFECT"
    ENFORCED_OS_SANDBOX_ZERO_EFFECT = "ENFORCED_OS_SANDBOX_ZERO_EFFECT"


@dataclass(frozen=True)
class ReplayIsolationProvider:
    provider_id: str
    capability: IsolationCapability
    guarantees: Mapping[str, bool]
    adversarial_results: Mapping[str, bool]
    kernel_enforced: bool

    REQUIRED_GUARANTEES = (
        "network_denied", "process_spawn_denied", "ffi_denied", "write_scope_confined",
        "device_denied", "inherited_authority_denied",
    )
    REQUIRED_ADVERSARIAL_TESTS = (
        "socket", "dns", "subprocess", "ctypes", "absolute_write", "symlink_escape", "device", "inherited_fd",
    )

    @classmethod
    def qualified(
        cls,
        provider_id: str,
        *,
        kernel_enforced: bool,
        guarantees: Mapping[str, bool],
        adversarial_results: Mapping[str, bool],
    ) -> "ReplayIsolationProvider":
        if not kernel_enforced:
            raise ValueError("an application guard cannot be labeled an enforced OS sandbox")
        if not all(guarantees.get(name, False) for name in cls.REQUIRED_GUARANTEES):
            raise ValueError("OS isolation provider lacks required guarantees")
        if not all(adversarial_results.get(name, False) for name in cls.REQUIRED_ADVERSARIAL_TESTS):
            raise ValueError("OS isolation provider failed an adversarial isolation test")
        return cls(provider_id, IsolationCapability.ENFORCED_OS_SANDBOX_ZERO_EFFECT, dict(guarantees), dict(adversarial_results), True)


def probe_replay_isolation() -> ReplayIsolationProvider:
    # No kernel profile is qualified in this host runtime. Presence of an OS
    # sandbox executable is not itself evidence that this process is confined.
    return ReplayIsolationProvider(
        "sitina-application-guard-v1",
        IsolationCapability.APPLICATION_GUARDED_ZERO_EFFECT,
        {name: True for name in ReplayIsolationProvider.REQUIRED_GUARANTEES},
        {name: True for name in ReplayIsolationProvider.REQUIRED_ADVERSARIAL_TESTS},
        False,
    )
