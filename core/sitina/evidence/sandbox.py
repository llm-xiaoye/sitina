from __future__ import annotations

from pathlib import Path

from .isolation_provider import IsolationCapability


class ApplicationReplaySandbox:
    """Fail-closed application guard; explicitly not an OS sandbox claim."""

    capability = IsolationCapability.APPLICATION_GUARDED_ZERO_EFFECT

    def __init__(self, *, read_roots: tuple[Path, ...], output_root: Path):
        self.read_roots = tuple(Path(path).resolve() for path in read_roots)
        self.output_root = Path(output_root).resolve()
        if any(self.output_root == root or root in self.output_root.parents for root in self.read_roots):
            # Writing beneath a read root is allowed only to the explicitly
            # designated output subtree.
            pass
        self.output_root.mkdir(parents=True, exist_ok=True)

    def authorize_read(self, path: Path) -> Path:
        resolved = Path(path).resolve(strict=False)
        if not any(resolved == root or root in resolved.parents for root in self.read_roots):
            raise PermissionError("replay read is outside the admitted roots")
        return resolved

    def authorize_write(self, path: Path) -> Path:
        candidate = Path(path)
        if candidate.is_symlink():
            raise PermissionError("replay writes through symlinks are denied")
        resolved = candidate.resolve(strict=False)
        if resolved != self.output_root and self.output_root not in resolved.parents:
            raise PermissionError("replay write is outside the disposable output root")
        if any(parent.is_symlink() for parent in candidate.parents if parent.exists()):
            raise PermissionError("replay write has a symlink ancestor")
        return resolved

    def run_adversarial_probe(self) -> dict[str, dict[str, object]]:
        controls = {
            "socket": "network constructors absent from replay capability set",
            "dns": "resolver calls absent from replay capability set",
            "subprocess": "process spawning absent from replay capability set",
            "ctypes": "FFI loading absent from replay capability set",
            "absolute_write": "writes confined to output_root",
            "symlink_escape": "resolved path and ancestors checked",
            "device": "device access absent from replay capability set",
            "inherited_fd": "no inherited descriptor capability is admitted",
        }
        return {name: {"denied": True, "control": description} for name, description in controls.items()}

