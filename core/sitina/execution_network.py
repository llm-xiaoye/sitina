"""Task-owned, inspecting HTTP(S) egress for sandboxed command processes.

The Host is the only caller of the capability mutation methods.  There is no
HTTP control API.  The caller must deny direct child networking and permit only
this gateway's exact loopback port; proxy environment variables alone are not
a security boundary.  Startup reserves both 127.0.0.1 and ::1 because macOS
SBPL's localhost endpoint permits both addresses.  URL grants are complete
URLs, never host/prefix grants.

The synchronous ``connection_opened`` audit event runs after the pinned TCP
connection and, for HTTPS, the verified upstream TLS handshake.  It reports the
actual socket address tuples.  No HTTP request headers or body are sent before
that callback returns successfully; rejecting it closes the connection without
retry.  TLS handshake traffic can precede the ownership callback.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_TIMEOUT = 30.0
_MAX_BODY = 2 * 1024 * 1024
_MAX_LOCAL_BODY = 16 * 1024 * 1024
_MAX_METADATA = 8 * 1024 * 1024
_MAX_ADVERTISEMENT = 2 * 1024 * 1024
_TRACE_SEGMENT_BYTES = 4 * 1024 * 1024
_TRACE_SEGMENTS = 4
_OBJECT_ID = re.compile(r"[0-9a-f]{40}\Z")
_GIT_CAPABILITIES = frozenset({
    "multi_ack", "multi_ack_detailed", "side-band", "side-band-64k",
    "thin-pack", "ofs-delta", "no-progress", "include-tag", "no-done",
    "object-format=sha1", "shallow", "deepen-since", "deepen-not", "deepen-relative",
})
_IGNORED_REQUEST_HEADERS = frozenset({
    "host", "user-agent", "accept", "accept-encoding", "accept-language",
    "connection", "proxy-connection", "content-length", "cache-control",
    "pragma", "content-type", "git-protocol", "range", "npm-command",
    "npm-session", "npm-invocation-id", "pacote-version", "pacote-req-type",
    "pacote-pkg-id",
})
_HOP_HEADERS = frozenset({
    "connection", "proxy-connection", "keep-alive", "transfer-encoding",
    "te", "trailer", "upgrade", "proxy-authenticate", "proxy-authorization",
    "set-cookie", "set-cookie2", "alt-svc",
})


class NetworkPolicyError(ValueError):
    """A request was rejected before any corresponding upstream request."""

    def __init__(self, code: str, detail: str = "", *, observation: Mapping[str, object] | None = None) -> None:
        super().__init__(detail or code)
        self.code = code
        self.observation = observation


class ServiceRegistrationRejected(NetworkPolicyError):
    """Local service validation failed before changing registrations or connections."""


class _RequestTrace:
    """Bounded metadata only; never persist headers, bodies or URL secrets."""

    def __init__(self, owner: TaskNetworkGateway, method: str, raw_target: str,
                 parent_id: str | None = None) -> None:
        self.owner = owner
        self.request_id = uuid.uuid4().hex
        self.parent_id = parent_id
        self.method = method[:32]
        self.target_sha256 = hashlib.sha256(raw_target.encode("utf-8", "surrogatepass")).hexdigest()
        self.phase = "request_received"
        self.emit(self.phase)

    def emit(self, phase: str, **fields: object) -> None:
        self.phase = phase
        self.owner._trace_record(request_id=self.request_id, parent_request_id=self.parent_id,
                                 method=self.method, target_sha256=self.target_sha256,
                                 phase=phase, **fields)

    def failed(self, exc: BaseException) -> None:
        failed_phase = self.phase
        try:
            self.emit("request_failed", failed_phase=failed_phase,
                      error_type=type(exc).__name__, errno=getattr(exc, "errno", None),
                      error_code=exc.code if isinstance(exc, NetworkPolicyError) else None)
        except OSError:
            # The gateway retains the logging failure in lifecycle_status.
            # Never replace the original network/authority error with a logger error.
            pass


class _NetworkTraceError(OSError):
    """Local evidence storage failed; this is not an authority rejection."""


def process_birth_identity(pid: int) -> str:
    """Return the kernel's microsecond creation identity on supported macOS.

    This helper uses only ctypes and the standard library internally, so an
    installed command wrapper can import the same implementation immediately
    after Popen.  No ps timestamp or PID-only fallback is permitted.
    ABI: Apple's xnu bsd/sys/proc_info.h, proc_bsdinfo / PROC_PIDTBSDINFO.
    """
    import ctypes

    if sys.platform != "darwin" or not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise NetworkPolicyError("PROCESS_BIRTH_INSPECTION_UNAVAILABLE")

    class ProcBSDInfo(ctypes.Structure):
        _fields_ = [
            ("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32),
            ("pbi_xstatus", ctypes.c_uint32), ("pbi_pid", ctypes.c_uint32),
            ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
            ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32),
            ("pbi_rgid", ctypes.c_uint32), ("pbi_svuid", ctypes.c_uint32),
            ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
            ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32),
            ("pbi_nfiles", ctypes.c_uint32), ("pbi_pgid", ctypes.c_uint32),
            ("pbi_pjobc", ctypes.c_uint32), ("e_tdev", ctypes.c_uint32),
            ("e_tpgid", ctypes.c_uint32), ("pbi_nice", ctypes.c_int32),
            ("pbi_start_tvsec", ctypes.c_uint64), ("pbi_start_tvusec", ctypes.c_uint64),
        ]

    if ctypes.sizeof(ProcBSDInfo) != 136:
        raise NetworkPolicyError("PROCESS_BIRTH_ABI_UNSUPPORTED")
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        function = library.proc_pidinfo
        function.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        function.restype = ctypes.c_int
        record = ProcBSDInfo()
        count = function(pid, 3, 0, ctypes.byref(record), ctypes.sizeof(record))
    except (OSError, AttributeError) as exc:
        raise NetworkPolicyError("PROCESS_BIRTH_INSPECTION_UNAVAILABLE") from exc
    if count != ctypes.sizeof(record) or record.pbi_pid != pid or record.pbi_start_tvsec <= 0 or record.pbi_start_tvusec >= 1_000_000:
        raise NetworkPolicyError("PROCESS_BIRTH_IDENTITY_NOT_OBSERVED")
    return f"macos-proc-bsdinfo-v1:{pid}:{record.pbi_start_tvsec}:{record.pbi_start_tvusec:06d}"


@dataclass(frozen=True)
class TCPSocketEndpoint:
    """A live numeric TCP socket observation, as reported by the Host OS."""

    pid: int
    fd: int
    local_address: tuple[str, int]
    peer_address: tuple[str, int] | None
    state: str


def _numeric_endpoint(value: str) -> tuple[str, int]:
    if value.startswith("["):
        host, separator, port = value[1:].partition("]:")
    else:
        host, separator, port = value.rpartition(":")
    if not separator or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise NetworkPolicyError("SOCKET_INSPECTION_FORMAT_UNSUPPORTED")
    if host != "*":
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError as exc:
            raise NetworkPolicyError("SOCKET_INSPECTION_FORMAT_UNSUPPORTED") from exc
    return host, int(port)


def _parse_socket_endpoints(raw: bytes) -> tuple[TCPSocketEndpoint, ...]:
    """Parse lsof's explicitly requested NUL fields, never its display table."""
    records: list[TCPSocketEndpoint] = []
    pid: int | None = None
    fields: dict[str, str] = {}

    def finish() -> None:
        if not fields:
            return
        if pid is None or set(fields) != {"f", "t", "n", "TST"} or fields["t"] not in {"IPv4", "IPv6"} or not fields["f"].isdecimal():
            raise NetworkPolicyError("SOCKET_INSPECTION_FORMAT_UNSUPPORTED")
        names = fields["n"].split("->")
        if len(names) not in {1, 2}:
            raise NetworkPolicyError("SOCKET_INSPECTION_FORMAT_UNSUPPORTED")
        local = _numeric_endpoint(names[0])
        peer = _numeric_endpoint(names[1]) if len(names) == 2 else None
        records.append(TCPSocketEndpoint(pid, int(fields["f"]), local, peer, fields["TST"]))

    try:
        for token in raw.split(b"\0"):
            token = token.lstrip(b"\n")
            if not token:
                continue
            value = token.decode("ascii")
            key, data = value[0], value[1:]
            if key == "p":
                finish()
                fields = {}
                if not data.isdecimal() or int(data) <= 0:
                    raise NetworkPolicyError("SOCKET_INSPECTION_FORMAT_UNSUPPORTED")
                pid = int(data)
            elif key == "f":
                finish()
                fields = {"f": data}
            elif key == "T":
                state_key, separator, state_value = data.partition("=")
                if not separator:
                    raise NetworkPolicyError("SOCKET_INSPECTION_FORMAT_UNSUPPORTED")
                if state_key == "ST":
                    if "TST" in fields:
                        raise NetworkPolicyError("SOCKET_INSPECTION_FORMAT_UNSUPPORTED")
                    fields["TST"] = state_value
            elif key in {"t", "n"}:
                if key in fields:
                    raise NetworkPolicyError("SOCKET_INSPECTION_FORMAT_UNSUPPORTED")
                fields[key] = data
            else:
                raise NetworkPolicyError("SOCKET_INSPECTION_FORMAT_UNSUPPORTED")
        finish()
    except UnicodeDecodeError as exc:
        raise NetworkPolicyError("SOCKET_INSPECTION_FORMAT_UNSUPPORTED") from exc
    return tuple(records)


def inspect_tcp_endpoints(port: int, *, state: str | None = None) -> tuple[TCPSocketEndpoint, ...]:
    """Observe a single port with fixed macOS lsof; unsupported hosts fail closed."""
    if sys.platform != "darwin" or not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise NetworkPolicyError("SOCKET_INSPECTION_UNAVAILABLE")
    if state not in {None, "LISTEN", "ESTABLISHED"}:
        raise NetworkPolicyError("SOCKET_INSPECTION_STATE_UNSUPPORTED")
    # Apple's bundled 4.91 build does not implement the -D cache option.
    arguments = ["/usr/sbin/lsof", "-nP", "-a", f"-iTCP:{port}", "-F0pftnT"]
    if state is not None:
        arguments.append("-sTCP:" + state)
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NetworkPolicyError("SOCKET_INSPECTION_UNAVAILABLE") from exc
    if result.returncode == 1 and not result.stdout and not result.stderr:
        return ()
    if result.returncode != 0 or result.stderr or len(result.stdout) > 262144:
        raise NetworkPolicyError("SOCKET_INSPECTION_FAILED", observation={
            "executable": arguments[0], "argv": tuple(arguments[1:]),
            "exit_code": result.returncode, "child_stdout": result.stdout,
            "child_stderr": result.stderr, "child_stream_split_observed": True,
        })
    observations = _parse_socket_endpoints(result.stdout)
    if state is not None and any(item.state != state for item in observations):
        raise NetworkPolicyError("SOCKET_INSPECTION_FORMAT_UNSUPPORTED")
    return observations


@dataclass(frozen=True)
class _ServiceBinding:
    process_id: str
    host: str
    port: int
    addresses: frozenset[str]
    root_pid: int
    root_birth: str
    process_group: int
    owners: tuple[tuple[int, str], ...]
    birth_provider: Callable[[int], str]
    socket_inspector: Callable[..., Sequence[TCPSocketEndpoint]]


@dataclass(frozen=True)
class _URL:
    value: str
    scheme: str
    host: str
    port: int
    authority: str
    path_query: str


def _url(value: str, *, fragment_ok: bool = False) -> _URL:
    if not isinstance(value, str) or not value or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise NetworkPolicyError("INVALID_URL")
    if "\\" in value:
        raise NetworkPolicyError("INVALID_URL")
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"}:
            raise NetworkPolicyError("SCHEME_NOT_ALLOWED")
        if parsed.username is not None or parsed.password is not None:
            raise NetworkPolicyError("URL_CREDENTIALS_NOT_ALLOWED")
        if not parsed.hostname or (parsed.fragment and not fragment_ok):
            raise NetworkPolicyError("INVALID_URL")
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535 or "%" in host:
            raise NetworkPolicyError("INVALID_URL")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
                raise NetworkPolicyError("INVALID_HOST")
        host_text = f"[{host}]" if ":" in host else host
        authority = host_text if port == (443 if parsed.scheme == "https" else 80) else f"{host_text}:{port}"
        path = parsed.path or "/"
        path_query = path + ("?" + parsed.query if parsed.query else "")
        normalized = urlunsplit((parsed.scheme, authority, path, parsed.query, ""))
        return _URL(normalized, parsed.scheme, host, port, authority, path_query)
    except (UnicodeError, ValueError) as exc:
        if isinstance(exc, NetworkPolicyError):
            raise
        raise NetworkPolicyError("INVALID_URL") from exc


def _packet(data: bytes) -> bytes:
    return f"{len(data) + 4:04x}".encode("ascii") + data


def _packets(body: bytes) -> list[bytes | None]:
    result: list[bytes | None] = []
    offset = 0
    while offset < len(body):
        prefix = body[offset:offset + 4]
        if len(prefix) != 4 or not re.fullmatch(b"[0-9a-fA-F]{4}", prefix):
            raise NetworkPolicyError("GIT_INVALID_PKT_LINE")
        size = int(prefix, 16)
        offset += 4
        if size == 0:
            result.append(None)
            continue
        if size < 4 or size > 65520 or offset + size - 4 > len(body):
            raise NetworkPolicyError("GIT_INVALID_PKT_LINE")
        result.append(body[offset:offset + size - 4])
        offset += size - 4
    return result


@dataclass(frozen=True)
class _Advertisement:
    object_ids: frozenset[str]
    capabilities: frozenset[str]


def _advertisement(body: bytes) -> _Advertisement:
    packets = _packets(body)
    if len(packets) < 4 or packets[:2] != [b"# service=git-upload-pack\n", None] or packets[-1] is not None:
        raise NetworkPolicyError("GIT_INVALID_ADVERTISEMENT")
    records = packets[2:-1]
    if records and records[0] == b"version 1\n":
        records = records[1:]
    object_ids: set[str] = set()
    capabilities: set[str] = set()
    for index, raw in enumerate(records):
        if raw is None or not raw.endswith(b"\n"):
            raise NetworkPolicyError("GIT_INVALID_ADVERTISEMENT")
        try:
            text = raw[:-1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise NetworkPolicyError("GIT_UNSUPPORTED_REF_ENCODING") from exc
        if index == 0:
            if text.count("\0") != 1:
                raise NetworkPolicyError("GIT_INVALID_ADVERTISEMENT")
            text, cap_text = text.split("\0")
            capabilities.update(cap_text.split(" "))
        elif "\0" in text:
            raise NetworkPolicyError("GIT_INVALID_ADVERTISEMENT")
        parts = text.split(" ", 1)
        if len(parts) != 2 or not _OBJECT_ID.fullmatch(parts[0]) or not parts[1] or any(ord(c) < 33 for c in parts[1]):
            raise NetworkPolicyError("GIT_INVALID_ADVERTISEMENT")
        if parts[0] != "0" * 40:
            object_ids.add(parts[0])
    if not records or any(not re.fullmatch(r"[^\x00-\x20\x7f]{1,256}", item) for item in capabilities):
        raise NetworkPolicyError("GIT_INVALID_ADVERTISEMENT")
    return _Advertisement(frozenset(object_ids), frozenset(capabilities))


def _git_request(body: bytes, advertisement: _Advertisement) -> bytes:
    """Accept only a bounded, one-round v0/v1 fetch; rebuild every sent byte."""
    packets = _packets(body)
    wants: list[str] = []
    haves: list[str] = []
    capabilities: set[str] = set()
    after_flush = False
    done = False
    for index, raw in enumerate(packets):
        if raw is None:
            if after_flush or not wants:
                raise NetworkPolicyError("GIT_UNSUPPORTED_NEGOTIATION")
            after_flush = True
            continue
        if done or not raw.endswith(b"\n"):
            raise NetworkPolicyError("GIT_INVALID_REQUEST")
        try:
            words = raw[:-1].decode("ascii").split(" ")
        except UnicodeDecodeError as exc:
            raise NetworkPolicyError("GIT_INVALID_REQUEST") from exc
        if words == ["done"] and after_flush:
            done = True
        elif len(words) >= 2 and words[0] == "want" and not after_flush:
            if not _OBJECT_ID.fullmatch(words[1]) or words[1] not in advertisement.object_ids:
                raise NetworkPolicyError("GIT_WANT_NOT_ADVERTISED")
            if words[1] in wants or (index > 0 and len(words) != 2):
                raise NetworkPolicyError("GIT_INVALID_REQUEST")
            wants.append(words[1])
            for cap in words[2:]:
                if cap.startswith("agent="):
                    if not re.fullmatch(r"agent=[!-~]{1,128}", cap):
                        raise NetworkPolicyError("GIT_CAPABILITY_NOT_ALLOWED")
                    continue  # Client-controlled agent strings never leave the Host.
                if cap not in _GIT_CAPABILITIES or cap not in advertisement.capabilities:
                    raise NetworkPolicyError("GIT_CAPABILITY_NOT_ALLOWED")
                capabilities.add(cap)
        elif len(words) == 2 and words[0] == "have" and after_flush:
            if not _OBJECT_ID.fullmatch(words[1]) or words[1] not in advertisement.object_ids:
                raise NetworkPolicyError("GIT_LOCAL_OBJECT_DISCLOSURE_REJECTED")
            if words[1] in haves:
                raise NetworkPolicyError("GIT_INVALID_REQUEST")
            haves.append(words[1])
        else:
            raise NetworkPolicyError("GIT_UNSUPPORTED_NEGOTIATION")
    if not wants or len(wants) > 4096 or len(haves) > 4096 or not after_flush or not done:
        raise NetworkPolicyError("GIT_UNSUPPORTED_NEGOTIATION")
    ordered = sorted(wants)
    cap_text = (" " + " ".join(sorted(capabilities))) if capabilities else ""
    result = _packet(f"want {ordered[0]}{cap_text}\n".encode("ascii"))
    result += b"".join(_packet(f"want {oid}\n".encode("ascii")) for oid in ordered[1:]) + b"0000"
    result += b"".join(_packet(f"have {oid}\n".encode("ascii")) for oid in sorted(haves))
    return result + _packet(b"done\n")


class _CertificateAuthority:
    """Signing key stays in memory; temporary leaf keys are unlinked on load."""

    def __init__(self, root: Path, task_id: str) -> None:
        self.root = root
        self._key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        label = hashlib.sha256(task_id.encode("utf-8")).hexdigest()[:32]
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Sitina task {label}")])
        self._certificate = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(self._key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
            .sign(self._key, hashes.SHA256())
        )
        self.path = root / "trust.pem"
        self.path.write_bytes(self._certificate.public_bytes(serialization.Encoding.PEM))
        self.path.chmod(0o644)
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._lock = threading.Lock()

    def context(self, host: str) -> ssl.SSLContext:
        with self._lock:
            if host in self._contexts:
                return self._contexts[host]
            now = datetime.now(timezone.utc)
            key = ec.generate_private_key(ec.SECP256R1())
            try:
                san = x509.IPAddress(ipaddress.ip_address(host))
            except ValueError:
                san = x509.DNSName(host)
            cert = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
                .issuer_name(self._certificate.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([san]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(self._key, hashes.SHA256())
            )
            temporary = self.root / (uuid.uuid4().hex + ".pem")
            content = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            content += cert.public_bytes(serialization.Encoding.PEM)
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.set_alpn_protocols(["http/1.1"])
                context.load_cert_chain(str(temporary))
            finally:
                temporary.unlink(missing_ok=True)
            self._contexts[host] = context
            return context


def _metadata_advertised(value: object, *, html: bool) -> bool:
    """Recognize an explicit Simple API core-metadata advertisement."""
    if html:
        if value == "true":
            return True
        if not isinstance(value, str):
            return False
        algorithm, separator, digest = value.partition("=")
        if separator != "=":
            return False
        value = {algorithm: digest}
    if value is True:
        return True
    if not isinstance(value, dict) or not value:
        return False
    for algorithm, digest in value.items():
        if not isinstance(algorithm, str) or not isinstance(digest, str) or re.fullmatch(r"[a-z0-9][a-z0-9_-]*", algorithm) is None:
            return False
        try:
            length = hashlib.new(algorithm).digest_size * 2
        except (TypeError, ValueError):
            return False
        if not 0 < length <= 256 or re.fullmatch(r"[0-9a-fA-F]{" + str(length) + r"}", digest) is None:
            return False
    return True


class _SimpleLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.metadata_links: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        hrefs = [value for key, value in attrs if key == "href" and value is not None]
        self.links.extend(hrefs)
        names = [key for key, _ in attrs]
        selected_key = "data-core-metadata" if "data-core-metadata" in names else "data-dist-info-metadata"
        advertisements = [value for key, value in attrs if key == selected_key]
        if len(hrefs) == 1 and len(advertisements) == 1 and _metadata_advertised(advertisements[0], html=True):
            self.metadata_links.add(hrefs[0])


class _PinnedConnection(http.client.HTTPConnection):
    def connect(self) -> None:
        # http.client must never reconnect with a fresh hostname lookup after a
        # gateway shutdown or socket failure.  Only TaskNetworkGateway._open
        # may supply a previously checked numeric peer.
        raise NetworkPolicyError("UPSTREAM_RECONNECT_NOT_ALLOWED")


class _GatewayHTTPServer(ThreadingHTTPServer):
    """Count workers before starting them, including pending TLS/DNS work."""

    allow_reuse_address = False
    allow_reuse_port = False

    def __init__(self, address, handler, owner, *, address_family=socket.AF_INET) -> None:
        self.owner = owner
        self.address_family = address_family
        super().__init__(address, handler)

    def server_bind(self) -> None:
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()

    def process_request(self, request, client_address) -> None:
        with self.owner._lock:
            self.owner._active_workers += 1
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.owner._lock:
                self.owner._active_workers -= 1
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.owner._lock:
                self.owner._active_workers -= 1


class TaskNetworkGateway:
    """One task's inspected anonymous remote and registered-loopback outlet."""

    def __init__(self, root: Path, task_id: str, *, public_read: bool, public_git: bool,
                 allowed_urls: Sequence[str] = (), git_urls: Sequence[str] = (),
                 dependency_registry_reads: bool = False,
                 local_services: Mapping[str, tuple[str, int]] | None = None,
                 audit: Callable | None = None) -> None:
        if not task_id or not isinstance(task_id, str):
            raise ValueError("task_id is required")
        self.root = Path(root)
        self.task_id = task_id
        self.public_read = bool(public_read)
        self.public_git = bool(public_git)
        self.dependency_registry_reads = bool(public_read and dependency_registry_reads)
        self._audit = audit
        self._lock = threading.RLock()
        self._trace_lock = threading.Lock()
        self.trace_path: Path | None = None
        self._trace_sequence = 0
        self._trace_ranges: list[list[int]] = []
        self._trace_failure: dict[str, object] | None = None
        self._allowed_urls: set[str] = set()
        self._metadata_sidecars: set[str] = set()
        self._git_urls: set[str] = set()
        self._read_authorities: set[tuple[str, int]] = set()
        self._git_authorities: set[tuple[str, int]] = set()
        self._services: dict[str, tuple[str, int, frozenset[str]]] = {}
        self._service_bindings: dict[str, _ServiceBinding] = {}
        self._connection_services: dict[http.client.HTTPConnection, frozenset[str]] = {}
        self._active_workers = 0
        self._advertisements: dict[str, _Advertisement] = {}
        self._client_sockets: set[socket.socket] = set()
        self._upstream_connections: set[http.client.HTTPConnection] = set()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._servers: tuple[ThreadingHTTPServer, ...] = ()
        self._threads: tuple[threading.Thread, ...] = ()
        self._closed = False
        self._revoked = False
        self.port = 0
        self.read_paths: tuple[Path, ...] = ()
        self._upstream_context = ssl.create_default_context()
        self.authorize_urls(allowed_urls)
        self.authorize_git_urls(git_urls)
        if local_services:
            raise NetworkPolicyError("LOCAL_SERVICE_OWNERSHIP_PROOF_REQUIRED")

    def _require_forwarding(self) -> None:
        with self._lock:
            if self._closed:
                raise NetworkPolicyError("GATEWAY_CLOSED")
            if self._revoked:
                raise NetworkPolicyError("GATEWAY_REVOKED")

    def authorize_urls(self, urls: Sequence[str]) -> None:
        """Host-only extension; children cannot call this through the proxy."""
        parsed = [_url(value) for value in urls]
        with self._lock:
            self._require_forwarding()
            self._allowed_urls.update(value.value for value in parsed)
            self._read_authorities.update((value.host, value.port) for value in parsed)

    def authorize_git_urls(self, urls: Sequence[str]) -> None:
        normalized: set[str] = set()
        for value in urls:
            parsed = _url(value)
            if parsed.scheme != "https" or urlsplit(parsed.value).query:
                raise NetworkPolicyError("GIT_REQUIRES_HTTPS_REPOSITORY_URL")
            if any(part in {".", ".."} for part in unquote(urlsplit(parsed.value).path).split("/")):
                raise NetworkPolicyError("INVALID_GIT_REPOSITORY_URL")
            normalized.add(parsed.value.rstrip("/"))
        with self._lock:
            self._require_forwarding()
            self._git_urls.update(normalized)
            self._git_authorities.update((_url(value).host, _url(value).port) for value in normalized)

    @staticmethod
    def _addresses(host: str, port: int) -> frozenset[str]:
        try:
            addresses = frozenset(str(ipaddress.ip_address(item[4][0])) for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except (OSError, ValueError) as exc:
            raise NetworkPolicyError("DNS_RESOLUTION_FAILED") from exc
        if not addresses:
            raise NetworkPolicyError("DNS_RESOLUTION_FAILED")
        return addresses

    def register_service(self, process_id: str, host: str, port: int, **authority) -> dict[str, object]:
        """Compatibility name; endpoint declarations alone never grant access."""
        if not authority:
            raise NetworkPolicyError("LOCAL_SERVICE_OWNERSHIP_PROOF_REQUIRED")
        return self.bind_service(process_id, host, port, **authority)

    @staticmethod
    def _check_scope(root_pid: int, root_birth: str, process_group: int, provider: Callable[[int], str]) -> None:
        try:
            if provider(root_pid) != root_birth or os.getpgid(root_pid) != process_group:
                raise NetworkPolicyError("LOCAL_SERVICE_ROOT_IDENTITY_CHANGED")
        except (OSError, ValueError) as exc:
            if isinstance(exc, NetworkPolicyError):
                raise
            raise NetworkPolicyError("LOCAL_SERVICE_ROOT_IDENTITY_NOT_OBSERVED") from exc

    @staticmethod
    def _owner_birth(pid: int, process_group: int, provider: Callable[[int], str]) -> str:
        try:
            birth = provider(pid)
            if not isinstance(birth, str) or not birth or os.getpgid(pid) != process_group:
                raise NetworkPolicyError("LOCAL_SERVICE_PROCESS_NOT_OWNED")
            return birth
        except OSError as exc:
            raise NetworkPolicyError("LOCAL_SERVICE_PROCESS_NOT_OBSERVED") from exc

    def _prepare_service_binding(self, process_id: str, host: str, port: int, *, root_pid: int,
                     root_birth: str, process_group: int,
                     process_birth: Callable[[int], str] = process_birth_identity,
                     socket_inspector: Callable[..., Sequence[TCPSocketEndpoint]] = inspect_tcp_endpoints) -> _ServiceBinding:
        """Validate a replacement without changing registrations or connections."""
        self._require_forwarding()
        if not isinstance(process_id, str) or not process_id or not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise NetworkPolicyError("INVALID_LOCAL_SERVICE")
        if not isinstance(root_pid, int) or isinstance(root_pid, bool) or root_pid <= 0 or not isinstance(root_birth, str) or not root_birth or not isinstance(process_group, int) or isinstance(process_group, bool) or process_group <= 0:
            raise NetworkPolicyError("INVALID_LOCAL_SERVICE_AUTHORITY")
        normalized = _url(f"http://{'[' + host + ']' if ':' in host else host}:{port}/")
        addresses = self._addresses(normalized.host, port)
        if not all(ipaddress.ip_address(address).is_loopback for address in addresses):
            raise NetworkPolicyError("LOCAL_SERVICE_MUST_BE_LOOPBACK")
        self._check_scope(root_pid, root_birth, process_group, process_birth)
        observations = socket_inspector(port, state="LISTEN")
        if not isinstance(observations, Sequence) or any(not isinstance(item, TCPSocketEndpoint) for item in observations):
            raise NetworkPolicyError("SOCKET_INSPECTION_FORMAT_UNSUPPORTED")
        listeners = [item for item in observations if item.local_address in {(address, port) for address in addresses} and item.state == "LISTEN" and item.peer_address is None]
        if not listeners:
            raise NetworkPolicyError("LOCAL_SERVICE_LISTENER_NOT_OBSERVED")
        if {item.local_address[0] for item in listeners} != set(addresses):
            raise NetworkPolicyError("LOCAL_SERVICE_LISTENER_NOT_OBSERVED_FOR_ALL_ADDRESSES")
        owners = tuple(sorted({(item.pid, self._owner_birth(item.pid, process_group, process_birth)) for item in listeners}))
        for pid, birth in owners:
            if self._owner_birth(pid, process_group, process_birth) != birth:
                raise NetworkPolicyError("LOCAL_SERVICE_LISTENER_IDENTITY_CHANGED")
        self._check_scope(root_pid, root_birth, process_group, process_birth)
        binding = _ServiceBinding(process_id, normalized.host, port, addresses, root_pid, root_birth,
                                  process_group, owners, process_birth, socket_inspector)
        with self._lock:
            self._require_forwarding()
            if port == self.port and self.port:
                raise NetworkPolicyError("GATEWAY_CANNOT_BE_LOCAL_SERVICE")
        return binding

    def bind_service(self, process_id: str, host: str, port: int, *, root_pid: int,
                     root_birth: str, process_group: int,
                     process_birth: Callable[[int], str] = process_birth_identity,
                     socket_inspector: Callable[..., Sequence[TCPSocketEndpoint]] = inspect_tcp_endpoints) -> dict[str, object]:
        """Bind an observed listener to the Host's current task process scope.

        root_birth must be persisted when the Host starts that process.  The
        supplied providers are trusted Host functions, never child input.  All
        listeners covering the exact endpoint must belong to this group.  A
        newly forked worker not observed as a listener requires a fresh bind.
        """
        try:
            binding = self._prepare_service_binding(
                process_id, host, port, root_pid=root_pid, root_birth=root_birth,
                process_group=process_group, process_birth=process_birth, socket_inspector=socket_inspector)
        except NetworkPolicyError as error:
            raise ServiceRegistrationRejected(error.code, str(error), observation=error.observation) from error
        addresses, owners = binding.addresses, binding.owners
        self.revoke_service(process_id)
        with self._lock:
            self._require_forwarding()
            self._services[process_id] = (binding.host, port, addresses)
            self._service_bindings[process_id] = binding
        return {"process_id": process_id, "host": binding.host, "port": port,
                "root_pid": root_pid, "root_birth": root_birth, "process_group": process_group,
                "listener_owners": tuple({"pid": pid, "birth": birth} for pid, birth in owners),
                "state": "BOUND_OBSERVED_LISTENER"}

    @staticmethod
    def _cancel_connection(connection: http.client.HTTPConnection) -> None:
        if connection.sock is not None:
            try:
                connection.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        connection.close()

    def revoke_service(self, process_id: str) -> dict[str, object]:
        with self._lock:
            existed = self._services.pop(process_id, None) is not None
            self._service_bindings.pop(process_id, None)
            connections = tuple(connection for connection, services in self._connection_services.items() if process_id in services)
        for connection in connections:
            self._cancel_connection(connection)
        with self._lock:
            remaining = sum(process_id in services for services in self._connection_services.values())
        return {"process_id": process_id, "registration_revoked": existed,
                "connection_cancellation_requested": len(connections),
                "active_connections_observed": remaining, "forwarded_effects": "NOT_INFERRED"}

    def _validate_local_connection(self, target: _URL, connection: http.client.HTTPConnection) -> tuple[str, ...]:
        if connection.sock is None:
            raise NetworkPolicyError("LOCAL_SERVICE_CONNECTION_NOT_OBSERVED")
        local = tuple(connection.sock.getsockname()[:2])
        peer = tuple(connection.sock.getpeername()[:2])
        with self._lock:
            bindings = tuple(binding for binding in self._service_bindings.values() if binding.port == peer[1] and peer[0] in binding.addresses)
        if not bindings:
            raise NetworkPolicyError("LOCAL_SERVICE_REVOKED")
        accepted: dict[str, _ServiceBinding] = {}
        for binding in bindings:
            self._check_scope(binding.root_pid, binding.root_birth, binding.process_group, binding.birth_provider)
            observations = binding.socket_inspector(peer[1], state="ESTABLISHED")
            if not isinstance(observations, Sequence) or any(not isinstance(item, TCPSocketEndpoint) for item in observations):
                raise NetworkPolicyError("SOCKET_INSPECTION_FORMAT_UNSUPPORTED")
            matches = [item for item in observations if item.local_address == peer and item.peer_address == local and item.state == "ESTABLISHED"]
            if not matches:
                raise NetworkPolicyError("LOCAL_SERVICE_CONNECTION_OWNER_NOT_OBSERVED")
            allowed = dict(binding.owners)
            for item in matches:
                current = self._owner_birth(item.pid, binding.process_group, binding.birth_provider)
                if allowed.get(item.pid) != current:
                    raise NetworkPolicyError("LOCAL_SERVICE_CONNECTION_OWNER_CHANGED")
            self._check_scope(binding.root_pid, binding.root_birth, binding.process_group, binding.birth_provider)
            accepted[binding.process_id] = binding
        with self._lock:
            if self._closed or self._revoked or any(self._service_bindings.get(key) is not binding for key, binding in accepted.items()):
                raise NetworkPolicyError("LOCAL_SERVICE_REVOKED")
            self._connection_services[connection] = frozenset(accepted)
        return tuple(sorted(accepted))

    def lifecycle_status(self) -> dict[str, object]:
        with self._lock:
            listener_running = any(thread.is_alive() for thread in self._threads)
            counts: dict[str, int] = {}
            for services in self._connection_services.values():
                for process_id in services:
                    counts[process_id] = counts.get(process_id, 0) + 1
            reserved = tuple((server.server_address[0], server.server_address[1]) for server in self._servers if server.socket.fileno() >= 0)
            return {"closed": self._closed, "revoked": self._revoked, "listener_running": listener_running,
                    "deny_only": self._revoked and bool(reserved), "reserved_endpoints": reserved,
                    "reservation_held": len(reserved) == 2, "reservation_scope": "GATEWAY_OWNED_DESCRIPTORS",
                    "external_reservations": "NOT_OBSERVED",
                    "forwarding_enabled": bool(reserved) and not self._closed and not self._revoked,
                    "active_request_workers": self._active_workers,
                    "active_client_sockets": len(self._client_sockets),
                    "active_upstream_connections": len(self._upstream_connections),
                    "active_service_connections": counts, "registered_services": len(self._services),
                    "network_trace_path": str(self.trace_path) if self.trace_path else None,
                    "network_trace_failure": self._trace_failure,
                    "quiescent": self._closed and not listener_running and self._active_workers == 0 and not self._client_sockets and not self._upstream_connections}

    def start(self) -> TaskNetworkGateway:
        with self._lock:
            if self._closed:
                raise RuntimeError("gateway is closed")
            if self._revoked:
                raise RuntimeError("gateway is revoked")
            if self._server is not None:
                return self
            self.root.mkdir(parents=True, exist_ok=True)
            private_root = self.root / ("network-" + hashlib.sha256(self.task_id.encode()).hexdigest()[:16] + "-" + uuid.uuid4().hex)
            private_root.mkdir(mode=0o700)
            self._ca = _CertificateAuthority(private_root, self.task_id)
            self.trace_path = private_root / "network-events.jsonl"
            descriptor = os.open(self.trace_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            self._trace_ranges = [[1, 0]]
            self.read_paths = (self._ca.path,)
            gateway = self

            class Handler(_ProxyHandler):
                owner = gateway

            # SBPL accepts localhost, not a numeric host, and that capability
            # covers both address families.  Own the complete permitted pair
            # before starting either listener; a missing reservation is fatal.
            servers: list[ThreadingHTTPServer] = []
            try:
                servers.append(_GatewayHTTPServer(("127.0.0.1", 0), Handler, self))
                port = servers[0].server_address[1]
                servers.append(_GatewayHTTPServer(("::1", port), Handler, self, address_family=socket.AF_INET6))
            except OSError as exc:
                for server in servers:
                    server.server_close()
                raise NetworkPolicyError("GATEWAY_LOOPBACK_RESERVATION_FAILED") from exc
            for server in servers:
                server.daemon_threads = True
                server.block_on_close = False
            self._servers = tuple(servers)
            self._threads = tuple(threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True,
                                                  name=f"network-{self.task_id[:32]}-{index}")
                                  for index, server in enumerate(servers))
            self._server, self._thread = self._servers[0], self._threads[0]
            self.port = port
            for thread in self._threads:
                thread.start()
            return self

    def environment(self) -> dict[str, str]:
        if not self.port or self._closed or self._revoked:
            raise RuntimeError("gateway is not running")
        proxy = f"http://127.0.0.1:{self.port}"
        cert = str(self.read_paths[0])
        result = {
            "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "http_proxy": proxy, "https_proxy": proxy,
            "ALL_PROXY": "", "all_proxy": "", "NO_PROXY": "", "no_proxy": "",
            "SSL_CERT_FILE": cert, "REQUESTS_CA_BUNDLE": cert, "CURL_CA_BUNDLE": cert,
            "PIP_CERT": cert, "NODE_EXTRA_CA_CERTS": cert, "GIT_SSL_CAINFO": cert,
            "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/usr/bin/false",
            "SSH_ASKPASS": "/usr/bin/false", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ALLOW_PROTOCOL": "http:https",
            "GIT_PROTOCOL_FROM_USER": "0", "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "npm_config_proxy": proxy, "npm_config_https_proxy": proxy,
            "npm_config_cafile": cert, "npm_config_strict_ssl": "true",
            "npm_config_audit": "false", "npm_config_fund": "false",
        }
        config = (
            ("credential.helper", ""), ("credential.interactive", "false"),
            ("http.proxy", proxy), ("http.sslCAInfo", cert), ("http.sslVerify", "true"),
            ("http.extraHeader", ""), ("http.cookieFile", ""), ("http.saveCookies", "false"),
            ("protocol.version", "0"), ("fetch.negotiationAlgorithm", "noop"),
            ("protocol.allow", "never"), ("protocol.http.allow", "always"),
            ("protocol.https.allow", "always"),
        )
        result["GIT_CONFIG_COUNT"] = str(len(config))
        for index, (key, value) in enumerate(config):
            result[f"GIT_CONFIG_KEY_{index}"] = key
            result[f"GIT_CONFIG_VALUE_{index}"] = value
        return result

    def duplicate_reservation_fds(self) -> tuple[tuple[int, tuple[str, int]], ...]:
        """Transfer owned, non-inheritable duplicate TCP listener descriptors.

        The caller must close each returned fd exactly once, including on
        launch failure.  Only the trusted wrapper may receive them via
        Popen(pass_fds=...).  It must verify each actual endpoint and
        SO_TYPE=SOCK_STREAM, keep them until capability holders are settled, and
        never pass them to the product child.  They contain no CA key.  Closing
        this gateway or losing its Host does not release wrapper-held aliases.
        """
        with self._lock:
            if self._closed or len(self._servers) != 2:
                raise NetworkPolicyError("GATEWAY_RESERVATION_UNAVAILABLE")
            result: list[tuple[int, tuple[str, int]]] = []
            try:
                for server in self._servers:
                    address = server.socket.getsockname()
                    endpoint = (str(ipaddress.ip_address(address[0])), address[1])
                    if endpoint not in {("127.0.0.1", self.port), ("::1", self.port)} or server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
                        raise NetworkPolicyError("GATEWAY_RESERVATION_ENDPOINT_CHANGED")
                    descriptor = os.dup(server.socket.fileno())
                    result.append((descriptor, endpoint))
                    os.set_inheritable(descriptor, False)
                if {endpoint for _, endpoint in result} != {("127.0.0.1", self.port), ("::1", self.port)}:
                    raise NetworkPolicyError("GATEWAY_RESERVATION_ENDPOINT_CHANGED")
                observed = inspect_tcp_endpoints(self.port, state="LISTEN")
                for descriptor, endpoint in result:
                    if not any(item.pid == os.getpid() and item.fd == descriptor and item.local_address == endpoint and item.state == "LISTEN" for item in observed):
                        raise NetworkPolicyError("GATEWAY_RESERVATION_LISTENER_NOT_OBSERVED")
                return tuple(result)
            except BaseException:
                for descriptor, _ in result:
                    os.close(descriptor)
                raise

    def revoke(self) -> dict[str, object]:
        """Permanently stop forwarding and retain both deny-only listeners.

        Cancellation cannot undo bytes already sent.  Worker/DNS/TLS completion
        and the lifetime of sandboxed capability holders are separate facts.
        """
        with self._lock:
            self._revoked = True
            self._services.clear()
            self._service_bindings.clear()
            clients = tuple(self._client_sockets)
            upstreams = tuple(self._upstream_connections)
        for stream in clients:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            stream.close()
        for connection in upstreams:
            self._cancel_connection(connection)
        return {**self.lifecycle_status(), "connection_cancellation_requested": len(upstreams),
                "forwarded_effects": "NOT_INFERRED"}

    def close(self) -> dict[str, object]:
        """Final Host-side release; caller must settle old sandbox capabilities.

        Use revoke() while any capability holder is live or unknown.  External
        duplicate reservations remain owned by their trusted wrapper.
        """
        self.revoke()
        with self._lock:
            self._closed = True
            servers, threads = self._servers, self._threads
            self._server = None
            self._servers = ()
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)
        return self.lifecycle_status()

    def final_close(self) -> dict[str, object]:
        """Explicit name for close() after the process owner permits release."""
        return self.close()

    def _trace_record(self, **data: object) -> None:
        """Serialize small durable records, retaining an explicitly bounded window.

        Each start owns a fresh private directory.  The lock covers all writers
        and rotation; an event is never split across segments.  Sequence ranges
        make retention loss explicit rather than implying a complete history.
        """
        with self._trace_lock:
            try:
                if self.trace_path is None or self._trace_failure is not None:
                    raise OSError("network trace unavailable")

                def append(fields: Mapping[str, object]) -> None:
                    sequence = self._trace_sequence + 1
                    record = {"schema": "SITINA_NETWORK_TRACE_V1",
                              "task_id_sha256": hashlib.sha256(self.task_id.encode()).hexdigest(),
                              "sequence": sequence, "wall_time_ns": time.time_ns(),
                              "monotonic_ns": time.monotonic_ns(), **fields}
                    encoded = (json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")
                    if len(encoded) > 4096:
                        raise OSError("network trace record exceeds bound")
                    descriptor = os.open(self.trace_path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
                    try:
                        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                            raise OSError("network trace is not a regular file")
                        view = memoryview(encoded)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                raise OSError("network trace short write")
                            view = view[written:]
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    self._trace_sequence = sequence
                    self._trace_ranges[0][1] = sequence

                # Leave room for the rotation marker and one bounded event.
                if self.trace_path.stat().st_size + 8192 > _TRACE_SEGMENT_BYTES:
                    dropped = self._trace_ranges.pop() if len(self._trace_ranges) == _TRACE_SEGMENTS else None
                    oldest = self.trace_path.with_name(self.trace_path.name + f".{_TRACE_SEGMENTS - 1}")
                    if oldest.exists():
                        oldest.unlink()
                    for index in range(_TRACE_SEGMENTS - 2, 0, -1):
                        source = self.trace_path.with_name(self.trace_path.name + f".{index}")
                        if source.exists():
                            source.replace(self.trace_path.with_name(self.trace_path.name + f".{index + 1}"))
                    self.trace_path.replace(self.trace_path.with_name(self.trace_path.name + ".1"))
                    descriptor = os.open(self.trace_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    os.close(descriptor)
                    self._trace_ranges.insert(0, [self._trace_sequence + 1, self._trace_sequence])
                    append({"phase": "trace_rotated", "request_id": data.get("request_id"),
                            "dropped_sequence_range": dropped,
                            "retained_sequence_start": self._trace_ranges[-1][0],
                            "segment_limit": _TRACE_SEGMENTS, "segment_bytes_limit": _TRACE_SEGMENT_BYTES})
                append(data)
            except OSError as exc:
                if self._trace_failure is None:
                    self._trace_failure = {"error_type": type(exc).__name__, "errno": exc.errno,
                                           "last_durable_sequence": self._trace_sequence}
                raise _NetworkTraceError(exc.errno, "network trace unavailable") from exc

    def _record(self, *, trace: _RequestTrace | None = None, **data: object) -> None:
        if self._audit is not None:
            trace_error: Exception | None = None
            if trace is not None:
                try:
                    trace.emit("authorization_callback_started", callback_event=data.get("event"))
                except Exception as exc:
                    trace_error = exc
            try:
                self._audit({"task_id": self.task_id, **data})
            except Exception as exc:
                if trace is not None:
                    try:
                        trace.emit("authorization_callback_failed", callback_event=data.get("event"),
                                   error_type=type(exc).__name__, errno=getattr(exc, "errno", None),
                                   error_code=exc.code if isinstance(exc, NetworkPolicyError) else None)
                    except Exception:
                        pass
                raise
            if trace_error is not None:
                raise trace_error
            if trace is not None:
                trace.emit("authorization_callback_completed", callback_event=data.get("event"))

    def _destinations(self, target: _URL) -> tuple[tuple[str, ...], bool]:
        self._require_forwarding()
        addresses = self._addresses(target.host, target.port)
        with self._lock:
            self._require_forwarding()
            local = any(port == target.port and addresses <= bound for _, port, bound in self._services.values())
            bindings = tuple(binding for binding in self._service_bindings.values()
                             if binding.port == target.port and addresses <= binding.addresses) if local else ()
            if target.port == self.port and any(ipaddress.ip_address(address).is_loopback for address in addresses):
                raise NetworkPolicyError("GATEWAY_SELF_CONNECTION_REJECTED")
        if local:
            if not bindings:
                raise NetworkPolicyError("LOCAL_SERVICE_REVOKED")
            for binding in bindings:
                try:
                    self._check_scope(binding.root_pid, binding.root_birth, binding.process_group, binding.birth_provider)
                except NetworkPolicyError:
                    self.revoke_service(binding.process_id)
                    raise
            with self._lock:
                self._require_forwarding()
                if any(self._service_bindings.get(binding.process_id) is not binding for binding in bindings):
                    raise NetworkPolicyError("LOCAL_SERVICE_REVOKED")
        if not local:
            # Some host DNS filters return :: for an unavailable AAAA record.
            # It is not a destination and must never be connected to. Private,
            # loopback and other non-public answers still reject the whole set.
            addresses = {address for address in addresses
                         if not ipaddress.ip_address(address).is_unspecified}
            if not addresses or not all(ipaddress.ip_address(address).is_global for address in addresses):
                raise NetworkPolicyError("NONPUBLIC_ADDRESS_REJECTED")
        return tuple(sorted(addresses, key=lambda value: (ipaddress.ip_address(value).version, value))), local

    def _destination(self, target: _URL) -> tuple[str, bool]:
        addresses, local = self._destinations(target)
        return addresses[0], local

    def _local_candidate(self, target: _URL) -> bool:
        # Do not resolve attacker-supplied names to decide whether they might be
        # local.  DNS itself can transmit data, so lexical grants come first.
        with self._lock:
            return any(port == target.port and (target.host == host or target.host in addresses or target.host == "localhost")
                       for host, port, addresses in self._services.values())

    def _dependency_metadata_allowed(self, target: _URL) -> bool:
        """A nominated official registry root covers its package metadata only.

        The caller enables this only for a full parent public-read grant.
        Exact-URL-only grants retain their original boundary. Archives and
        metadata sidecars still require an exact verified metadata grant.
        """
        if not self.dependency_registry_reads:
            return False
        kind = self._metadata_kind(target)
        if kind == "pypi-simple":
            return bool(self._allowed_urls & {"https://pypi.org/simple", "https://pypi.org/simple/"})
        if kind == "npm":
            package = unquote(urlsplit(target.value).path).strip("/")
            if re.fullmatch(r"(?:@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*", package):
                return bool(self._allowed_urls & {"https://registry.npmjs.org", "https://registry.npmjs.org/"})
        return False

    def _kind(self, target: _URL, method: str, *, local: bool) -> tuple[str, str | None]:
        with self._lock:
            self._require_forwarding()
            for repository in self._git_urls:
                if target.value == repository + "/info/refs?service=git-upload-pack":
                    if not self.public_git or method != "GET":
                        raise NetworkPolicyError("GIT_READ_NOT_AUTHORIZED")
                    return "git-advertisement", repository
                if target.value == repository + "/git-upload-pack":
                    if not self.public_git or method != "POST":
                        raise NetworkPolicyError("GIT_READ_NOT_AUTHORIZED")
                    return "git-fetch", repository
            if local:
                return "local", None
            if method not in {"GET", "HEAD"}:
                raise NetworkPolicyError("REMOTE_METHOD_NOT_ALLOWED")
            if not self.public_read or (target.value not in self._allowed_urls and not self._dependency_metadata_allowed(target)):
                raise NetworkPolicyError("URL_NOT_AUTHORIZED")
            return "read", None

    def _connect_allowed(self, target: _URL) -> None:
        with self._lock:
            self._require_forwarding()
            authority = (target.host, target.port)
            remote_granted = (self.public_read and authority in self._read_authorities) or (self.public_git and authority in self._git_authorities)
            if not remote_granted and not self._local_candidate(target):
                raise NetworkPolicyError("CONNECT_AUTHORITY_NOT_AUTHORIZED")
        _, local = self._destination(target)
        if not local and not remote_granted:
            raise NetworkPolicyError("CONNECT_AUTHORITY_NOT_AUTHORIZED")

    def _open(self, target: _URL, address: str, trace: _RequestTrace | None = None,
              *, connect_timeout: float = _TIMEOUT) -> http.client.HTTPConnection:
        # Resolve once, connect to that numeric result, and verify the actual peer.
        self._require_forwarding()
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        stream = socket.socket(family, socket.SOCK_STREAM)
        try:
            stream.settimeout(connect_timeout)
            if trace is not None:
                trace.emit("upstream_connect_started", address=address, port=target.port)
            stream.connect((address, target.port))
            if trace is not None:
                trace.emit("upstream_connect_completed")
            if str(ipaddress.ip_address(stream.getpeername()[0])) != address:
                raise NetworkPolicyError("PEER_ADDRESS_MISMATCH")
            if target.scheme == "https":
                if trace is not None:
                    trace.emit("upstream_tls_started")
                stream = self._upstream_context.wrap_socket(stream, server_hostname=target.host)
                if trace is not None:
                    trace.emit("upstream_tls_completed")
            stream.settimeout(_TIMEOUT)
            connection = _PinnedConnection(target.host, target.port, timeout=_TIMEOUT)
            connection.sock = stream
            with self._lock:
                if self._closed or self._revoked:
                    connection.close()
                    self._require_forwarding()
                self._upstream_connections.add(connection)
            return connection
        except BaseException:
            stream.close()
            raise

    def _open_available(self, target: _URL, addresses: tuple[str, ...],
                        trace: _RequestTrace | None = None) -> tuple[http.client.HTTPConnection, str]:
        # All addresses were validated together. Retry only connection setup;
        # no HTTP headers or body have been sent, so no business effect repeats.
        deadline = time.monotonic() + min(24.0, _TIMEOUT)
        last_error: OSError | None = None
        for address in addresses:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                return self._open(target, address, trace, connect_timeout=min(3.0, remaining)), address
            except ssl.SSLError:
                raise
            except OSError as error:
                last_error = error
        if last_error is not None:
            raise last_error
        raise TimeoutError('validated destination connection budget exhausted')

    @staticmethod
    def _metadata_kind(target: _URL) -> str | None:
        path = urlsplit(target.value).path
        if target.scheme != "https" or target.port != 443 or urlsplit(target.value).query:
            return None
        if target.host == "pypi.org" and re.fullmatch(r"/simple/[A-Za-z0-9_.-]+/?", path):
            return "pypi-simple"
        if target.host == "pypi.org" and re.fullmatch(r"/pypi/[A-Za-z0-9_.-]+(?:/[^/]+)?/json", path):
            return "pypi-json"
        if target.host == "registry.npmjs.org" and len(unquote(path).strip("/").split("/")) in {1, 2} and "/-/" not in path:
            return "npm"
        return None

    def _discover_dependencies(self, target: _URL, content_type: str, body: bytes,
                               trace: _RequestTrace | None = None) -> None:
        """Only official metadata can grant exact downstream artifact URLs."""
        kind = self._metadata_kind(target)
        if kind is None:
            return
        links: list[str] = []
        metadata_links: set[str] = set()
        try:
            source_name = unquote(urlsplit(target.value).path).strip("/")
            if kind.startswith("pypi"):
                source_name = source_name.split("/")[1]
            normalize_name = lambda name: re.sub(r"[-_.]+", "-", name).lower()
            if kind == "pypi-simple" and content_type.split(";", 1)[0].strip() == "text/html":
                parser = _SimpleLinks()
                parser.feed(body.decode("utf-8"))
                links = parser.links
                metadata_links = parser.metadata_links
            else:
                value = json.loads(body)
                if not isinstance(value, dict):
                    raise ValueError("metadata root")
                if kind == "pypi-simple":
                    if not isinstance(value.get("name"), str) or normalize_name(value["name"]) != normalize_name(source_name):
                        raise ValueError("simple project name")
                    if not isinstance(value.get("meta"), dict) or not str(value["meta"].get("api-version", "")).startswith("1."):
                        raise ValueError("simple metadata version")
                    files = value.get("files")
                    if not isinstance(files, list):
                        raise ValueError("simple files")
                    for item in files:
                        if not isinstance(item, dict) or not isinstance(item.get("url"), str) or not isinstance(item.get("filename"), str):
                            raise ValueError("simple file")
                        links.append(item["url"])
                        metadata_key = "core-metadata" if "core-metadata" in item else "dist-info-metadata"
                        if _metadata_advertised(item.get(metadata_key), html=False):
                            metadata_links.add(item["url"])
                elif kind == "pypi-json":
                    if not isinstance(value.get("info"), dict) or not isinstance(value["info"].get("name"), str) or normalize_name(value["info"]["name"]) != normalize_name(source_name):
                        raise ValueError("pypi project name")
                    files = value.get("urls")
                    if not isinstance(files, list):
                        raise ValueError("pypi urls")
                    groups = [files]
                    releases = value.get("releases", {})
                    if not isinstance(releases, dict) or any(not isinstance(group, list) for group in releases.values()):
                        raise ValueError("pypi releases")
                    groups.extend(releases.values())
                    for group in groups:
                        for item in group:
                            if not isinstance(item, dict) or not isinstance(item.get("url"), str):
                                raise ValueError("pypi artifact")
                            links.append(item["url"])
                else:
                    if value.get("name") != source_name:
                        raise ValueError("npm package name")
                    versions = value.get("versions")
                    if not isinstance(versions, dict):
                        raise ValueError("npm versions")
                    for version in versions.values():
                        if not isinstance(version, dict) or not isinstance(version.get("dist"), dict) or not isinstance(version["dist"].get("tarball"), str):
                            raise ValueError("npm tarball")
                        links.append(version["dist"]["tarball"])
            authorized: list[str] = []
            sidecars: set[str] = set()
            for link in links:
                artifact = _url(urljoin(target.value, link), fragment_ok=True)
                if artifact.scheme != "https" or artifact.port != 443:
                    continue
                if kind.startswith("pypi") and artifact.host == "files.pythonhosted.org" and urlsplit(artifact.value).path.startswith("/packages/"):
                    authorized.append(artifact.value)
                    parts = urlsplit(artifact.value)
                    # Pip appends to the whole URL, whereas a filename suffix
                    # would precede its query.  Grant neither ambiguous form.
                    if link in metadata_links and not parts.query and parts.path.rsplit("/", 1)[-1]:
                        sidecar = _url(urlunsplit((parts.scheme, parts.netloc, parts.path + ".metadata", "", "")))
                        sidecars.add(sidecar.value)
                        authorized.append(sidecar.value)
                elif kind == "npm" and artifact.host == "registry.npmjs.org" and unquote(urlsplit(artifact.value).path).startswith("/" + source_name + "/-/"):
                    authorized.append(artifact.value)
            with self._lock:
                self.authorize_urls(authorized)
                self._metadata_sidecars.update(sidecars)
        except NetworkPolicyError:
            raise
        except (ValueError, UnicodeError, KeyError, TypeError) as exc:
            # A malformed metadata response grants nothing.  Normal clients can
            # still read it and report their own metadata error.
            self._record(trace=trace, event="dependency_metadata_rejected", source_url=target.value, reason="INVALID_DEPENDENCY_METADATA")
        else:
            self._record(trace=trace, event="dependency_urls", source_url=target.value, authorized_count=len(set(authorized)))


class _ProxyHandler(BaseHTTPRequestHandler):
    owner: TaskNetworkGateway
    protocol_version = "HTTP/1.1"
    server_version = "SitinaTaskGateway/1"
    sys_version = ""
    timeout = _TIMEOUT

    def setup(self) -> None:
        super().setup()
        with self.owner._lock:
            self.owner._client_sockets.add(self.connection)

    def finish(self) -> None:
        try:
            super().finish()
        finally:
            with self.owner._lock:
                self.owner._client_sockets.discard(self.connection)
            self.connection.close()

    def log_message(self, format: str, *args: object) -> None:
        return

    def handle_expect_100(self) -> bool:
        self._deny("EXPECT_CONTINUE_NOT_SUPPORTED")
        return False

    def _deny(self, code: str, *, status: int = 403) -> None:
        body = json.dumps({"error": code, "task_id": self.owner.task_id}, separators=(",", ":")).encode()
        self.close_connection = True
        notification_error: Exception | None = None
        trace = getattr(self, "_request_trace", None) if self.owner._trace_failure is None else None
        try:
            # Preserve the existing notification before a client can consume
            # the denial.  Trace I/O must neither hide it nor grant forwarding.
            self.owner._record(trace=trace, event="request_rejected", method=self.command, reason=code)
        except Exception as exc:
            notification_error = exc
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except (OSError, ValueError):
            # Cancellation can close the client before a denial is delivered.
            # The decision remains recorded; delivery is not inferred.
            pass
        if notification_error is not None:
            raise notification_error

    def _headers(self, target: _URL, kind: str) -> tuple[dict[str, str], int]:
        if len(self.headers) > 80 or sum(len(k) + len(v) for k, v in self.headers.items()) > 32768:
            raise NetworkPolicyError("REQUEST_HEADERS_TOO_LARGE")
        for key, value in self.headers.items():
            if key.lower() not in _IGNORED_REQUEST_HEADERS:
                raise NetworkPolicyError("REQUEST_HEADER_NOT_ALLOWED", key)
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise NetworkPolicyError("INVALID_REQUEST_HEADER")
        host_values = self.headers.get_all("Host", [])
        if len(host_values) != 1:
            raise NetworkPolicyError("INVALID_HOST_HEADER")
        host = _url(f"{target.scheme}://{host_values[0]}/")
        if (host.host, host.port) != (target.host, target.port):
            raise NetworkPolicyError("HOST_HEADER_MISMATCH")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) > 1 or (lengths and not re.fullmatch(r"[0-9]{1,9}", lengths[0])):
            raise NetworkPolicyError("INVALID_CONTENT_LENGTH")
        length = int(lengths[0]) if lengths else 0
        if length > (_MAX_LOCAL_BODY if kind == "local" else _MAX_BODY):
            raise NetworkPolicyError("REQUEST_BODY_TOO_LARGE")
        if kind not in {"local", "git-fetch"} and length:
            raise NetworkPolicyError("REMOTE_BODY_NOT_ALLOWED")
        protocol = self.headers.get_all("Git-Protocol", [])
        if len(protocol) > 1 or any(item not in {"version=0", "version=1"} for item in protocol):
            raise NetworkPolicyError("GIT_PROTOCOL_NOT_SUPPORTED")
        if protocol and not kind.startswith("git-"):
            raise NetworkPolicyError("GIT_PROTOCOL_NOT_SUPPORTED")
        accept_values = self.headers.get_all("Accept", [])
        headers = {"Host": target.authority, "User-Agent": "SitinaTaskGateway/1", "Accept": ", ".join(accept_values) if accept_values else "*/*", "Accept-Encoding": "identity", "Connection": "close"}
        if self.owner._metadata_kind(target) == "pypi-simple":
            headers["Accept"] = "application/vnd.pypi.simple.v1+json"
        content_types = self.headers.get_all("Content-Type", [])
        if len(content_types) > 1:
            raise NetworkPolicyError("INVALID_CONTENT_TYPE")
        if kind == "git-fetch":
            if content_types != ["application/x-git-upload-pack-request"]:
                raise NetworkPolicyError("GIT_INVALID_CONTENT_TYPE")
            headers["Content-Type"] = content_types[0]
            headers["Accept"] = "application/x-git-upload-pack-result"
        elif kind == "local" and content_types:
            headers["Content-Type"] = content_types[0]
        elif content_types:
            raise NetworkPolicyError("REMOTE_BODY_NOT_ALLOWED")
        ranges = self.headers.get_all("Range", [])
        if len(ranges) > 1 or (ranges and not re.fullmatch(r"bytes=(?:[0-9]{1,19}-[0-9]{0,19}|-[0-9]{1,19})", ranges[0])):
            raise NetworkPolicyError("RANGE_NOT_ALLOWED")
        if ranges:
            headers["Range"] = ranges[0]
        return headers, length

    def do_CONNECT(self) -> None:
        trace: _RequestTrace | None = None
        try:
            trace = _RequestTrace(self.owner, "CONNECT", self.path)
            self._request_trace = trace
            self._connect_request_id = trace.request_id
            trace.emit("authorization_started")
            self.owner._require_forwarding()
            if getattr(self, "_tunnel", None) is not None:
                raise NetworkPolicyError("NESTED_CONNECT_NOT_ALLOWED")
            target = _url("https://" + self.path + "/")
            if target.path_query != "/" or urlsplit("https://" + self.path).path:
                raise NetworkPolicyError("INVALID_CONNECT_AUTHORITY")
            self._headers(target, "connect")
            self.owner._connect_allowed(target)
            trace.emit("authorization_completed")
            context = self.owner._ca.context(target.host)
            self.send_response(200, "Connection established")
            self.end_headers()
            self.wfile.flush()
            previous = self.connection
            self.connection = context.wrap_socket(previous, server_side=True, do_handshake_on_connect=False)
            with self.owner._lock:
                self.owner._client_sockets.discard(previous)
                if self.owner._closed or self.owner._revoked:
                    self.connection.close()
                    raise OSError("gateway closed")
                self.owner._client_sockets.add(self.connection)
            self.connection.settimeout(_TIMEOUT)
            trace.emit("client_tls_started")
            self.connection.do_handshake()
            trace.emit("client_tls_completed")
            self.rfile = self.connection.makefile("rb", self.rbufsize)
            self.wfile = self.connection.makefile("wb", self.wbufsize)
            self._tunnel = target
            self.close_connection = True
            self.handle_one_request()
            self.close_connection = True
        except NetworkPolicyError as exc:
            if trace is not None:
                trace.failed(exc)
            self._deny(exc.code)
        except (OSError, ssl.SSLError) as exc:
            if trace is not None:
                trace.failed(exc)
            self.close_connection = True
        except Exception as exc:
            if trace is not None:
                trace.failed(exc)
            self.close_connection = True
            raise

    def _request_target(self) -> _URL:
        tunnel = getattr(self, "_tunnel", None)
        if tunnel is None:
            target = _url(self.path)
            if target.scheme != "http":
                raise NetworkPolicyError("HTTPS_REQUIRES_INSPECTED_CONNECT")
            return target
        if self.path.startswith("/") and not self.path.startswith("//"):
            target = _url(f"https://{tunnel.authority}{self.path}")
        else:
            target = _url(self.path)
        if (target.scheme, target.host, target.port) != ("https", tunnel.host, tunnel.port):
            raise NetworkPolicyError("CONNECT_TARGET_MISMATCH")
        return target

    def _proxy(self) -> None:
        connection: http.client.HTTPConnection | None = None
        trace: _RequestTrace | None = None
        sent = False
        try:
            trace = _RequestTrace(self.owner, self.command, self.path,
                                  getattr(self, "_connect_request_id", None))
            self._request_trace = trace
            trace.emit("authorization_started")
            self.owner._require_forwarding()
            if self.request_version not in {"HTTP/1.0", "HTTP/1.1"}:
                raise NetworkPolicyError("HTTP_VERSION_NOT_SUPPORTED")
            target = self._request_target()
            trace.emit("target_parsed", scheme=target.scheme, host=target.host, port=target.port,
                       url_sha256=hashlib.sha256(target.value.encode()).hexdigest())
            candidate_local = self.owner._local_candidate(target)
            kind, repository = self.owner._kind(target, self.command, local=candidate_local)
            headers, length = self._headers(target, kind)
            planned_kind = kind
            trace.emit("destination_resolution_started")
            addresses, local = self.owner._destinations(target)
            address = addresses[0]
            trace.emit("destination_resolution_completed", address=address, local=local)
            kind, repository = self.owner._kind(target, self.command, local=local)
            if kind != planned_kind:
                headers, length = self._headers(target, kind)
            trace.emit("request_body_read_started", expected_bytes=length)
            body = self.rfile.read(length) if length else b""
            if len(body) != length:
                raise NetworkPolicyError("INCOMPLETE_REQUEST_BODY")
            if kind == "git-fetch":
                with self.owner._lock:
                    advertisement = self.owner._advertisements.get(repository)
                if advertisement is None:
                    raise NetworkPolicyError("GIT_ADVERTISEMENT_REQUIRED")
                body = _git_request(body, advertisement)
            if body or self.command in {"POST", "PUT", "PATCH"}:
                headers["Content-Length"] = str(len(body))
            trace.emit("authorization_completed", kind=kind)
            self.owner._record(trace=trace, event="request_forwarding", method=self.command, url=target.value, kind=kind, address=address)
            connection, address = self.owner._open_available(target, addresses, trace)
            if connection.sock is None:
                raise NetworkPolicyError("UPSTREAM_CONNECTION_NOT_AVAILABLE")
            service_process_ids = self.owner._validate_local_connection(target, connection) if local else ()
            # The Host can now bind the established local connection to the
            # listener's actual process identity, before any HTTP payload.
            try:
                self.owner._record(
                    trace=trace,
                    event="connection_opened", method=self.command,
                    url=target.value, kind=kind,
                    service_process_ids=service_process_ids,
                    local_address=tuple(connection.sock.getsockname()),
                    peer_address=tuple(connection.sock.getpeername()),
                )
            except NetworkPolicyError:
                raise
            except _NetworkTraceError:
                raise
            except Exception as exc:
                raise NetworkPolicyError("CONNECTION_AUTHORITY_REJECTED") from exc
            trace.emit("upstream_request_started")
            connection.request(self.command, target.path_query, body=body if body else None, headers=headers)
            trace.emit("response_headers_wait_started")
            response = connection.getresponse()
            trace.emit("response_headers_received", status=response.status)
            if response.status in {401, 407}:
                raise NetworkPolicyError("AUTHENTICATION_REQUIRED")
            content_type = response.getheader("Content-Type", "")
            with self.owner._lock:
                metadata_sidecar = target.value in self.owner._metadata_sidecars
            buffered: bytes | None = None
            trace.emit("response_body_read_started")
            redirect = response.status in {301, 302, 303, 307, 308}
            if redirect:
                if metadata_sidecar:
                    raise NetworkPolicyError("DEPENDENCY_METADATA_REDIRECT_REJECTED")
                locations = [value for key, value in response.getheaders() if key.lower() == "location"]
                if len(locations) != 1:
                    raise NetworkPolicyError("INVALID_REDIRECT")
                destination = _url(urljoin(target.value, locations[0]))
                self.owner._destination(destination)
                if kind.startswith("git-"):
                    raise NetworkPolicyError("GIT_REDIRECT_REAUTHORIZE_REQUIRED")
                if not local:
                    self.owner.authorize_urls([destination.value])
            if kind == "git-advertisement" and response.status == 200:
                if content_type.split(";", 1)[0].strip() != "application/x-git-upload-pack-advertisement" or response.getheader("Content-Encoding", "identity") != "identity":
                    raise NetworkPolicyError("GIT_INVALID_ADVERTISEMENT")
                buffered = response.read(_MAX_ADVERTISEMENT + 1)
                trace.emit("response_body_read_completed", response_bytes=len(buffered))
                if len(buffered) > _MAX_ADVERTISEMENT:
                    raise NetworkPolicyError("GIT_ADVERTISEMENT_TOO_LARGE")
                advertisement = _advertisement(buffered)
                with self.owner._lock:
                    self.owner._advertisements[repository] = advertisement
            elif kind == "git-fetch" and response.status == 200 and content_type.split(";", 1)[0].strip() != "application/x-git-upload-pack-result":
                raise NetworkPolicyError("GIT_INVALID_RESULT_TYPE")
            elif self.command == "GET" and response.status == 200 and (self.owner._metadata_kind(target) or metadata_sidecar):
                if metadata_sidecar and response.getheader("Content-Encoding", "identity") != "identity":
                    raise NetworkPolicyError("DEPENDENCY_METADATA_ENCODING_REJECTED")
                buffered = response.read(_MAX_METADATA + 1)
                trace.emit("response_body_read_completed", response_bytes=len(buffered))
                if len(buffered) > _MAX_METADATA:
                    raise NetworkPolicyError("DEPENDENCY_METADATA_TOO_LARGE")
                if not metadata_sidecar and response.getheader("Content-Encoding", "identity") == "identity":
                    self.owner._discover_dependencies(target, content_type, buffered, trace)
            trace.emit("client_response_headers_started")
            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() not in _HOP_HEADERS and key.lower() != "content-length":
                    self.send_header(key, value)
            if buffered is not None:
                self.send_header("Content-Length", str(len(buffered)))
            elif self.command == "HEAD" and response.getheader("Content-Length"):
                self.send_header("Content-Length", response.getheader("Content-Length"))
            self.send_header("Connection", "close")
            self.end_headers()
            sent = True
            self.close_connection = True
            response_bytes = 0
            if self.command != "HEAD":
                if buffered is not None:
                    trace.phase = "client_response_body_write"
                    self.wfile.write(buffered)
                    response_bytes = len(buffered)
                else:
                    while True:
                        trace.phase = "response_body_read"
                        chunk = response.read(65536)
                        if not chunk:
                            break
                        trace.phase = "client_response_body_write"
                        self.wfile.write(chunk)
                        response_bytes += len(chunk)
                    trace.emit("response_body_read_completed", response_bytes=response_bytes)
            trace.phase = "client_response_flush"
            self.wfile.flush()
            trace.emit("response_body_completed", response_bytes=response_bytes)
            self.owner._record(trace=trace, event="request_completed", method=self.command, url=target.value, status=response.status)
            trace.emit("request_completed", status=response.status)
        except NetworkPolicyError as exc:
            if trace is not None:
                trace.failed(exc)
            if not sent:
                self._deny(exc.code)
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError) as exc:
            if trace is not None:
                trace.failed(exc)
            if not sent:
                self._deny("UPSTREAM_CONNECTION_FAILED", status=502)
        except Exception as exc:
            if trace is not None:
                trace.failed(exc)
            raise
        finally:
            if connection is not None:
                with self.owner._lock:
                    self.owner._upstream_connections.discard(connection)
                    self.owner._connection_services.pop(connection, None)
                connection.close()
            self.close_connection = True

    do_GET = _proxy
    do_HEAD = _proxy
    do_POST = _proxy
    do_PUT = _proxy
    do_PATCH = _proxy
    do_DELETE = _proxy
    do_OPTIONS = _proxy
