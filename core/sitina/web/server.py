from __future__ import annotations

import hashlib
import json
import mimetypes
import secrets
import signal
import threading
import time
import webbrowser
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from sitina.extensions.authority import ExtensionAuthorityConflict, ExtensionAuthorityError
from sitina.extensions.manager import ExtensionInstallError

from .sessions import WebError, WebSessions
from .event_stream import SnapshotPool, serve_events

STATIC = Path(__file__).parent / "static"
ASSETS = {"app.js": "text/javascript", "app.css": "text/css", "activity.css": "text/css", "logo.svg": "image/svg+xml", "work-plan.js": "text/javascript", "memory-ui.js": "text/javascript"}


class LocalWebServer(ThreadingHTTPServer):
    daemon_threads = True
    # Rebind after a clean stop even while old TCP connections drain. The
    # exclusive registry lease still prevents two owners of this task store.
    allow_reuse_address = True

    def __init__(self, sessions: WebSessions, port: int = 8765):
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("invalid local port")
        super().__init__(("127.0.0.1", port), WebHandler)
        self.sessions = sessions
        self.origins = {f"http://127.0.0.1:{self.server_port}", f"http://localhost:{self.server_port}"}
        self.hosts = {f"127.0.0.1:{self.server_port}", f"localhost:{self.server_port}"}
        self.cookie_name = f"sitina_web_{self.server_port}"
        self._auth: dict[str, tuple[str, float]] = {}
        self._auth_lock = threading.Lock()
        self.snapshot_pool = SnapshotPool(sessions.snapshot)
        self.event_slots = threading.BoundedSemaphore(8)

    def authentication(self, token: str | None):
        with self._auth_lock:
            record = self._auth.get(token or "")
            if record and record[1] > time.monotonic():
                return token, record[0], False
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            now = time.monotonic()
            self._auth = {key: value for key, value in self._auth.items() if value[1] > now}
            self._auth[token] = (csrf, now + 12 * 3600)
            return token, csrf, True


class WebHandler(BaseHTTPRequestHandler):
    server: LocalWebServer
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        # Never log cookies, request bodies, profile values or user prompts.
        pass

    def _origin_check(self):
        if self.headers.get("Host") not in self.server.hosts:
            raise WebError("仅允许本机页面访问。", status=403, code="host_rejected")
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.server.origins:
            raise WebError("请求来源不属于此本机页面。", status=403, code="origin_rejected")
        if self.headers.get("Sec-Fetch-Site") not in {None, "same-origin", "none"}:
            raise WebError("其他网站不能访问此本地服务。", status=403, code="site_rejected")

    def _cookie(self):
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except Exception:
            return None
        item = jar.get(self.server.cookie_name)
        return item.value if item else None

    def _authorize(self):
        self._origin_check()
        token = self._cookie()
        with self.server._auth_lock:
            auth = self.server._auth.get(token or "")
        if auth is None or auth[1] <= time.monotonic():
            raise WebError("本地页面连接已过期，请刷新页面。", status=401, code="expired")
        if self.command in {"POST", "DELETE"}:
            if self.headers.get("Origin") not in self.server.origins:
                raise WebError("操作需要本机页面的明确来源。", status=403, code="origin_required")
            csrf = self.headers.get("X-Sitina-CSRF", "")
            if not secrets.compare_digest(auth[0], csrf):
                raise WebError("操作令牌无效，请刷新页面。", status=403, code="csrf_rejected")

    def _headers(self, status: int, mime: str, size: int, *, cookie: str | None = None):
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("X-Frame-Options", "DENY")
        if self.close_connection:
            self.send_header("Connection", "close")
        if cookie:
            self.send_header("Set-Cookie", f"{self.server.cookie_name}={cookie}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200")
        self.end_headers()

    def _json(self, value, status: int = 200, *, cookie: str | None = None):
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if status >= 400 and self.command in {"POST", "DELETE"}:
            # An authorization/body rejection may leave request bytes unread.
            self.close_connection = True
        self._headers(status, "application/json; charset=utf-8", len(raw), cookie=cookie)
        self.wfile.write(raw)

    def _body(self):
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            raise WebError("操作需要完整 JSON 参数。", status=415, code="content_type")
        length = self.headers.get("Content-Length", "")
        if not length.isdecimal() or not 0 < int(length) <= 12 * 1024 * 1024:
            raise WebError("请求内容长度无效。", status=413, code="body_bound")
        if self.headers.get("Transfer-Encoding"):
            raise WebError("不接受分块操作参数。", status=400, code="chunked_body")
        self.connection.settimeout(15)
        raw = self.rfile.read(int(length))
        if len(raw) != int(length):
            raise WebError("请求参数不完整，尚未派发操作。", status=400, code="incomplete_body")
        def exact_object(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate JSON field")
                value[key] = item
            return value
        try:
            value = json.loads(raw, object_pairs_hook=exact_object)
        except (UnicodeError, ValueError) as error:
            raise WebError("请求 JSON 不完整或无效，尚未派发操作。", status=400, code="invalid_json") from error
        if not isinstance(value, dict):
            raise WebError("操作参数必须是对象。", status=400, code="invalid_json")
        return value

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def _handle(self):
        try:
            self._route()
        except WebError as error:
            self._json({"error": {"code": error.code, "message": str(error)}}, error.status)
        except ExtensionAuthorityConflict as error:
            self._json({"error": {"code": "skills_authority_conflict", "message": str(error)}}, 409)
        except (ExtensionAuthorityError, ExtensionInstallError) as error:
            self._json({"error": {"code": "skills_validation", "message": str(error)}}, 400)
        except (BrokenPipeError, ConnectionResetError):
            # Client loss does not cancel native work and never retransmits.
            pass
        except Exception as error:
            self._json({"error": {"code": "server_error",
                "message": "本地服务无法完成此操作。已有记录保留，操作不会自动重发。",
                "error_type": type(error).__name__}}, 500)

    def _route(self):
        self._origin_check()
        url = urlsplit(self.path)
        path = url.path
        if self.command == "GET" and path == "/":
            token, _csrf, _new = self.server.authentication(self._cookie())
            raw = (STATIC / "index.html").read_bytes()
            self._headers(200, "text/html; charset=utf-8", len(raw), cookie=token)
            self.wfile.write(raw)
            return
        if self.command == "GET" and path.startswith("/assets/"):
            name = path.removeprefix("/assets/")
            if name not in ASSETS:
                raise WebError("资源不存在。", status=404, code="not_found")
            raw = (STATIC / name).read_bytes()
            self._headers(200, ASSETS[name] + "; charset=utf-8", len(raw))
            self.wfile.write(raw)
            return
        self._authorize()
        if path == "/api/bootstrap" and self.command == "GET":
            _token, csrf, _new = self.server.authentication(self._cookie())
            self._json({"csrf": csrf, "models": [{"choice": "flash", "label": "DeepSeek Flash"},
                                                {"choice": "pro", "label": "DeepSeek Pro"}],
                        "profile": "deepseek", "local_only": True})
            return
        sessions = self.server.sessions
        if path == "/api/memory":
            if self.command == "GET":
                self._json(sessions.memory_view(parse_qs(url.query).get("session_id", [None])[0]))
            elif self.command == "POST":
                self._json(sessions.memory_action(self._body()))
            else:
                raise WebError("此方法不可用。", status=405, code="method_not_allowed")
            return
        if path == "/api/deletions":
            if self.command == "GET":
                self._json({"job": sessions.deletion_queue.view()})
            elif self.command == "POST":
                self._json({"job": sessions.start_deletion(self._body())}, 202)
            else:
                raise WebError("不支持此操作。", status=405, code="method")
            return
        deletion_parts = path.strip("/").split("/")
        if len(deletion_parts) == 4 and deletion_parts[:2] == ["api", "deletions"] and deletion_parts[3] == "control":
            if self.command != "POST":
                raise WebError("不支持此操作。", status=405, code="method")
            self._json({"job": sessions.control_deletion(deletion_parts[2], self._body())})
            return
        if path == "/api/skills/inspect" and self.command == "POST":
            self._json(sessions.skills_inspect(self._body()))
            return
        if path == "/api/skills":
            if self.command == "GET":
                self._json(sessions.skills_list())
            elif self.command == "POST":
                self._json(sessions.skills_mutate(self._body()))
            else:
                raise WebError("不支持此操作。", status=405, code="method")
            return
        if path == "/api/sessions":
            if self.command == "GET":
                self._json({"sessions": sessions.list()})
            elif self.command == "POST":
                self._json(sessions.create(self._body().get("request_id")), 201)
            else:
                raise WebError("不支持此操作。", status=405, code="method")
            return
        parts = path.strip("/").split("/")
        if len(parts) < 3 or parts[:2] != ["api", "sessions"]:
            raise WebError("入口不存在。", status=404, code="not_found")
        sid = parts[2]
        if len(parts) == 4 and parts[3] == "events" and self.command == "GET":
            serve_events(self, sid)
            return
        if len(parts) == 3:
            if self.command == "GET":
                snapshot = sessions.snapshot(sid)
                digest = hashlib.sha256(json.dumps(snapshot, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
                if parse_qs(url.query).get("since") == [digest]:
                    self._json({"unchanged": True, "version": digest})
                else:
                    self._json({**snapshot, "version": digest})
            elif self.command == "DELETE":
                self._json(sessions.delete(sid, self._body().get("confirmation")))
            else:
                raise WebError("不支持此操作。", status=405, code="method")
            return
        if parts[3] == "executions":
            if len(parts) == 4 and self.command == "GET":
                if url.query:
                    raise WebError("执行列表不接受查询参数。", status=400, code="invalid_cursor")
                self._json(sessions.executions(sid))
            elif len(parts) == 5 and self.command == "GET":
                query = parse_qs(url.query, keep_blank_values=True)
                allowed = {"stdout_offset", "stderr_offset", "combined_offset", "control_request_id"}
                if set(query) - allowed or any(len(values) != 1 for values in query.values()):
                    raise WebError("输出游标参数无效。", status=400, code="invalid_cursor")
                offsets = {}
                for name in ("stdout", "stderr", "combined"):
                    field = name + "_offset"
                    if field in query:
                        value = query[field][0]
                        if not value.isascii() or not value.isdecimal() or len(value) > 19:
                            raise WebError("输出游标必须是非负字节位置。", status=400, code="invalid_cursor")
                        offsets[name] = int(value)
                self._json(sessions.execution(sid, unquote(parts[4]), offsets,
                    control_request_id=query.get("control_request_id", [None])[0]))
            elif len(parts) == 6 and parts[5] == "control" and self.command == "POST":
                if url.query:
                    raise WebError("进程控制不接受查询参数。", status=400, code="invalid_control")
                self._json(sessions.execution_control(sid, unquote(parts[4]), self._body()))
            elif len(parts) in {4, 5, 6}:
                raise WebError("不支持此操作。", status=405, code="method")
            else:
                raise WebError("入口不存在。", status=404, code="not_found")
            return
        if len(parts) != 4:
            raise WebError("入口不存在。", status=404, code="not_found")
        resource = parts[3]
        if self.command == "GET" and resource == "context-activity":
            self._json(sessions.context_activity(sid))
            return
        if self.command == "GET" and resource == "activity":
            query = parse_qs(url.query)
            before = query.get("before", [None])[0]
            if before is not None and (not before.isascii() or not before.isdecimal() or len(before) > 19):
                raise WebError("操作记录游标无效。", status=400, code="invalid_cursor")
            self._json(sessions.activity(sid, query.get("task_id", [""])[0],
                                         before=int(before) if before is not None else None))
            return
        if self.command == "GET" and resource in {"file", "attachment", "preview"}:
            query = parse_qs(url.query)
            fid = query.get("id", [""])[0]
            unverified = query.get("unverified", [""])[0] == "1"
            raw, name = (sessions.read_file(sid, fid, allow_unverified=unverified if resource == "file" else False,
                                           expected_version=query.get("version", [None])[0]) if resource != "attachment"
                         else sessions.read_upload(sid, fid))
            if resource == "preview":
                if not query.get("version") or Path(name).suffix.lower() not in {".html", ".htm"}:
                    raise WebError("仅支持当前已验证网页的预览。", status=400, code="invalid_preview")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("X-Content-Type-Options", "nosniff")
                # Executable artifacts get an opaque origin, never the app's
                # session authority. A user can still follow outbound links.
                self.send_header("Content-Security-Policy", "sandbox allow-scripts allow-popups allow-popups-to-escape-sandbox; default-src 'none'; script-src 'unsafe-inline' https:; style-src 'unsafe-inline' https:; img-src data: blob: https: http:; font-src data: https:; connect-src 'none'; form-action 'none'; base-uri 'none'")
                self.end_headers()
                self.wfile.write(raw)
                return
            # Native-owned files are downloads, never executable web pages.
            from urllib.parse import quote
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + quote(name, safe=""))
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Sitina-Artifact-Access", "unverified-recovery" if resource == "file" and unverified else "normal")
            self.end_headers()
            self.wfile.write(raw)
            return
        if self.command != "POST":
            raise WebError("不支持此操作。", status=405, code="method")
        body = self._body()
        if resource == "messages":
            self._json(sessions.message(sid, body), 202)
        elif resource == "control":
            self._json(sessions.control(sid, body), 202)
        elif resource == "model":
            self._json(sessions.model(sid, body.get("choice")))
        elif resource == "attachments":
            self._json(sessions.upload(sid, body), 201)
        elif resource == "open-folder":
            self._json(sessions.open_folder(sid))
        else:
            raise WebError("入口不存在。", status=404, code="not_found")


def serve(*, port: int = 8765, open_browser: bool = False) -> int:
    if not 1 <= port <= 65535:
        raise SystemExit("web port must be between 1 and 65535")
    sessions = WebSessions.current()
    try:
        server = LocalWebServer(sessions, port)
    except Exception:
        sessions.close()
        raise
    url = f"http://127.0.0.1:{server.server_port}"
    print(f"Sitina 本地网页 · {url}", flush=True)
    print("只监听本机。关闭页面不会取消任务；停止服务会先暂停并等待原生任务收口。", flush=True)
    if open_browser:
        webbrowser.open(url)
    stop = threading.Event()
    shutdown = {"mode": None}
    handoff_signal = getattr(signal, "SIGUSR1", None)

    def request_shutdown(signum, _frame):
        # Signal handlers only record intent. Ordinary exit takes priority
        # over an earlier handoff until the final backend handoff decision.
        if signum == handoff_signal:
            if shutdown["mode"] is None:
                shutdown["mode"] = "handoff"
        else:
            shutdown["mode"] = "stop"
        stop.set()

    previous = {}
    signals = [signal.SIGINT, signal.SIGTERM]
    if handoff_signal is not None:
        signals.append(handoff_signal)
    for sig in signals:
        previous[sig] = signal.signal(sig, request_shutdown)
    server.timeout = 0.5
    try:
        while not stop.is_set():
            server.handle_request()
    finally:
        server.server_close()
        last_notice = 0.0
        try:
            while True:
                complete = (sessions.close(timeout=15, preserve_running=True,
                                           handoff_current=lambda: shutdown["mode"] == "handoff")
                            if shutdown["mode"] == "handoff" else sessions.close(timeout=15))
                if complete:
                    break
                now = time.monotonic()
                if now - last_notice >= 15:
                    print("正在等待原生操作安全收口；未强制释放写入所有权。", flush=True)
                    last_notice = now
                time.sleep(0.25)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    return 0
