"""Bounded, read-only session observation for server-sent events.

Native Journal remains authoritative. Streams send complete UI snapshots, not
business commands; reconnecting never submits, resumes or replays an operation.
"""
from __future__ import annotations

from concurrent.futures import Future
import hashlib
import json
import threading
import time


class SnapshotCapacityError(RuntimeError):
    pass


class SnapshotPool:
    """Coalesce readers by session; a slow native read cannot multiply workers."""

    def __init__(self, reader, *, capacity=8, interval=1.0, clock=time.monotonic):
        self.reader = reader
        self.capacity = capacity
        self.interval = interval
        self.clock = clock
        self.lock = threading.Lock()
        self.pending = {}

    def request(self, sid):
        with self.lock:
            now = self.clock()
            previous = self.pending.get(sid)
            if previous is not None:
                future, completed_at = previous
                if not future.done() or now - completed_at < self.interval:
                    return future
            # Retain in-flight reads even after all viewers disconnect. Do not
            # cancel/reissue them just because the HTTP connection was lost.
            self.pending = {key: value for key, value in self.pending.items()
                            if not value[0].done() or now - value[1] < 30}
            if sum(not value[0].done() for value in self.pending.values()) >= self.capacity:
                raise SnapshotCapacityError('session observation capacity reached')
            future = Future()
            self.pending[sid] = (future, now)

            def capture():
                try:
                    snapshot = self.reader(sid)
                    raw = json.dumps(snapshot, sort_keys=True, ensure_ascii=False).encode('utf-8')
                    digest = hashlib.sha256(raw).hexdigest()
                    value = {**snapshot, 'version': digest}
                except Exception as error:
                    with self.lock:
                        self.pending[sid] = (future, self.clock())
                        future.set_exception(error)
                else:
                    with self.lock:
                        self.pending[sid] = (future, self.clock())
                        future.set_result(value)

            threading.Thread(target=capture, name='sitina-session-observation', daemon=True).start()
            return future


def frame(event, value, *, event_id=None):
    if event not in {'snapshot', 'context', 'problem', 'heartbeat', 'reconnect'}:
        raise ValueError('unsupported SSE event')
    prefix = ''
    if event_id is not None:
        if len(event_id) != 64 or any(c not in '0123456789abcdef' for c in event_id):
            raise ValueError('invalid snapshot identity')
        prefix = 'id: ' + event_id + '\n'
    data = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    return (prefix + 'event: ' + event + '\ndata: ' + data + '\n\n').encode('utf-8')


def serve_events(handler, sid):
    """One bounded SSE connection; auth is checked before and during delivery."""
    server = handler.server
    if not server.event_slots.acquire(blocking=False):
        handler._json({'error': {'code': 'event_capacity', 'message': '实时连接暂时繁忙，页面将只读重连。'}}, 503)
        return
    try:
        handler.connection.settimeout(10)
        handler.close_connection = True
        handler.send_response(200)
        handler.send_header('Content-Type', 'text/event-stream; charset=utf-8')
        handler.send_header('Cache-Control', 'no-store')
        handler.send_header('X-Content-Type-Options', 'nosniff')
        handler.send_header('X-Accel-Buffering', 'no')
        handler.send_header('Connection', 'close')
        handler.end_headers()
        handler.wfile.write(b'retry: 2000\n\n')
        handler.wfile.flush()

        def send(event, value, event_id=None):
            handler.wfile.write(frame(event, value, event_id=event_id))
            handler.wfile.flush()

        deadline = time.monotonic() + 600
        last_version = None  # Always resynchronize a reconnect with a full snapshot.
        last_context = None
        last_heartbeat = 0.0
        last_problem = None
        waiting_since = time.monotonic()
        observed_future = None
        while time.monotonic() < deadline:
            try:
                handler._authorize()
            except Exception:
                send('problem', {'code': 'expired', 'message': '本机连接已过期，正在重新连接；原任务不会重发。'})
                return
            now = time.monotonic()
            try:
                future = server.snapshot_pool.request(sid)
                if future is not observed_future:
                    observed_future = future
                    waiting_since = now
                if future.done():
                    data = future.result()
                    if data['version'] != last_version or last_problem is not None:
                        send('snapshot', data, data['version'])
                        last_version = data['version']
                    last_problem = None
                elif now - waiting_since >= 5:
                    problem = '任务状态读取较慢。已有内容仍保留；正在只读核对，不会重发操作。'
                    if problem != last_problem:
                        send('problem', {'code': 'snapshot_slow', 'message': problem})
                        last_problem = problem
                # This lightweight source deliberately avoids native projection
                # locks, so compaction remains visible during a slow snapshot.
                activity = server.sessions.context_activity(sid)
                context_bytes = json.dumps(activity, sort_keys=True)
                if context_bytes != last_context:
                    send('context', activity)
                    last_context = context_bytes
            except Exception as error:
                code = getattr(error, 'code', 'status_unavailable')
                message = (str(error) if hasattr(error, 'code') else
                           '暂时无法取得新的任务状态。已有记录保留；正在只读重连，不会重新执行任务。')
                problem = (code, message)
                if problem != last_problem:
                    send('problem', {'code': code, 'message': message})
                    last_problem = problem
                if code in {'not_found', 'invalid_session'}:
                    return
            if now - last_heartbeat >= 10:
                send('heartbeat', {'connected': True})
                last_heartbeat = now
            time.sleep(0.4)
        send('reconnect', {'reason': 'connection_rotation'})
    except (OSError, ValueError):
        # A closed viewer is not a native task failure or a reason to replay.
        return
    finally:
        server.event_slots.release()
