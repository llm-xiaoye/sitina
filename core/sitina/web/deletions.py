"""Resumable queue metadata; actual removal stays in WebSessions.delete."""
from __future__ import annotations

import copy
import json
import os
import re
import threading
import time
from pathlib import Path

from sitina.security.redaction import redact_text

ACTIVE = {"RUNNING", "PAUSING", "PAUSED"}


class DeletionQueue:
    def __init__(self, path: Path, remove, describe, observe=None):
        self.path, self.remove, self.describe = path, remove, describe
        self.observe = observe
        self.lock = threading.RLock()
        self.thread = None
        self.jobs = []
        if path.exists():
            value = json.loads(path.read_text())
            if value.get("schema") != "SITINA_WEB_DELETIONS_V1" or not isinstance(value.get("jobs"), list):
                raise ValueError("Invalid deletion queue metadata")
            self.jobs = value["jobs"]
            for job in self.jobs:
                if job["status"] in ACTIVE:
                    job["status"] = "PAUSED"
                    for item in job["items"]:
                        if item["status"] == "DELETING":
                            item.update(status="UNCONFIRMED", error="服务停止时结果尚未确认，没有自动重试。")
            self._save()

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_name(self.path.name + ".new")
        with temp.open("w", encoding="utf-8") as stream:
            os.chmod(temp, 0o600)
            json.dump({"schema":"SITINA_WEB_DELETIONS_V1", "jobs":self.jobs}, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, self.path)

    def _public(self, job):
        if job is None:
            return None
        items = copy.deepcopy(job["items"])
        for item in items:
            item.setdefault("reason_code", self._legacy_reason(item.get("error")))
            item["outcome_status"] = item["status"]
            item["confirmation"] = "REMOVED" if item["status"] == "DELETED" else "NOT_OBSERVED"
            if item["status"] in {"FAILED", "UNCONFIRMED"}:
                observation = self._observe(item["id"])
                item["reconciliation"] = observation
                item["confirmation"] = observation["confirmation"]
                item["outcome_status"] = {"REMOVED":"DELETED", "RETAINED":"FAILED"}.get(
                    observation["confirmation"], "UNCONFIRMED")
        counts = {status:sum(item["outcome_status"] == status for item in items)
                  for status in ("QUEUED", "DELETING", "DELETED", "FAILED", "UNCONFIRMED")}
        current = next((item for item in items if item["status"] == "DELETING"), None)
        status = job["status"]
        if status not in ACTIVE and counts["DELETED"] == len(items):
            status = "COMPLETED"
        return {"id":job["id"], "status":status, "recorded_status":job["status"], "total":len(items),
                "deleted":counts["DELETED"], "failed":counts["FAILED"] + counts["UNCONFIRMED"],
                "not_deleted":counts["FAILED"], "unconfirmed":counts["UNCONFIRMED"],
                "remaining":counts["QUEUED"], "current":copy.deepcopy(current),
                "items":items, "updated_at":job["updated_at"]}

    @staticmethod
    def _legacy_reason(error):
        if not error:
            return None
        if "任务或外部动作尚未确认收口" in error:
            return "unsettled"
        if "原生控制端点仍存在" in error:
            return "control_endpoint_present"
        if "another live coordinator" in error:
            return "authority_busy"
        return "legacy_unclassified"

    def _observe(self, sid):
        if self.observe is not None:
            try:
                value = self.observe(sid)
                if isinstance(value, dict) and value.get("confirmation") in {"REMOVED", "RETAINED", "UNKNOWN"}:
                    return value
            except Exception:
                pass  # A failed read cannot confirm either removal or retention.
        return {"confirmation":"UNKNOWN", "reason_code":"observation_unavailable"}

    def view(self):
        with self.lock:
            return self._public(self.jobs[-1] if self.jobs else None)

    def create(self, request_id, ids):
        if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", request_id):
            raise ValueError("删除请求标识无效。")
        if not isinstance(ids, list) or not 1 <= len(ids) <= 1000 or any(
                not isinstance(sid, str) or not re.fullmatch(r"[0-9a-f]{32}", sid) for sid in ids) or len(set(ids)) != len(ids):
            raise ValueError("请选择有效且不重复的会话。")
        with self.lock:
            previous = next((job for job in self.jobs if job["id"] == request_id), None)
            if previous is not None:
                if [item["id"] for item in previous["items"]] != ids:
                    raise ValueError("同一删除请求不能改为另一批会话。")
                return self._public(previous)
            if any(job["status"] in ACTIVE for job in self.jobs):
                raise ValueError("已有删除队列，请先继续并完成它。")
            items = [{"id":sid, "title":self.describe(sid), "status":"QUEUED", "error":None} for sid in ids]
            job = {"id":request_id, "status":"RUNNING", "items":items, "updated_at":time.time()}
            self.jobs.append(job)
            self.jobs = self.jobs[-10:]
            self._save()
            self._start(job)
            return self._public(job)

    def control(self, job_id, action):
        with self.lock:
            job = next((job for job in self.jobs if job["id"] == job_id), None)
            if job is None:
                raise ValueError("删除队列不存在。")
            if action == "pause":
                if job["status"] == "RUNNING":
                    job["status"] = "PAUSING"
            elif action == "resume":
                if job["status"] == "PAUSED":
                    job["status"] = "RUNNING"
                    self._start(job)
            else:
                raise ValueError("只支持暂停或继续删除。")
            job["updated_at"] = time.time()
            self._save()
            return self._public(job)

    def _start(self, job):
        # create/resume only call here on a state transition under the lock.
        # A prior worker may be returning after committing PAUSED/COMPLETED.
        self.thread = threading.Thread(target=self._run, args=(job,), daemon=True, name="sitina-delete-queue")
        self.thread.start()

    def _run(self, job):
        while True:
            with self.lock:
                if job["status"] == "PAUSING":
                    job["status"] = "PAUSED"
                    job["updated_at"] = time.time()
                    self._save()
                    return
                item = next((item for item in job["items"] if item["status"] == "QUEUED"), None)
                if item is None:
                    job["status"] = "COMPLETED_WITH_ERRORS" if any(item["status"] != "DELETED" for item in job["items"]) else "COMPLETED"
                    job["updated_at"] = time.time()
                    self._save()
                    return
                item["status"] = "DELETING"
                job["updated_at"] = time.time()
                self._save()
            try:
                observed = self._observe(item["id"])
                result = {"status":"deleted"} if observed["confirmation"] == "REMOVED" else self.remove(item["id"], item["id"])
                if result.get("status") != "deleted":
                    raise ValueError("删除结果尚未确认。")
                status, error, reason_code = "DELETED", None, None
            except Exception as exc:
                status, error = "FAILED", redact_text(str(exc))[:500]
                reason_code = getattr(exc, "code", None) or self._legacy_reason(error)
            with self.lock:
                item.update(status=status, error=error, reason_code=reason_code)
                job["updated_at"] = time.time()
                self._save()

    def close(self, timeout=15):
        with self.lock:
            for job in self.jobs:
                if job["status"] == "RUNNING":
                    job["status"] = "PAUSING"
            self._save()
            thread = self.thread
        if thread is not None:
            thread.join(timeout)
        return thread is None or not thread.is_alive()
