from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

from sitina.constants import SITINA_HOME
from sitina.storage import SitinaStore
from sitina.utils import ensure_dir, iso_now, new_id, sha256_text


class GitWorktreeManager:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)

    def prepare(self, repo: str, run_id: str) -> dict[str, Any]:
        repo_path = Path(repo).expanduser().resolve(strict=False)
        check = subprocess.run(["git", "-C", str(repo_path), "rev-parse", "--is-inside-work-tree"], capture_output=True, text=True)
        if check.returncode != 0:
            result = {"status": "not_git", "repo": str(repo_path), "reason": "repo is not a git worktree"}
            self.store.record_audit("git_worktree_prepare", result, run_id=run_id, exit_status="not_git")
            return result
        worktree_dir = self.home / "artifacts" / "worktrees" / run_id
        ensure_dir(worktree_dir.parent)
        if worktree_dir.exists():
            result = {"status": "ok", "repo": str(repo_path), "worktree": str(worktree_dir), "note": "already exists"}
            self.store.record_audit("git_worktree_prepare", result, run_id=run_id, exit_status="ok")
            return result
        proc = subprocess.run(["git", "-C", str(repo_path), "worktree", "add", "--detach", str(worktree_dir), "HEAD"], capture_output=True, text=True)
        status = "ok" if proc.returncode == 0 else "failed"
        result = {"status": status, "repo": str(repo_path), "worktree": str(worktree_dir), "stdout": proc.stdout[-1000:], "stderr": proc.stderr[-1000:]}
        self.store.record_audit("git_worktree_prepare", result, run_id=run_id, exit_status=status)
        return result

    def generate_patch(self, repo: str, run_id: str, *, source: str | None = None) -> dict[str, Any]:
        repo_path = Path(repo).expanduser().resolve(strict=False)
        source_path = Path(source).expanduser().resolve(strict=False) if source else repo_path
        repo_check = self._check_git(repo_path)
        if repo_check:
            result = {"status": "not_git", "repo": str(repo_path), "source": str(source_path), "reason": repo_check}
            self.store.record_audit("git_patch_generate", result, run_id=run_id, exit_status="not_git")
            return result
        source_check = self._check_git(source_path)
        if source_check:
            result = {"status": "not_git", "repo": str(repo_path), "source": str(source_path), "reason": source_check}
            self.store.record_audit("git_patch_generate", result, run_id=run_id, exit_status="not_git")
            return result

        diff = subprocess.run(["git", "-C", str(source_path), "diff", "--binary", "HEAD"], capture_output=True, text=True)
        names = subprocess.run(["git", "-C", str(source_path), "diff", "--name-only", "HEAD"], capture_output=True, text=True)
        if diff.returncode != 0:
            result = {"status": "failed", "repo": str(repo_path), "source": str(source_path), "stderr": diff.stderr[-2000:]}
            self.store.record_audit("git_patch_generate", result, run_id=run_id, exit_status="failed")
            return result
        changed_files = [line for line in names.stdout.splitlines() if line.strip()]
        diff_text = diff.stdout
        untracked = subprocess.run(["git", "-C", str(source_path), "ls-files", "--others", "--exclude-standard"], capture_output=True, text=True)
        for rel_path in [line for line in untracked.stdout.splitlines() if line.strip()]:
            no_index = subprocess.run(
                ["git", "-C", str(source_path), "diff", "--binary", "--no-index", "--", "/dev/null", rel_path],
                capture_output=True,
                text=True,
            )
            if no_index.stdout:
                diff_text += ("\n" if diff_text and not diff_text.endswith("\n") else "") + no_index.stdout
                changed_files.append(rel_path)
        if not diff_text:
            result = {"status": "no_changes", "repo": str(repo_path), "source": str(source_path), "changed_files": changed_files}
            self.store.record_audit("git_patch_generate", result, run_id=run_id, exit_status="no_changes")
            return result
        patch_dir = (self.home / "artifacts" / "patches").resolve(strict=False)
        ensure_dir(patch_dir)
        patch_hash = sha256_text(diff_text)
        patch_id = self._patch_id_for_hash(patch_hash)
        patch_path = patch_dir / f"{run_id}-{patch_id}.patch"
        patch_path.write_text(diff_text, encoding="utf-8")
        changed_files = sorted(set(changed_files))
        artifact = {
            "run_id": run_id,
            "patch_id": patch_id,
            "patch_path": str(patch_path),
            "patch_hash": patch_hash,
            "target_repo": str(repo_path),
            "worktree_path": str(source_path),
            "base_commit": self._git_stdout(source_path, ["rev-parse", "HEAD"]),
            "created_at": iso_now(),
            "generated_by": "git_worktree_patch",
            "changed_files": changed_files,
        }
        self._write_json(self._patch_artifact_path(patch_path), artifact)
        result = {
            "status": "ok",
            "repo": str(repo_path),
            "source": str(source_path),
            "patch_id": patch_id,
            "patch_path": str(patch_path),
            "patch_hash": patch_hash,
            "patch_artifact": str(self._patch_artifact_path(patch_path)),
            "changed_files": changed_files,
            "next": "reviewer_accept_required_then_user_approve_apply",
        }
        self.store.record_audit("git_patch_generate", result, run_id=run_id, exit_status="ok")
        return result

    def record_review(
        self,
        patch: str,
        run_id: str,
        *,
        decision: str = "accept",
        reviewer: str = "cli",
        notes: str | None = None,
    ) -> dict[str, Any]:
        patch_path = Path(patch).expanduser().resolve(strict=False)
        artifact, blocked = self._validated_patch_artifact(patch_path, run_id)
        if blocked:
            return self._operation_blocked("git_patch_review", run_id, patch_path, blocked["reason"], extra=blocked)
        if decision not in {"accept", "reject", "needs_changes"}:
            result = {"status": "blocked", "patch_path": str(patch_path), "reason": "reviewer decision must be accept, reject, or needs_changes"}
            self.store.record_audit("git_patch_review", result, run_id=run_id, exit_status="blocked")
            return result
        review = {
            "run_id": run_id,
            "patch_id": artifact["patch_id"],
            "patch_hash": artifact["patch_hash"],
            "target_repo": artifact["target_repo"],
            "reviewer_decision": decision,
            "reviewer": reviewer,
            "reviewed_at": iso_now(),
            "reviewer_notes": notes or "",
        }
        self._write_json(self._review_artifact_path(patch_path), review)
        result = {"status": "ok", "review_artifact": str(self._review_artifact_path(patch_path)), **review}
        self.store.record_audit("git_patch_review", result, run_id=run_id, exit_status="ok")
        return result

    def record_approval(self, patch: str, run_id: str, *, approved_by: str = "cli") -> dict[str, Any]:
        patch_path = Path(patch).expanduser().resolve(strict=False)
        artifact, blocked = self._validated_patch_artifact(patch_path, run_id)
        if blocked:
            return self._operation_blocked("git_patch_approval", run_id, patch_path, blocked["reason"], extra=blocked)
        review, review_blocked = self._validated_review_artifact(patch_path, run_id, artifact)
        if review_blocked:
            return self._operation_blocked("git_patch_approval", run_id, patch_path, review_blocked["reason"], artifact=artifact, extra=review_blocked)
        approval_path = self._approval_artifact_path(patch_path)
        if approval_path.exists():
            approval = self._read_json(approval_path)
            approval_blocked = self._validate_approval_record(approval, run_id, artifact)
            if approval_blocked:
                return self._operation_blocked("git_patch_approval", run_id, patch_path, approval_blocked["reason"], artifact=artifact, extra=approval_blocked)
            result = {"status": "ok", "approval_artifact": str(approval_path), **approval, "reviewer_decision": review["reviewer_decision"]}
            self.store.record_audit("git_patch_approval", result, run_id=run_id, approval_id=approval.get("approval_id"), exit_status="ok")
            return result
        approval = {
            "approval_id": "appr_" + new_id(),
            "run_id": run_id,
            "patch_id": artifact["patch_id"],
            "patch_hash": artifact["patch_hash"],
            "approved_by": approved_by,
            "approved_at": iso_now(),
            "approval_scope": artifact.get("changed_files", []),
            "target_repo": artifact["target_repo"],
        }
        self._write_json(approval_path, approval)
        result = {"status": "ok", "approval_artifact": str(approval_path), **approval, "reviewer_decision": review["reviewer_decision"]}
        self.store.record_audit("git_patch_approval", result, run_id=run_id, approval_id=approval["approval_id"], exit_status="ok")
        return result

    def apply_patch(self, repo: str, patch: str, run_id: str, *, approve: bool = False) -> dict[str, Any]:
        repo_path = Path(repo).expanduser().resolve(strict=False)
        patch_path = Path(patch).expanduser().resolve(strict=False)
        check = self._check_git(repo_path)
        if check:
            result = {"status": "not_git", "repo": str(repo_path), "patch_path": str(patch_path), "reason": check}
            self.store.record_audit("git_patch_apply", result, run_id=run_id, exit_status="not_git")
            return result
        artifact, blocked = self._validated_patch_artifact(patch_path, run_id)
        if blocked:
            return self._apply_blocked(run_id, repo_path, patch_path, blocked["reason"])
        if artifact["target_repo"] != str(repo_path):
            return self._apply_blocked(run_id, repo_path, patch_path, "target_repo does not match patch artifact", artifact=artifact)
        review, review_blocked = self._validated_review_artifact(patch_path, run_id, artifact)
        if review_blocked:
            return self._apply_blocked(run_id, repo_path, patch_path, review_blocked["reason"], artifact=artifact)
        if not approve:
            return self._apply_blocked(run_id, repo_path, patch_path, "approval record missing; rerun with --approve after reviewer accept", artifact=artifact)
        approval = self.record_approval(str(patch_path), run_id, approved_by="cli")
        if approval.get("status") != "ok":
            return self._apply_blocked(run_id, repo_path, patch_path, approval.get("reason", "approval record invalid"), artifact=artifact)
        approval_blocked = self._validate_approval_record(approval, run_id, artifact)
        if approval_blocked:
            return self._apply_blocked(run_id, repo_path, patch_path, approval_blocked["reason"], artifact=artifact)
        check_proc = subprocess.run(["git", "-C", str(repo_path), "apply", "--check", str(patch_path)], capture_output=True, text=True)
        if check_proc.returncode != 0:
            result = {
                "status": "blocked",
                "repo": str(repo_path),
                "patch_path": str(patch_path),
                "patch_id": artifact["patch_id"],
                "patch_hash": artifact["patch_hash"],
                "reason": "patch does not apply cleanly; conflict or drift detected",
                "stderr": check_proc.stderr[-2000:],
            }
            self.store.record_audit("git_patch_apply_conflict", result, run_id=run_id, exit_status="blocked")
            return result
        apply_proc = subprocess.run(["git", "-C", str(repo_path), "apply", str(patch_path)], capture_output=True, text=True)
        status = "ok" if apply_proc.returncode == 0 else "blocked"
        result = {
            "status": status,
            "repo": str(repo_path),
            "patch_path": str(patch_path),
            "patch_id": artifact["patch_id"],
            "patch_hash": artifact["patch_hash"],
            "approval_id": approval["approval_id"],
            "reviewer_decision": review["reviewer_decision"],
            "stdout": apply_proc.stdout[-1000:],
            "stderr": apply_proc.stderr[-2000:],
        }
        self.store.record_audit("git_patch_apply", result, run_id=run_id, exit_status=status)
        return result

    def _check_git(self, path: Path) -> str | None:
        check = subprocess.run(["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"], capture_output=True, text=True)
        if check.returncode != 0:
            return "repo is not a git worktree"
        return None

    def _validated_patch_artifact(self, patch_path: Path, run_id: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
        managed_error = self._managed_patch_path_error(patch_path)
        if managed_error:
            return {}, {
                "status": "blocked",
                "reason": managed_error,
                "patch_path": str(patch_path),
                "allowed_patch_roots": [str(root) for root in self._managed_patch_roots()],
            }
        if not patch_path.exists():
            return {}, {"status": "blocked", "reason": "patch file missing", "patch_path": str(patch_path)}
        if not patch_path.is_file():
            return {}, {"status": "blocked", "reason": "patch_path is not a file", "patch_path": str(patch_path)}
        artifact_path = self._patch_artifact_path(patch_path)
        if not artifact_path.exists():
            return {}, {"status": "blocked", "reason": "patch artifact missing", "patch_path": str(patch_path)}
        artifact = self._read_json(artifact_path)
        for key in ("run_id", "patch_id", "patch_path", "patch_hash", "target_repo"):
            if not artifact.get(key):
                return {}, {"status": "blocked", "reason": f"patch artifact missing {key}", "patch_artifact": str(artifact_path)}
        if artifact["run_id"] != run_id:
            return {}, {"status": "blocked", "reason": "run_id does not match patch artifact", "patch_artifact": str(artifact_path)}
        if Path(artifact["patch_path"]).expanduser().resolve(strict=False) != patch_path:
            return {}, {"status": "blocked", "reason": "patch_path does not match patch artifact", "patch_artifact": str(artifact_path)}
        current_hash = self._patch_hash(patch_path)
        if current_hash != artifact["patch_hash"]:
            return {}, {"status": "blocked", "reason": "patch_hash changed after artifact generation", "patch_hash": current_hash, "expected_patch_hash": artifact["patch_hash"]}
        if artifact.get("generated_by") != "git_worktree_patch":
            return {}, {"status": "blocked", "reason": "patch artifact generated_by is not git_worktree_patch", "patch_artifact": str(artifact_path)}
        expected_patch_id = self._patch_id_for_hash(current_hash)
        if artifact["patch_id"] != expected_patch_id:
            return {}, {"status": "blocked", "reason": "patch_id does not match patch_hash", "patch_artifact": str(artifact_path)}
        if patch_path.name != f"{run_id}-{artifact['patch_id']}.patch":
            return {}, {"status": "blocked", "reason": "patch filename does not match run_id and patch_id", "patch_path": str(patch_path)}
        if not self._has_generate_audit(run_id, patch_path, artifact):
            return {}, {"status": "blocked", "reason": "patch artifact is not bound to a git_patch_generate audit record", "patch_artifact": str(artifact_path)}
        return artifact, None

    def _validated_review_artifact(self, patch_path: Path, run_id: str, patch_artifact: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
        merge_path = self._review_merge_artifact_path(patch_path)
        if merge_path.exists():
            merge = self._read_json(merge_path)
            if merge.get("run_id") != run_id:
                return {}, {"status": "blocked", "reason": "merged reviewer artifact run_id mismatch"}
            if merge.get("patch_id") != patch_artifact.get("patch_id"):
                return {}, {"status": "blocked", "reason": "merged reviewer artifact patch_id mismatch"}
            if merge.get("patch_hash") != patch_artifact.get("patch_hash"):
                return {}, {"status": "blocked", "reason": "merged reviewer artifact patch_hash mismatch"}
            if not merge.get("target_repo"):
                return {}, {"status": "blocked", "reason": "merged reviewer artifact missing target_repo"}
            if merge.get("target_repo") != patch_artifact.get("target_repo"):
                return {}, {"status": "blocked", "reason": "merged reviewer artifact target_repo mismatch"}
            if merge.get("merged_decision") != "accept":
                return merge, {"status": "blocked", "reason": f"merged reviewer decision is {merge.get('merged_decision')}"}
            return {
                "run_id": merge["run_id"],
                "patch_id": merge["patch_id"],
                "patch_hash": merge["patch_hash"],
                "target_repo": merge["target_repo"],
                "reviewer_decision": "accept",
                "reviewer": "multi_reviewer_merge",
                "merge_artifact": str(merge_path),
            }, None
        review_path = self._review_artifact_path(patch_path)
        if not review_path.exists():
            return {}, {"status": "blocked", "reason": "reviewer artifact missing", "patch_id": patch_artifact.get("patch_id")}
        review = self._read_json(review_path)
        if review.get("run_id") != run_id:
            return {}, {"status": "blocked", "reason": "reviewer artifact run_id mismatch"}
        if review.get("patch_id") != patch_artifact.get("patch_id"):
            return {}, {"status": "blocked", "reason": "reviewer artifact patch_id mismatch"}
        if review.get("patch_hash") != patch_artifact.get("patch_hash"):
            return {}, {"status": "blocked", "reason": "reviewer artifact patch_hash mismatch"}
        if not review.get("target_repo"):
            return {}, {"status": "blocked", "reason": "reviewer artifact missing target_repo"}
        if review.get("target_repo") != patch_artifact.get("target_repo"):
            return {}, {"status": "blocked", "reason": "reviewer artifact target_repo mismatch"}
        if review.get("reviewer_decision") != "accept":
            return review, {"status": "blocked", "reason": f"reviewer decision is {review.get('reviewer_decision')}"}
        return review, None

    def _validate_approval_record(self, approval: dict[str, Any], run_id: str, patch_artifact: dict[str, Any]) -> dict[str, Any] | None:
        if approval.get("run_id") != run_id:
            return {"status": "blocked", "reason": "approval record run_id mismatch"}
        if approval.get("patch_id") != patch_artifact.get("patch_id"):
            return {"status": "blocked", "reason": "approval record patch_id mismatch"}
        if approval.get("patch_hash") != patch_artifact.get("patch_hash"):
            return {"status": "blocked", "reason": "approval record patch_hash mismatch"}
        if approval.get("target_repo") != patch_artifact.get("target_repo"):
            return {"status": "blocked", "reason": "approval record target_repo mismatch"}
        return None

    def _apply_blocked(self, run_id: str, repo_path: Path, patch_path: Path, reason: str, *, artifact: dict[str, Any] | None = None) -> dict[str, Any]:
        result = {
            "status": "blocked",
            "repo": str(repo_path),
            "patch_path": str(patch_path),
            "reason": reason,
        }
        if artifact:
            result.update({"patch_id": artifact.get("patch_id"), "patch_hash": artifact.get("patch_hash")})
        self.store.record_audit("git_patch_apply", result, run_id=run_id, exit_status="blocked")
        return result

    def _operation_blocked(
        self,
        operation: str,
        run_id: str,
        patch_path: Path,
        reason: str,
        *,
        artifact: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = {"status": "blocked", "patch_path": str(patch_path), "reason": reason}
        if artifact:
            result.update({"patch_id": artifact.get("patch_id"), "patch_hash": artifact.get("patch_hash")})
        if extra:
            for key, value in extra.items():
                if key not in result:
                    result[key] = value
        self.store.record_audit(operation, result, run_id=run_id, exit_status="blocked")
        return result

    def _patch_hash(self, patch_path: Path) -> str:
        return sha256_text(patch_path.read_text(encoding="utf-8"))

    def _patch_id_for_hash(self, patch_hash: str) -> str:
        return f"patch_{patch_hash.split(':', 1)[1][:24]}"

    def _managed_patch_roots(self) -> list[Path]:
        raw_roots = [
            self.home / "artifacts" / "patches",
            self.home / "artifacts" / "worktrees",
            self.home / "outputs" / "artifacts",
            self.home / "runtime" / "worktrees",
            self.home / ".sitina" / "worktrees",
        ]
        return [root.expanduser().resolve(strict=False) for root in raw_roots]

    def _managed_patch_path_error(self, patch_path: Path) -> str | None:
        resolved = patch_path.expanduser().resolve(strict=False)
        if not resolved.name.endswith(".patch"):
            return "patch_path must be a managed .patch file"
        if any(self._is_relative_to(resolved, root) for root in self._managed_patch_roots()):
            return None
        return "patch_path outside Sitina managed patch roots"

    def _has_generate_audit(self, run_id: str, patch_path: Path, artifact: dict[str, Any]) -> bool:
        try:
            with self.store.connect() as conn:
                rows = conn.execute(
                    """
                    SELECT payload_json
                    FROM audit_log
                    WHERE run_id = ? AND operation = 'git_patch_generate' AND exit_status = 'ok'
                    ORDER BY id DESC
                    """,
                    (run_id,),
                ).fetchall()
        except sqlite3.Error:
            return False
        for (payload_json,) in rows:
            try:
                payload = json.loads(payload_json)
            except json.JSONDecodeError:
                continue
            if (
                payload.get("patch_path") == str(patch_path)
                and payload.get("patch_id") == artifact.get("patch_id")
                and payload.get("patch_hash") == artifact.get("patch_hash")
                and payload.get("repo") == artifact.get("target_repo")
            ):
                return True
        return False

    def _is_relative_to(self, path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    def _patch_artifact_path(self, patch_path: Path) -> Path:
        return patch_path.with_name(patch_path.name + ".artifact.json")

    def _review_artifact_path(self, patch_path: Path) -> Path:
        return patch_path.with_name(patch_path.name + ".review.json")

    def _review_merge_artifact_path(self, patch_path: Path) -> Path:
        return patch_path.with_name(patch_path.name + ".review.merge.json")

    def _approval_artifact_path(self, patch_path: Path) -> Path:
        return patch_path.with_name(patch_path.name + ".approval.json")

    def _read_json(self, path: Path) -> dict[str, Any]:
        return json.loads(path.read_text(encoding="utf-8"))

    def _write_json(self, path: Path, value: dict[str, Any]) -> None:
        ensure_dir(path.parent)
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _git_stdout(self, path: Path, args: list[str]) -> str | None:
        proc = subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True)
        return proc.stdout.strip() if proc.returncode == 0 else None
