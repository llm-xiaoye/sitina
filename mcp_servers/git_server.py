from __future__ import annotations

import subprocess

from common_stdio import json_result, require_allowed_path, run_stdio_server


TOOLS = [
    {
        "name": "status",
        "description": "Return git status --short for a local repository.",
        "inputSchema": {"type": "object", "required": ["repo"], "properties": {"repo": {"type": "string"}}, "additionalProperties": False},
    },
    {
        "name": "diff",
        "description": "Return git diff for a local repository.",
        "inputSchema": {"type": "object", "required": ["repo"], "properties": {"repo": {"type": "string"}, "path": {"type": "string"}}, "additionalProperties": False},
    },
    {
        "name": "log",
        "description": "Return recent git log entries.",
        "inputSchema": {"type": "object", "required": ["repo"], "properties": {"repo": {"type": "string"}, "max_count": {"type": "integer"}}, "additionalProperties": False},
    },
    {
        "name": "show",
        "description": "Return git show output for a revision.",
        "inputSchema": {"type": "object", "required": ["repo", "rev"], "properties": {"repo": {"type": "string"}, "rev": {"type": "string"}}, "additionalProperties": False},
    },
]


def run_git(repo, args):
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=20)
    if proc.returncode != 0 and "not a git repository" in (proc.stderr or "").lower():
        return {"status": "not_git", "stdout": proc.stdout, "stderr": proc.stderr}
    return {"status": "ok" if proc.returncode == 0 else "failed", "exit_code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}


def status(args):
    repo = require_allowed_path(args["repo"])
    return json_result(run_git(repo, ["status", "--short"]))


def diff(args):
    repo = require_allowed_path(args["repo"])
    cmd = ["diff", "--"]
    if args.get("path"):
        cmd.append(args["path"])
    return json_result(run_git(repo, cmd))


def log(args):
    repo = require_allowed_path(args["repo"])
    max_count = str(int(args.get("max_count", 10)))
    return json_result(run_git(repo, ["log", f"--max-count={max_count}", "--oneline"]))


def show(args):
    repo = require_allowed_path(args["repo"])
    return json_result(run_git(repo, ["show", "--stat", "--oneline", args["rev"]]))


if __name__ == "__main__":
    run_stdio_server(TOOLS, {"status": status, "diff": diff, "log": log, "show": show})
