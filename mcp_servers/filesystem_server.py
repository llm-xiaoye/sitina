from __future__ import annotations

from pathlib import Path

from common_stdio import checked_allowed_path, json_result, run_stdio_server


TOOLS = [
    {
        "name": "list_dir",
        "description": "List a local directory under allowed roots.",
        "inputSchema": {
            "type": "object",
            "required": ["path"],
            "properties": {"path": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "read_file",
        "description": "Read a UTF-8 text file under allowed roots.",
        "inputSchema": {
            "type": "object",
            "required": ["path"],
            "properties": {"path": {"type": "string"}, "max_bytes": {"type": "integer"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "stat_path",
        "description": "Return metadata for a path under allowed roots.",
        "inputSchema": {
            "type": "object",
            "required": ["path"],
            "properties": {"path": {"type": "string"}},
            "additionalProperties": False,
        },
    },
]


def list_dir(args):
    path, blocked = checked_allowed_path(args["path"], operation="list_dir")
    if blocked:
        return json_result(blocked)
    assert path is not None
    if not path.exists():
        return json_result({"status": "not_found", "path": str(path), "reason": "path does not exist"})
    if not path.is_dir():
        return json_result({"status": "blocked", "path": str(path), "reason": "path is not a directory"})
    items = []
    for child in sorted(path.iterdir(), key=lambda item: item.name):
        items.append({"name": child.name, "path": str(child), "type": "dir" if child.is_dir() else "file"})
    return json_result({"status": "ok", "path": str(path), "entries": items})


def read_file(args):
    path, blocked = checked_allowed_path(args["path"], operation="read_file")
    if blocked:
        return json_result(blocked)
    assert path is not None
    if not path.exists():
        return json_result({"status": "not_found", "path": str(path), "reason": "path does not exist"})
    if not path.is_file():
        return json_result({"status": "blocked", "path": str(path), "reason": "path is not a file"})
    max_bytes = max(0, int(args.get("max_bytes", 65536)))
    data = path.read_bytes()[:max_bytes]
    return json_result({"status": "ok", "path": str(path), "content": data.decode("utf-8", errors="replace"), "truncated": path.stat().st_size > max_bytes})


def stat_path(args):
    path, blocked = checked_allowed_path(args["path"], operation="stat_path")
    if blocked:
        return json_result(blocked)
    assert path is not None
    if not path.exists():
        return json_result({"status": "not_found", "path": str(path), "exists": False, "reason": "path does not exist"})
    stat = path.stat()
    return json_result(
        {
            "status": "ok",
            "path": str(path),
            "exists": path.exists(),
            "type": "dir" if path.is_dir() else "file",
            "size": stat.st_size,
            "mtime": stat.st_mtime,
        }
    )


if __name__ == "__main__":
    run_stdio_server(TOOLS, {"list_dir": list_dir, "read_file": read_file, "stat_path": stat_path})
