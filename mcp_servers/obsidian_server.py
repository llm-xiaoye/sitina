from __future__ import annotations

from common_stdio import json_result, require_allowed_path, run_stdio_server


TOOLS = [
    {
        "name": "search",
        "description": "Search markdown files under a local Obsidian vault root.",
        "inputSchema": {
            "type": "object",
            "required": ["root", "query"],
            "properties": {"root": {"type": "string"}, "query": {"type": "string"}, "limit": {"type": "integer"}},
            "additionalProperties": False,
        },
    }
]


def search(args):
    root = require_allowed_path(args["root"])
    needle = str(args["query"]).lower()
    limit = int(args.get("limit", 10))
    results = []
    for path in root.rglob("*.md"):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for idx, line in enumerate(lines, start=1):
            if needle in line.lower():
                results.append({"path": str(path), "line": idx, "citation": f"{path}:{idx}", "excerpt": line})
                break
        if len(results) >= limit:
            break
    return json_result({"status": "ok", "results": results})


if __name__ == "__main__":
    run_stdio_server(TOOLS, {"search": search})
