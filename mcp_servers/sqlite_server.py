from __future__ import annotations

import sqlite3

from common_stdio import json_result, require_allowed_path, run_stdio_server


TOOLS = [
    {
        "name": "query",
        "description": "Run a read-only SQLite query against a local database under allowed roots.",
        "inputSchema": {
            "type": "object",
            "required": ["db_path", "query"],
            "properties": {"db_path": {"type": "string"}, "query": {"type": "string"}, "limit": {"type": "integer"}},
            "additionalProperties": False,
        },
    }
]


def query(args):
    db_path = require_allowed_path(args["db_path"])
    sql = str(args["query"]).strip()
    lowered = sql.lower()
    if not (lowered.startswith("select") or lowered.startswith("pragma") or lowered.startswith("with")):
        raise ValueError("only read-only SELECT/PRAGMA/WITH queries are allowed")
    limit = int(args.get("limit", 100))
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql).fetchmany(limit)
    return json_result({"status": "ok", "rows": [dict(row) for row in rows], "limit": limit})


if __name__ == "__main__":
    run_stdio_server(TOOLS, {"query": query})
