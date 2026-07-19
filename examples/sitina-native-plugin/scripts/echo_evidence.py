#!/usr/bin/env python3
from __future__ import annotations

import json
import sys


value = json.load(sys.stdin)
print(json.dumps({"confirmed": True, "text": str(value.get("text", ""))}, ensure_ascii=False))
