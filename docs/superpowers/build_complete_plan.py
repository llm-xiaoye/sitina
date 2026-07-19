#!/usr/bin/env python3
"""Build or verify the generated Sitina B+ complete design/plan document."""

from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "docs/superpowers/2026-07-13-sitina-bplus-complete-design-and-implementation-plan.md"


@dataclass(frozen=True)
class Source:
    part: str
    label: str
    relative_path: str


SOURCES = (
    Source("第一部分：完整正式设计规范", "正式 B+ 数据架构设计规范", "docs/superpowers/specs/2026-07-13-sitina-bplus-data-architecture-design.md"),
    Source("第二部分：实施总路线图", "实施总路线图", "docs/superpowers/plans/2026-07-13-sitina-bplus-implementation-roadmap.md"),
    Source("第三部分：Phase -1 Execution Foundation", "Phase -1 Execution Foundation", "docs/superpowers/plans/2026-07-13-sitina-bplus-phase-minus-1-execution-foundation.md"),
    Source("第四部分：Phase 0 Legacy Compatibility", "Phase 0 Legacy Compatibility", "docs/superpowers/plans/2026-07-13-sitina-bplus-phase-0-legacy-compatibility.md"),
    Source("第五部分：Phase 1 Journal/CAS/Projection Kernel", "Phase 1 Journal/CAS/Projection Kernel", "docs/superpowers/plans/2026-07-13-sitina-bplus-phase-1-journal-cas-kernel.md"),
    Source("第六部分：Phase 2 Run/Task/Process/Scheduling", "Phase 2 Run/Task/Process/Scheduling", "docs/superpowers/plans/2026-07-13-sitina-bplus-phase-2-run-task-scheduling.md"),
    Source("第七部分：Phase 3 Collaboration Protocols", "Phase 3 Collaboration Protocols", "docs/superpowers/plans/2026-07-13-sitina-bplus-phase-3-collaboration-protocols.md"),
    Source("第八部分：Phase 4 Effect/Observation", "Phase 4 Effect/Observation", "docs/superpowers/plans/2026-07-13-sitina-bplus-phase-4-effects-observations.md"),
    Source("第九部分：Phase 5 Evidence/Archive", "Phase 5 Evidence/Archive", "docs/superpowers/plans/2026-07-13-sitina-bplus-phase-5-evidence-archive.md"),
    Source("第十部分：Phase 6A Cutover Tooling/Readiness", "Phase 6A Cutover Tooling/Readiness", "docs/superpowers/plans/2026-07-13-sitina-bplus-phase-6a-cutover-tooling-readiness.md"),
    Source("第十一部分：Phase 6B Authorized Production Cutover", "Phase 6B Authorized Production Cutover", "docs/superpowers/plans/2026-07-13-sitina-bplus-phase-6b-authorized-production-cutover.md"),
    Source("第十二部分：Phase 7 Backend Scale-out", "Phase 7 Backend Scale-out", "docs/superpowers/plans/2026-07-13-sitina-bplus-phase-7-backend-scaleout.md"),
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_sources() -> list[tuple[Source, str, str, int]]:
    loaded: list[tuple[Source, str, str, int]] = []
    for source in SOURCES:
        path = ROOT / source.relative_path
        body = path.read_text(encoding="utf-8")
        if not body.endswith("\n"):
            raise SystemExit(f"source must end with newline: {source.relative_path}")
        loaded.append((source, body, digest(body.encode("utf-8")), len(body.splitlines())))
    return loaded


def render() -> str:
    loaded = read_sources()
    lines = [
        "# Sitina B+ 完整设计与实施前方案（唯一展示版）",
        "",
        "- **状态：** 执行安全与兼容性优化修订完成；尚未实施",
        "- **原始设计日期：** 2026-07-13",
        "- **最终合同审查日期：** 2026-07-14",
        "- **修订标识：** `BPLUS_PLAN_V3_CONTRACT_CLOSED_IMPLEMENTATION_READY`",
        "- **唯一展示文件：** 本文件（由来源文件确定性生成，禁止手工修改）",
        "- **内容策略：** 完整汇编，不做摘要替代，不因单文件展示而删减分阶段内容",
        "- **禁止误读：** 除严格受限的 `PHASE_MINUS_1_BOOTSTRAP_V0` 外，没有当前用户会话绑定的 `EXECUTION_MANIFEST_V1` 时，本文件不授权代码修改、迁移、部署、数据删除、数据库重建、Authority Cutover、Live Effect 或 Hot Eviction",
        "",
        "## 阅读与执行说明",
        "",
        "本文件按以下顺序完整包含：",
        "",
        "1. 正式 B+ 数据架构设计规范；",
        "2. 实施总路线图；",
        "3. Phase -1 Execution Foundation；",
        "4. Phase 0 Legacy Compatibility；",
        "5. Phase 1 Journal/CAS/Projection Kernel；",
        "6. Phase 2 Run/Task/Process/Scheduling；",
        "7. Phase 3 Collaboration Protocols；",
        "8. Phase 4 Effect/Observation；",
        "9. Phase 5 Evidence/Archive；",
        "10. Phase 6A Cutover Tooling/Readiness；",
        "11. Phase 6B Authorized Production Cutover；",
        "12. Phase 7 Backend Scale-out。",
        "",
        "来源文件是规范性编辑来源，本文件是生成的唯一展示产物。执行时必须先读取设计规范、路线图、当前授权 Phase 和所有前置 Acceptance Report；不得把整份 Checklist 解释为一次性全量授权。",
        "",
        "## 首次执行入口",
        "",
        "第一次实现会话只能用 `PHASE_MINUS_1_BOOTSTRAP_V0` 执行 Phase -1 Foundation Tasks 1–3；V0 只能引用已存在的输入，不能引用尚未生成的 Foundation Record 或 Manifest V1 哈希。稳定哈希产生后必须人工批准并签发 `EXECUTION_MANIFEST_V1`，此后才能继续 Phase -1。完成并提交 Phase -1 Acceptance Report 后必须停止；Phase 0 需要新的用户授权。",
        "",
        "## 总体阶段依赖",
        "",
        "```text",
        "Phase -1 Execution Foundation",
        "  ↓",
        "Phase 0 Legacy Fence / Inventory",
        "  ↓",
        "Phase 1 Journal / CAS / Projection Kernel",
        "  ↓",
        "Phase 2 Run / Task / Process / Scheduling",
        "  ↓",
        "Phase 3 Collaboration Protocols",
        "  ↓",
        "Phase 4 Effect / Observation",
        "  ↓",
        "Phase 5 Evidence / Archive",
        "  ↓",
        "Phase 6A Cutover Tooling / Readiness (isolated only)",
        "  ↓",
        "Phase 6B Authorized Production Cutover (separate operation)",
        "  ↓",
        "Phase 7 Backend Scale-out",
        "```",
        "",
        "每个 Phase 都需要新的明确实施授权。Phase -1 只建立隔离执行基础；Phase 6A 只证明工具且不得访问 Production；Phase 6B Authority Cutover、Production Freeze、迁移、部署、Live Effect、删除和 Hot Eviction 必须分别确认。",
        "",
        "## 来源完整性清单",
        "",
        "| 顺序 | 来源文件 | 行数 | SHA-256 |",
        "|---:|---|---:|---|",
    ]
    for index, (source, _body, sha, count) in enumerate(loaded, start=1):
        lines.append(f"| {index} | `{source.relative_path}` | {count} | `{sha}` |")
    lines.append("")

    text = "\n".join(lines)
    for source, body, sha, _count in loaded:
        text += (
            "\n\n---\n\n"
            f"# {source.part}\n\n"
            f"> 完整来源：`{source.relative_path}`  \n"
            f"> 来源 SHA-256：`{sha}`\n\n"
            f"{body.rstrip()}"
        )
    return text + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if the generated output is stale")
    args = parser.parse_args()
    expected = render()
    current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else None
    if args.check:
        if current != expected:
            print(f"stale generated plan: {OUTPUT}")
            return 1
        print(f"ok: {OUTPUT}")
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{OUTPUT.name}.", suffix=".tmp", dir=OUTPUT.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(expected)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, OUTPUT)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    print(f"generated: {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
