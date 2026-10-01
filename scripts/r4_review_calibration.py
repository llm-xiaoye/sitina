#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import struct
import subprocess
import zlib
from pathlib import Path
from typing import Any, Iterable, Mapping


SPEC_VERSION = "sitina-loop-v1-r4"
ALLOWED_PACKET_FILES = (
    "requirements.md",
    "packet.md",
    "chart.png",
    "source.csv",
    "plot-data.csv",
    "provenance.json",
    "render_plot.py",
)
REQUIRED_EVIDENCE_FILES = (
    "requirements.md",
    "chart.png",
    "source.csv",
    "plot-data.csv",
    "provenance.json",
)
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
CHART_MAX_BYTES = 16 * 1024 * 1024
CHART_MAX_DIMENSION = 4096
CHART_SEMANTICS_V1_KEYS = frozenset(
    {
        "renderer_contract",
        "title",
        "x_axis",
        "y_axis",
        "plot_data_sha256",
        "width_px",
        "height_px",
        "pixel_payload_sha256",
    }
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _read_semantic_png(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) > CHART_MAX_BYTES or not data.startswith(PNG_SIGNATURE):
        raise ValueError("invalid png envelope")
    offset = len(PNG_SIGNATURE)
    dimensions: tuple[int, int] | None = None
    texts: dict[str, str] = {}
    idat: list[bytes] = []
    saw_iend = False
    while offset < len(data):
        if offset + 12 > len(data):
            raise ValueError("truncated png chunk")
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8]
        chunk_end = offset + 12 + length
        if length > CHART_MAX_BYTES or chunk_end > len(data):
            raise ValueError("invalid png chunk length")
        payload = data[offset + 8 : offset + 8 + length]
        declared_crc = struct.unpack(">I", data[offset + 8 + length : chunk_end])[0]
        if zlib.crc32(chunk_type + payload) & 0xFFFFFFFF != declared_crc:
            raise ValueError("png crc mismatch")
        if chunk_type == b"IHDR":
            if dimensions is not None or len(payload) != 13:
                raise ValueError("invalid png header")
            width, height, bit_depth, color_type, compression, filtering, interlace = struct.unpack(
                ">IIBBBBB", payload
            )
            if (
                not 0 < width <= CHART_MAX_DIMENSION
                or not 0 < height <= CHART_MAX_DIMENSION
                or (bit_depth, color_type, compression, filtering, interlace) != (8, 2, 0, 0, 0)
            ):
                raise ValueError("unsupported png encoding")
            dimensions = (width, height)
        elif chunk_type == b"tEXt":
            if b"\x00" not in payload:
                raise ValueError("invalid png text")
            key_bytes, value_bytes = payload.split(b"\x00", 1)
            key = key_bytes.decode("latin-1")
            if key in texts:
                raise ValueError("duplicate png text key")
            texts[key] = value_bytes.decode("latin-1")
        elif chunk_type == b"IDAT":
            idat.append(payload)
        elif chunk_type == b"IEND":
            if payload or chunk_end != len(data):
                raise ValueError("invalid png end")
            saw_iend = True
        offset = chunk_end
        if saw_iend:
            break
    if dimensions is None or not idat or not saw_iend:
        raise ValueError("incomplete png")
    width, height = dimensions
    pixel_payload = zlib.decompress(b"".join(idat))
    expected_length = height * (1 + width * 3)
    if len(pixel_payload) != expected_length:
        raise ValueError("invalid png pixel payload length")
    for row in range(height):
        if pixel_payload[row * (1 + width * 3)] not in range(5):
            raise ValueError("invalid png row filter")
    return {
        "width_px": width,
        "height_px": height,
        "texts": texts,
        "pixel_payload_sha256": hashlib.sha256(pixel_payload).hexdigest(),
    }


def _chart_semantic_reasons(packet: Path, provenance: Mapping[str, Any]) -> tuple[list[str], bool]:
    contract = provenance.get("chart_semantics_v1")
    if contract is None:
        return [], False
    if not isinstance(contract, Mapping) or set(contract) != CHART_SEMANTICS_V1_KEYS:
        return ["CHART_SEMANTICS_CONTRACT_INVALID"], True
    string_keys = ("renderer_contract", "title", "x_axis", "y_axis")
    if (
        any(not isinstance(contract.get(key), str) or not contract[key] for key in string_keys)
        or contract.get("renderer_contract") != "SITINA_CHART_SEMANTICS_V1"
        or not _is_sha256(contract.get("plot_data_sha256"))
        or not _is_sha256(contract.get("pixel_payload_sha256"))
        or type(contract.get("width_px")) is not int
        or type(contract.get("height_px")) is not int
        or not 0 < contract["width_px"] <= CHART_MAX_DIMENSION
        or not 0 < contract["height_px"] <= CHART_MAX_DIMENSION
    ):
        return ["CHART_SEMANTICS_CONTRACT_INVALID"], True
    try:
        observed = _read_semantic_png(packet / "chart.png")
    except (OSError, UnicodeError, ValueError, zlib.error):
        return ["CHART_INVALID_PNG"], True

    texts = observed["texts"]
    reasons: list[str] = []
    if texts.get("Renderer-Contract") != contract["renderer_contract"]:
        reasons.append("CHART_RENDERER_CONTRACT_MISMATCH")
    if texts.get("Title") != contract["title"]:
        reasons.append("CHART_TITLE_MISMATCH")
    if texts.get("X-Axis") != contract["x_axis"]:
        reasons.append("CHART_X_AXIS_MISMATCH")
    if texts.get("Y-Axis") != contract["y_axis"]:
        reasons.append("CHART_Y_AXIS_MISMATCH")
    if (
        contract["plot_data_sha256"] != sha256_file(packet / "plot-data.csv")
        or texts.get("Plot-Data-SHA256") != contract["plot_data_sha256"]
    ):
        reasons.append("CHART_PLOT_DATA_MISMATCH")
    if (
        observed["width_px"] != contract["width_px"]
        or observed["height_px"] != contract["height_px"]
    ):
        reasons.append("CHART_DIMENSIONS_MISMATCH")
    if observed["pixel_payload_sha256"] != contract["pixel_payload_sha256"]:
        reasons.append("CHART_PIXEL_PAYLOAD_MISMATCH")
    return sorted(set(reasons)), True


def program_check(packet: Path) -> dict[str, Any]:
    missing = [name for name in REQUIRED_EVIDENCE_FILES if not (packet / name).is_file()]
    if "chart.png" in missing:
        return {
            "program_status": "FAIL",
            "reason_codes": ["CHART_MISSING"],
            "missing": missing,
        }
    if missing:
        return {
            "program_status": "NEEDS_EVIDENCE",
            "reason_codes": ["TRACEABILITY_MATERIAL_MISSING"],
            "missing": missing,
        }

    with (packet / "source.csv").open(newline="", encoding="utf-8") as handle:
        source = list(csv.DictReader(handle))
    with (packet / "plot-data.csv").open(newline="", encoding="utf-8") as handle:
        plotted = list(csv.DictReader(handle))
    provenance = json.loads((packet / "provenance.json").read_text(encoding="utf-8"))
    reasons: list[str] = []
    if len(source) != len(plotted):
        reasons.append("DATA_POINT_COUNT_MISMATCH")
    else:
        for source_row, plotted_row in zip(source, plotted, strict=True):
            expected_time = float(source_row["time_s"])
            expected_value = float(source_row["concentration_mg_L"]) / 1000.0
            if (
                float(plotted_row["time_s"]) != expected_time
                or abs(float(plotted_row["concentration_g_L"]) - expected_value) > 1e-12
            ):
                reasons.append("MG_L_TO_G_L_CONVERSION_MISMATCH")
                break
    if provenance.get("source_sha256") != sha256_file(packet / "source.csv"):
        reasons.append("SOURCE_HASH_MISMATCH")
    if provenance.get("plot_data_sha256") != sha256_file(packet / "plot-data.csv"):
        reasons.append("PLOT_DATA_HASH_MISMATCH")
    if provenance.get("transformation") != "concentration_g_L = concentration_mg_L / 1000":
        reasons.append("TRANSFORMATION_DECLARATION_MISMATCH")
    chart_reasons, presentation_attributes_scored = _chart_semantic_reasons(packet, provenance)
    reasons.extend(chart_reasons)
    return {
        "program_status": "FAIL" if reasons else "PASS",
        "reason_codes": sorted(set(reasons)),
        "missing": [],
        "presentation_attributes_scored": presentation_attributes_scored,
    }


def prepare_isolated_packet(source: Path, destination: Path) -> dict[str, Any]:
    destination.mkdir(parents=True, exist_ok=False)
    packet_destination = destination / "packet"
    packet_destination.mkdir()
    reproduction_output = destination / "reproduction-output"
    reproduction_output.mkdir()
    copied: list[str] = []
    for name in ALLOWED_PACKET_FILES:
        candidate = source / name
        if candidate.is_file():
            target = packet_destination / name
            shutil.copy2(candidate, target)
            target.chmod(0o444)
            copied.append(name)
    packet_destination.chmod(0o555)
    return {
        "source_case_id": source.name,
        "workspace": str(destination.resolve()),
        "read_only_packet": str(packet_destination.resolve()),
        "writable_reproduction_output": str(reproduction_output.resolve()),
        "allowlist": list(ALLOWED_PACKET_FILES),
        "copied": copied,
        "excluded": ["generate_fixtures.py", "evaluator-only", "sibling-cases", "top-level-QA"],
    }


def _json_object(text: str) -> Mapping[str, Any] | None:
    try:
        value = json.loads(text)
        return value if isinstance(value, Mapping) else None
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    while start >= 0:
        try:
            value, _end = json.JSONDecoder().raw_decode(text[start:])
        except json.JSONDecodeError:
            start = text.find("{", start + 1)
            continue
        if isinstance(value, Mapping):
            return value
        start = text.find("{", start + 1)
    return None


def _review_verdict(result: Mapping[str, Any] | None) -> tuple[str, Mapping[str, Any] | None]:
    if result is None or result.get("terminal_state") != "SUCCEEDED":
        return "NOT_RUN", None
    parsed = _json_object(str(result.get("response") or ""))
    if parsed is None:
        return "NOT_RUN", None
    verdict = str(parsed.get("verdict") or "").upper()
    if verdict not in {"PASS", "BLOCK", "NEEDS_EVIDENCE"}:
        return "NOT_RUN", parsed
    return verdict, parsed


def _path_values(value: Any, *, key: str = "") -> Iterable[str]:
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            yield from _path_values(child, key=str(child_key))
    elif isinstance(value, list):
        for child in value:
            yield from _path_values(child, key=key)
    elif isinstance(value, str) and ("path" in key.lower() or "target" in key.lower()):
        yield value


def _tool_paths_within_workspace(result: Mapping[str, Any] | None, workspace: Path) -> bool:
    if result is None:
        return False
    root = workspace.resolve()
    for candidate_text in _path_values(result.get("tool_results", [])):
        candidate = Path(candidate_text).expanduser()
        if not candidate.is_absolute():
            continue
        try:
            candidate.resolve(strict=False).relative_to(root)
        except ValueError:
            return False
    return True


def _workspace_snapshot(workspace: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for path in sorted(workspace.rglob("*")):
        relative = path.relative_to(workspace).as_posix()
        if path.is_symlink():
            snapshot[relative] = "symlink:" + os.readlink(path)
        elif path.is_dir():
            snapshot[relative + "/"] = "directory"
        elif path.is_file():
            snapshot[relative] = "sha256:" + sha256_file(path)
        else:
            snapshot[relative] = "other"
    return snapshot


def run_reviewer(
    *,
    repository: Path,
    workspace: Path,
    profile: str,
    reviewer_id: str,
) -> dict[str, Any]:
    packet = workspace / "packet"
    reproduction_output = workspace / "reproduction-output"
    before = _workspace_snapshot(packet)
    prompt = (
        "你是独立验收评审。只允许使用当前 workspace 中的材料，不得访问父目录、相邻案例、"
        "顶层维护脚本或参考答案。只读输入位于 packet/；不得修改其中任何文件。"
        "依据 packet/requirements.md 与 packet/packet.md 审查 packet/chart.png 及包内证据。"
        "不要把 chart.png 作为文本读取或输出任何二进制内容；若现有工具不能安全读图就明确能力边界。"
        "包内若有 render_plot.py，它是合法交付；需要复现时只能把产物写入 reproduction-output/，"
        "复现不是作出结论的必要条件；不得调用 shell、terminal、桌面/computer-use，不得安装依赖，"
        "也不得用复现修改原包。只使用目录枚举与文本读取工具检查包内材料。"
        "最终只输出一个 JSON 对象，格式为："
        '{"verdict":"PASS|BLOCK|NEEDS_EVIDENCE","direct_evidence":["..."],'
        '"blocking_issues":["..."],"missing_materials":["..."]}。'
        "每个数组最多三项，最终 JSON 尽量短于 800 个汉字。"
        "正确但配色不同不能阻断；有图但不能追溯源数据或换算时必须 NEEDS_EVIDENCE。"
    )
    command = [
        str(repository / "bin/sitina"),
        "agent",
        "--profile",
        profile,
        "--workspace",
        str(workspace),
        "--max-tokens",
        "4096",
        "--max-turns",
        "8",
        prompt,
    ]
    environment = dict(os.environ)
    environment["SITINA_HOME"] = str(repository)
    environment["SITINA_PYTHON"] = str(repository / ".venv-r4/bin/python")
    completed = subprocess.run(
        command,
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        timeout=240,
        check=False,
    )
    result = _json_object(completed.stdout)
    verdict, parsed = _review_verdict(result)
    after = _workspace_snapshot(packet)
    unchanged = before == after
    paths_scoped = _tool_paths_within_workspace(result, workspace)
    if not unchanged or not paths_scoped:
        verdict = "BLOCK"
    return {
        "schema": "SITINA_R4_ISOLATED_REVIEW_RESULT_V1",
        "reviewer_id": reviewer_id,
        "spec_version": SPEC_VERSION,
        "verdict": verdict,
        "parsed_response": dict(parsed or {}),
        "terminal_state": result.get("terminal_state") if result else None,
        "terminal_detail": result.get("response") if result and result.get("terminal_state") != "SUCCEEDED" else None,
        "run_id": result.get("run_id") if result else None,
        "tool_call_count": result.get("tool_call_count") if result else None,
        "workspace_unchanged": unchanged,
        "packet_input_unchanged": unchanged,
        "reproduction_output": _workspace_snapshot(reproduction_output),
        "tool_paths_within_workspace": paths_scoped,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "baseline_condition": (
            "review used the pre-r4 formal agent CLI with an explicit max_turns=8 containment bound; this is "
            "an old-path calibration condition and is not an r4 loop completion rule"
        ),
    }


def _compact_review(review: Mapping[str, Any], raw_path: Path) -> dict[str, Any]:
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(json.dumps(dict(review), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    compact = dict(review)
    stdout = str(compact.pop("stdout", ""))
    stderr = str(compact.pop("stderr", ""))
    compact["raw_result"] = str(raw_path.resolve())
    compact["stdout_sha256"] = hashlib.sha256(stdout.encode("utf-8")).hexdigest()
    compact["stderr_sha256"] = hashlib.sha256(stderr.encode("utf-8")).hexdigest()
    return compact


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--profile", default="deepseek")
    parser.add_argument("--skip-live-reviewers", action="store_true")
    parser.add_argument("--retry-not-run", action="store_true")
    args = parser.parse_args()

    report_path = args.output / "calibration-results.json"
    if args.retry_not_run:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        for case in report["cases"]:
            for review in case["reviewers"]:
                if review["verdict"] != "NOT_RUN":
                    continue
                reviewer_id = str(review["reviewer_id"])
                case_id = str(case["case_id"])
                history = list(review.get("prior_attempts", []))
                current = dict(review)
                current.pop("prior_attempts", None)
                current_attempt = len(history) + 1
                if "stdout" in current:
                    prior_path = args.output / "raw-results" / (
                        f"{case_id}-{reviewer_id}-attempt-{current_attempt}.json"
                    )
                    current = _compact_review(current, prior_path)
                history.append(current)
                workspace = args.output / "review-workspaces" / f"{case_id}-{reviewer_id}"
                retried = run_reviewer(
                    repository=args.repository.resolve(),
                    workspace=workspace,
                    profile=args.profile,
                    reviewer_id=reviewer_id,
                )
                retry_path = args.output / "raw-results" / (
                    f"{case_id}-{reviewer_id}-attempt-{current_attempt + 1}.json"
                )
                replacement = _compact_review(retried, retry_path)
                replacement["prior_attempts"] = history
                case["reviewers"][case["reviewers"].index(review)] = replacement
        for case in report["cases"]:
            for index, review in enumerate(case["reviewers"]):
                if "stdout" not in review:
                    continue
                raw_path = args.output / "raw-results" / (
                    f"{case['case_id']}-{review['reviewer_id']}-attempt-1.json"
                )
                case["reviewers"][index] = _compact_review(review, raw_path)
        report["not_run_retry_performed"] = True
        report["not_run_retry_rounds"] = int(report.get("not_run_retry_rounds", 0)) + 1
        report_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 0

    args.output.mkdir(parents=True, exist_ok=False)
    results: list[dict[str, Any]] = []
    for packet in sorted((args.source / "review-packets").glob("case-*")):
        program = program_check(packet)
        reviewers: list[dict[str, Any]] = []
        isolated_manifests: list[dict[str, Any]] = []
        for index in range(1, 3):
            workspace = args.output / "review-workspaces" / f"{packet.name}-reviewer-{index}"
            workspace.parent.mkdir(parents=True, exist_ok=True)
            isolated_manifests.append(prepare_isolated_packet(packet, workspace))
            if not args.skip_live_reviewers:
                review = run_reviewer(
                    repository=args.repository.resolve(),
                    workspace=workspace,
                    profile=args.profile,
                    reviewer_id=f"reviewer-{index}",
                )
                raw_path = args.output / "raw-results" / (
                    f"{packet.name}-reviewer-{index}-attempt-1.json"
                )
                reviewers.append(_compact_review(review, raw_path))
        results.append(
            {
                "case_id": packet.name,
                "program": program,
                "reviewers": reviewers,
                "isolated_workspaces": isolated_manifests,
            }
        )

    report = {
        "schema": "SITINA_R4_REVIEW_CALIBRATION_V1",
        "spec_version": SPEC_VERSION,
        "mode": "benchmark",
        "required_independent_reviewers_per_case": 2,
        "reviewers_received_one_neutral_packet_only": True,
        "evaluator_only_labels_visible_to_reviewers": False,
        "cases": results,
    }
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
