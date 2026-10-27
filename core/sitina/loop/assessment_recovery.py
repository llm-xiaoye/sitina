"""Typed stops for assessment infrastructure; never an acceptance decision.

User clarification remains the separately authenticated goal-input checkpoint.
A failed assessment does not itself establish that the user owes an answer.
"""
from collections.abc import Mapping

ASSESSMENT_STOP_SCHEMA = "SITINA_ASSESSMENT_STOP_V1"
_PHASES = {"review": "独立评审", "completion": "完成核验"}
_CAUSES = {
    "protocol": ("回复未通过格式或证据校验", "核对保留的拒绝回执及对应字段，修正协议问题后继续核验。"),
    "evidence": ("尚未取得足够的有效证据", "核对具体缺失来源、读取权限和已送达记录，补齐证据后继续核验。"),
    "provider": ("模型服务未返回有效结果", "先按原始错误确认服务状态；恢复后继续原任务，不重放结果未知的工具操作。"),
    "capability": ("尚未完成的要求依赖一项已确认不可用的能力", "先根据保留的执行回执恢复受影响的工具配置，再继续原任务；也可以明确调整要求。不会反复改写说明或把未完成项判为通过。"),
    "output_limit": ("模型输出超过当前接收范围", "核对实际输出限制与保留回执，调整受影响的输出合同后继续；不按原限制反复重试。"),
    "no_progress": ("连续检查没有取得新的有效进展", "检查最后一次失败与仍未完成的要求；条件或证据有实质变化后再继续。"),
    "rework_exhausted": ("自动返工后仍有要求未解决", "核对具体未完成项及已有成果，明确下一步处理后继续；不会自动降低验收标准。"),
}


def assessment_stop_resolution(phase: str, cause: str) -> dict:
    if not isinstance(phase, str) or not isinstance(cause, str) or phase not in _PHASES or cause not in _CAUSES:
        raise ValueError("unknown assessment stop phase or cause")
    summary, action = _CAUSES[cause]
    return {
        "schema": ASSESSMENT_STOP_SCHEMA,
        "phase": phase,
        "cause": cause,
        "status": "STALLED",
        "requires_user_input": False,
        "automatic_retry": False,
        "summary": _PHASES[phase] + "暂时停止：" + summary + "。成果尚未通过完整验收。",
        "next_action": action,
    }


def validate_assessment_stop_resolution(value: Mapping, *, status: str) -> dict:
    if not isinstance(value, Mapping):
        raise ValueError("assessment stop must be a mapping")
    expected = assessment_stop_resolution(value.get("phase"), value.get("cause"))
    if status != "STALLED" or dict(value) != expected or any(
        type(value[key]) is not type(expected[key]) for key in expected
    ):
        raise ValueError("assessment stop does not match its explicit recovery contract")
    return expected
