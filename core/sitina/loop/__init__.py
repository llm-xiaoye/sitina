"""sitina-loop-v1-r4 task-level persistence and coordination skeleton."""

from .coordinator import ExtensionPreparationContext, LoopBackend
from .admission import SubmissionIntent, build_submission_intent, submission_fingerprint
from .host import LoopHost
from .child_model import ReadonlyChildModelRunner
from .recovery import RecoveryCoordinator
from .model import (
    SPEC_VERSION,
    AcceptanceSubmission,
    CompletionProposal,
    ControlIntent,
    EffectStatus,
    InputKind,
    OperationMode,
    TaskProjection,
    TaskStatus,
)
from .operations import FilePrecondition, OperationIntent, OperationOutcome, RecoveryPolicy
from .storage import LoopRuntimeContext
from .termination import TERMINATION_CONTRACT_VERSION
from .delegation import (
    CHILD_RUNTIME_SCHEMA,
    CHILD_RUNTIME_RESULT_SCHEMA,
    DELEGATION_CONTRACT_VERSION,
    ChildDelegationProjection,
    ReadonlyChildCapability,
    ReadonlyChildExecutor,
)

__all__ = [
    "SPEC_VERSION",
    "TERMINATION_CONTRACT_VERSION",
    "AcceptanceSubmission",
    "CompletionProposal",
    "ControlIntent",
    "EffectStatus",
    "FilePrecondition",
    "InputKind",
    "LoopBackend",
    "ExtensionPreparationContext",
    "LoopHost",
    "ReadonlyChildModelRunner",
    "RecoveryCoordinator",
    "LoopRuntimeContext",
    "OperationIntent",
    "OperationMode",
    "OperationOutcome",
    "RecoveryPolicy",
    "TaskProjection",
    "TaskStatus",
    "SubmissionIntent",
    "build_submission_intent",
    "submission_fingerprint",
    "CHILD_RUNTIME_SCHEMA",
    "CHILD_RUNTIME_RESULT_SCHEMA",
    "DELEGATION_CONTRACT_VERSION",
    "ChildDelegationProjection",
    "ReadonlyChildCapability",
    "ReadonlyChildExecutor",
]
