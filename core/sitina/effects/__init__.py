"""Journal-oriented Effect, Attempt, Observation, and Settlement primitives.

Phase 4 exposes only deterministic mock/shadow capabilities.  The objects in
this package model authority facts; none of them grants a live external
capability by itself.
"""

from .model import (
    EffectRequest,
    EffectState,
    ExecutionCardinality,
    OutcomeState,
    SettlementBasis,
    SettlementState,
)

__all__ = [
    "EffectRequest",
    "EffectState",
    "ExecutionCardinality",
    "OutcomeState",
    "SettlementBasis",
    "SettlementState",
]
