from __future__ import annotations

from dataclasses import dataclass, replace
from enum import IntEnum, Enum


class ActivationError(RuntimeError): pass


class CapabilityLevel(IntEnum):
    MOCK_ONLY=0
    EXTERNAL_READ=1
    REVERSIBLE_MUTATION=2
    HIGH_RISK_OR_IRREVERSIBLE=3


class IntakeKind(str,Enum):
    NEW_TRANSMISSION="NEW_TRANSMISSION"
    RECEIPT="RECEIPT"
    OBSERVATION="OBSERVATION"
    RECONCILIATION="RECONCILIATION"
    CONTAINMENT="CONTAINMENT"


@dataclass(frozen=True)
class ReadinessMilestone:
    level: CapabilityLevel
    report_hash: str


@dataclass(frozen=True)
class ActivationController:
    active_ceiling: CapabilityLevel
    readiness_history: tuple[ReadinessMilestone,...]=()
    phase6a_locked: bool=True
    new_transmission_enabled: bool=True
    stop_reason: str|None=None
    journal_authority_changed: bool=False

    @classmethod
    def phase6a(cls)->"ActivationController": return cls(CapabilityLevel.MOCK_ONLY)
    @classmethod
    def fixture_for_test(cls,level:CapabilityLevel)->"ActivationController": return cls(level,phase6a_locked=False)
    def record_readiness(self,level:CapabilityLevel,report_hash:str)->"ActivationController":
        if level is CapabilityLevel.MOCK_ONLY: raise ActivationError("MOCK_ONLY is active baseline, not an activation milestone")
        return replace(self,readiness_history=(*self.readiness_history,ReadinessMilestone(level,report_hash)))
    def raise_ceiling(self,level:CapabilityLevel,*,authorization_hash:str,phase_flag:str|None=None)->"ActivationController":
        del authorization_hash,phase_flag
        if self.phase6a_locked or level>CapabilityLevel.MOCK_ONLY: raise ActivationError("Phase 6A cannot raise external capability above MOCK_ONLY")
        return replace(self,active_ceiling=level)
    def lower_ceiling(self,level:CapabilityLevel,reason:str)->"ActivationController":
        if level>self.active_ceiling: raise ActivationError("lowering cannot raise the active ceiling")
        return replace(self,active_ceiling=level,stop_reason=reason)
    def disable_new_transmission(self,reason:str)->"ActivationController": return replace(self,new_transmission_enabled=False,stop_reason=reason)
    def accepts(self,kind:IntakeKind)->bool:
        return kind is not IntakeKind.NEW_TRANSMISSION or self.new_transmission_enabled

