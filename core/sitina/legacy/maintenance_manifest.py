from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash

from .cutover_contracts import CutoverCommandIdentity, CutoverContracts, READINESS_PREDICATE_IDS


class MaintenanceManifestError(RuntimeError): pass


def _fixture_path(path:str)->bool:
    return path.startswith("/fixture/") and ".." not in path.split("/")


@dataclass(frozen=True)
class MaintenanceManifestCandidate:
    predicates: Mapping[str,bool]
    command: CutoverCommandIdentity
    intended_snapshot_hash: str
    genesis_hash: str
    operators: tuple[str,...]
    allowed_paths: tuple[str,...]
    window: tuple[int,int]
    expires_at: int
    expected_pre_state: str
    stop_conditions: tuple[str,...]
    manifest_hash: str
    authority: bool = False
    execute_capability_present: bool = False

    def mapping(self)->dict[str,object]:
        return {"schema":"PHASE6B_MAINTENANCE_MANIFEST_CANDIDATE_V1","predicates":dict(sorted(self.predicates.items())),"command":{"command_id":self.command.command_id,"request_hash":self.command.request_hash},"intended_snapshot_hash":self.intended_snapshot_hash,"genesis_hash":self.genesis_hash,"operators":list(self.operators),"allowed_paths":list(self.allowed_paths),"window":list(self.window),"expires_at":self.expires_at,"expected_pre_state":self.expected_pre_state,"stop_conditions":list(self.stop_conditions),"authority":False,"execute_capability_present":False}


class MaintenanceManifestBuilder:
    def build_candidate(self,*,predicates:Mapping[str,bool],command:CutoverCommandIdentity,intended_snapshot_hash:str,genesis_hash:str,operators:tuple[str,...],allowed_paths:tuple[str,...],window:tuple[int,int],expires_at:int,expected_pre_state:str,stop_conditions:tuple[str,...])->MaintenanceManifestCandidate:
        if set(predicates)!=set(READINESS_PREDICATE_IDS) or not all(predicates.values()): raise MaintenanceManifestError("all frozen readiness predicates must pass")
        unique_operators=tuple(sorted(set(operators)))
        if len(unique_operators)<2: raise MaintenanceManifestError("maintenance candidate requires an independent operator quorum")
        if not allowed_paths or not all(_fixture_path(path) for path in allowed_paths): raise MaintenanceManifestError("Phase 6A candidate paths must be synthetic fixture paths")
        if window[0]>=window[1] or expires_at>window[1] or expires_at<=window[0]: raise MaintenanceManifestError("maintenance window or expiry is invalid")
        if not stop_conditions: raise MaintenanceManifestError("maintenance stop conditions are required")
        provisional=MaintenanceManifestCandidate(dict(predicates),command,intended_snapshot_hash,genesis_hash,unique_operators,tuple(allowed_paths),window,expires_at,expected_pre_state,tuple(stop_conditions),"")
        from dataclasses import replace
        return replace(provisional,manifest_hash=domain_hash("MAINTENANCE_MANIFEST_CANDIDATE",canonical_json_bytes(provisional.mapping())))


class CutoverDryRun:
    CHECKLIST=("authority_prestate","admission_and_dispatch_stop","effect_exposure_drain","monitoring_transfer","legacy_writer_fence_coverage","coherent_snapshot","canonical_backup","disk_and_capacity","key_and_trust_profiles","restore_drill","migration_closure","dual_read","rebuild","reader_rollback","operator_quorum","stop_conditions")
    def evaluate(self,candidate:MaintenanceManifestCandidate)->dict[str,object]:
        return {"schema":"PHASE6A_CUTOVER_DRY_RUN_V1","candidate_manifest_hash":candidate.manifest_hash,"checklist":{name:"READY_FOR_PHASE6B_REVIEW" for name in self.CHECKLIST},"stable_command_id":candidate.command.command_id,"stable_request_hash":candidate.command.request_hash,"eligible_for_phase6b_review":True,"authority":False,"executed":False,"execute_capability_present":False,"production_path_access_count":0}

