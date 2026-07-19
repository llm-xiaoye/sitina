from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from sitina.authority.model import AuthorityControlFacts, AuthorityResolution, AuthorityState
from sitina.authority.resolver import AuthorityResolver
from sitina.journal.model import canonical_json_bytes, domain_hash


class RebuildError(RuntimeError): pass


@dataclass(frozen=True)
class RebuildResult:
    positions: tuple[int,...]
    command_outcomes: Mapping[str,str]
    semantic_checksum: str
    idempotency_preserved: bool
    external_call_count: int = 0
    production_path_access_count: int = 0


class ProjectionRebuilder:
    def rebuild(self,events:tuple[Mapping[str,object],...],*,cas_objects:Mapping[str,bytes])->RebuildResult:
        ordered=tuple(sorted(events,key=lambda event:int(event["position"])))
        positions=tuple(int(event["position"]) for event in ordered)
        if positions!=tuple(range(1,len(positions)+1)): raise RebuildError("Journal rebuild requires a gap-free prefix")
        outcomes:dict[str,str]={}
        material=[]
        for event in ordered:
            for reference in event.get("object_refs",[]):
                if reference not in cas_objects: raise RebuildError(f"required CAS object is missing: {reference}")
            command_id=str(event["command_id"]); outcome=str(event["outcome"])
            if command_id in outcomes and outcomes[command_id]!=outcome: raise RebuildError("same command has conflicting outcomes")
            outcomes[command_id]=outcome
            material.append({"event":dict(event),"object_hashes":{ref:domain_hash("REBUILD_CAS_OBJECT",cas_objects[ref]) for ref in event.get("object_refs",[])}})
        return RebuildResult(positions,outcomes,domain_hash("PROJECTION_REBUILD",canonical_json_bytes(material)),True)


class CutoverRecoverySimulator:
    def __init__(self,command_id:str,request_hash:str,genesis_hash:str,snapshot_hash:str,*,status:str="ABSENT",submitted:bool=False):
        self.command_id=command_id; self.request_hash=request_hash; self.genesis_hash=genesis_hash; self.snapshot_hash=snapshot_hash; self.status=status; self.submitted=submitted
        self.resolver=AuthorityResolver("phase6a-recovery-simulator","authority-resolver-v1",ttl=10)
    def _facts(self,*,same_identity_conflict:bool=False)->AuthorityControlFacts:
        committed=self.status=="COMMITTED"
        return AuthorityControlFacts(True,True,True,False,same_identity_conflict,None,False,True,self.command_id,self.request_hash,self.genesis_hash,self.snapshot_hash,self.status,committed,self.command_id if committed else None,self.request_hash if committed else None,self.genesis_hash if committed else None,self.snapshot_hash if committed else None,"f"*64)
    def submit(self,*,crash_window:str)->AuthorityResolution:
        self.submitted=True
        if crash_window=="AFTER_SUBMISSION_BEFORE_COMMIT": self.status="UNKNOWN"
        elif crash_window=="AFTER_COMMIT_BEFORE_ACK": self.status="COMMITTED"
        elif crash_window=="BEFORE_SUBMISSION": self.status="ABSENT"; self.submitted=False
        else: raise RebuildError("unknown cutover crash window")
        return self.resolver.resolve(self._facts(),now=100)
    def recover(self,command_id:str,request_hash:str)->AuthorityResolution:
        conflict=command_id!=self.command_id or request_hash!=self.request_hash
        return self.resolver.resolve(self._facts(same_identity_conflict=conflict),now=100)
    def restart(self)->"CutoverRecoverySimulator":
        return CutoverRecoverySimulator(self.command_id,self.request_hash,self.genesis_hash,self.snapshot_hash,status=self.status,submitted=self.submitted)
