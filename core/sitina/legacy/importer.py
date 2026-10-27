from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping
from sitina.install_identity import LEGACY_PRODUCTION_HOME

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class ImportError(RuntimeError):
    pass


@dataclass(frozen=True)
class ImportedRecord:
    canonical_id: str
    source_id: str
    source_hash: str
    classification: str
    payload: Mapping[str, object]
    conflict: bool

    def mapping(self) -> dict[str,object]:
        return {"canonical_id":self.canonical_id,"source_id":self.source_id,"source_hash":self.source_hash,"classification":self.classification,"payload":dict(self.payload),"conflict":self.conflict}


@dataclass(frozen=True)
class MigrationCandidate:
    snapshot_hash: str
    conversion_rule_hash: str
    records: tuple[ImportedRecord,...]
    source_record_count: int
    deduplicated_count: int
    conflict_count: int
    unresolved_legacy_incomplete_count: int
    migration_frontier_hash: str
    candidate_hash: str
    workspace_root_hash: str
    authority: bool = False

    def mapping(self) -> dict[str,object]:
        return {"schema":"MIGRATION_WORKSPACE_CANDIDATE_V1","snapshot_hash":self.snapshot_hash,"conversion_rule_hash":self.conversion_rule_hash,"records":[item.mapping() for item in self.records],"source_record_count":self.source_record_count,"deduplicated_count":self.deduplicated_count,"conflict_count":self.conflict_count,"unresolved_legacy_incomplete_count":self.unresolved_legacy_incomplete_count,"migration_frontier_hash":self.migration_frontier_hash,"workspace_root_hash":self.workspace_root_hash,"authority":False}


class MigrationWorkspace:
    def __init__(self, root: Path):
        self.root=Path(root).resolve(strict=True)
        if not (self.root/".sitina-bplus-migration-workspace-v1").is_file() or self.root==LEGACY_PRODUCTION_HOME:
            raise ImportError("migration requires an isolated marked workspace")

    def import_records(self, records: tuple[Mapping[str,object],...], *, snapshot_hash: str, conversion_rule_hash: str) -> MigrationCandidate:
        seen: dict[str,str]={}; imported: list[ImportedRecord]=[]; dedup=0; conflicts=0
        for index,record in enumerate(records):
            source_id=str(record.get("source_id","")); source_hash=str(record.get("source_hash","")); classification=str(record.get("classification","")); payload=record.get("payload")
            validate_identifier(source_id,field="source_id")
            if not re.fullmatch(r"[0-9a-f]{64}",source_hash) or not isinstance(payload,Mapping): raise ImportError("legacy import record is malformed")
            if classification=="PROJECTION_DERIVED_NATIVE_FACT": raise ImportError("projection output cannot fabricate a native fact")
            canonical_json_bytes(dict(payload))
            if source_id in seen and seen[source_id]==source_hash:
                dedup+=1; continue
            conflict=source_id in seen and seen[source_id]!=source_hash
            conflicts+=int(conflict); seen.setdefault(source_id,source_hash)
            canonical_id=domain_hash("MIGRATED_LEGACY_RECORD",canonical_json_bytes({"source_id":source_id,"source_hash":source_hash,"ordinal":index if conflict else 0}))
            imported.append(ImportedRecord(canonical_id,source_id,source_hash,classification,dict(payload),conflict))
        ordered=tuple(sorted(imported,key=lambda item:(item.source_id,item.source_hash,item.canonical_id)))
        frontier=domain_hash("MIGRATION_FRONTIER",canonical_json_bytes([item.canonical_id for item in ordered]))
        provisional=MigrationCandidate(snapshot_hash,conversion_rule_hash,ordered,len(records),dedup,conflicts,sum(item.classification=="LEGACY_INCOMPLETE" for item in ordered),frontier,"",domain_hash("MIGRATION_WORKSPACE_ROOT",str(self.root).encode()),False)
        return replace(
            provisional,
            candidate_hash=domain_hash("MIGRATION_WORKSPACE_CANDIDATE", canonical_json_bytes(provisional.mapping())),
        )
