"""Fixed-frontier Legacy/Shadow semantic comparison evidence."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Protocol

from sitina.legacy.classify import IncompleteReason
from sitina.legacy.model import canonical_bytes
from sitina.evidence.frontier import SignedFrontierVectorV1
from sitina.journal.model import canonical_json_bytes, domain_hash
from sitina.security.key_provider import InMemoryKeyProvider, KeyPurpose


class ComparisonDisposition(str, Enum):
    MATCH = "MATCH"
    LEGACY_INCOMPLETE = "LEGACY_INCOMPLETE"
    BLOCKING_MISMATCH = "BLOCKING_MISMATCH"


@dataclass(frozen=True)
class ComparisonProfile:
    profile_id: str
    ignored_fields: tuple[str, ...]
    required_business_fields: tuple[str, ...]
    profile_hash: str

    @classmethod
    def v1(cls) -> "ComparisonProfile":
        ignored = ("local_path", "row_id")
        required = (
            "terminal_status", "task_count", "proposal_count", "handoff_count",
            "arbitration_count", "lease_count", "provider_call_count", "checkpoint_hashes",
            "evidence_hashes", "secret_scan_status",
        )
        core = {"profile_id": "LEGACY_DUAL_READ_COMPARISON_V1", "ignored_fields": ignored, "required_business_fields": required}
        return cls(core["profile_id"], ignored, required, "sha256:" + hashlib.sha256(canonical_bytes(core)).hexdigest())

    @classmethod
    def cutover_v1(cls) -> "ComparisonProfile":
        ignored = ("local_path", "row_id", "projection_updated_at")
        required = (
            "terminal_status", "task_count", "protocol_count", "effect_accounting",
            "checkpoint_hashes", "audit_status", "evidence_hashes", "secret_scan_status",
        )
        core = {"profile_id":"CUTOVER_FIXED_FRONTIER_SEMANTIC_V1","ignored_fields":ignored,"required_business_fields":required}
        return cls(core["profile_id"],ignored,required,"sha256:"+hashlib.sha256(canonical_bytes(core)).hexdigest())


@dataclass(frozen=True)
class ComparisonResult:
    schema: str
    run_id: str
    frontier: str
    disposition: ComparisonDisposition
    profile_hash: str
    legacy_semantic_checksum: str
    shadow_semantic_checksum: str
    differences: Mapping[str, Mapping[str, Any]]
    incomplete: tuple[dict[str, Any], ...]
    ignored_fields: list[str]
    authority: bool = False


class SemanticReader(Protocol):
    def read_run(self, run_id: str, frontier: str) -> dict[str, Any]: ...


def _normalize(value: Any, profile: ComparisonProfile) -> Any:
    if isinstance(value, dict):
        return {
            key: _normalize(item, profile)
            for key, item in sorted(value.items())
            if key not in profile.ignored_fields
        }
    if isinstance(value, list):
        normalized = [_normalize(item, profile) for item in value]
        if all(not isinstance(item, (dict, list)) for item in normalized):
            return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True))
        return normalized
    return value


def _checksum(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def compare_run(
    run_id: str,
    legacy_reader: SemanticReader,
    shadow_reader: SemanticReader,
    frontier: str,
    profile: ComparisonProfile,
    *,
    approved_incomplete: Mapping[str, Mapping[str, Any]] | None = None,
) -> ComparisonResult:
    legacy = _normalize(legacy_reader.read_run(run_id, frontier), profile)
    shadow = _normalize(shadow_reader.read_run(run_id, frontier), profile)
    differences: dict[str, dict[str, Any]] = {}
    for key in sorted(set(legacy) | set(shadow)):
        if legacy.get(key) != shadow.get(key):
            differences[key] = {"legacy": legacy.get(key), "shadow": shadow.get(key)}
    approved = dict(approved_incomplete or {})
    incomplete: list[dict[str, Any]] = []
    for field, definition in approved.items():
        if field not in differences:
            continue
        reason_text = definition.get("reason")
        refs = definition.get("source_refs")
        try:
            reason = IncompleteReason(str(reason_text))
        except ValueError as error:
            raise ValueError(f"unapproved Legacy incomplete reason for {field}: {reason_text}") from error
        if not isinstance(refs, list) or not refs or not all(isinstance(item, str) and item for item in refs):
            raise ValueError(f"Legacy incomplete classification for {field} requires source_refs")
        incomplete.append({"field": field, "reason": reason.value, "source_refs": list(refs), "difference": differences[field]})
    approved_fields = {item["field"] for item in incomplete}
    blocking_fields = set(differences) - approved_fields
    if not differences:
        disposition = ComparisonDisposition.MATCH
    elif blocking_fields:
        disposition = ComparisonDisposition.BLOCKING_MISMATCH
    else:
        disposition = ComparisonDisposition.LEGACY_INCOMPLETE
    return ComparisonResult(
        schema="LEGACY_DUAL_READ_COMPARISON_RESULT_V1",
        run_id=run_id,
        frontier=frontier,
        disposition=disposition,
        profile_hash=profile.profile_hash,
        legacy_semantic_checksum=_checksum(legacy),
        shadow_semantic_checksum=_checksum(shadow),
        differences=differences,
        incomplete=tuple(incomplete),
        ignored_fields=list(profile.ignored_fields),
        authority=False,
    )


def write_comparison_reports(result: ComparisonResult, output_dir: Path) -> dict[str, Path]:
    output = Path(output_dir).resolve(strict=False)
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / f"{result.run_id}-comparison.json"
    markdown_path = output / f"{result.run_id}-comparison.md"
    payload = asdict(result)
    payload["disposition"] = result.disposition.value
    with json_path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    markdown = (
        f"# Legacy dual-read comparison: {result.run_id}\n\n"
        f"Disposition: `{result.disposition.value}`\n\n"
        f"Frontier: `{result.frontier}`\n\n"
        "Evidence only: this report is not writer Authority and cannot authorize Cutover.\n"
    )
    with markdown_path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(markdown)
        handle.flush()
        os.fsync(handle.fileno())
    return {"json": json_path, "markdown": markdown_path}


class FixedFrontierComparisonError(RuntimeError): pass


@dataclass(frozen=True)
class FixedFrontierComparisonReport:
    result: ComparisonResult
    signed_frontier_hash: str
    legacy_reader_generation: str
    journal_reader_generation: str
    catalog_snapshot_hash: str
    comparison_binary_hash: str
    key_id: str
    signature_hex: str
    report_hash: str

    def unsigned_mapping(self)->dict[str,Any]:
        result=asdict(self.result); result["disposition"]=self.result.disposition.value
        return {"schema":"CUTOVER_FIXED_FRONTIER_COMPARISON_REPORT_V1","result":result,"signed_frontier_hash":self.signed_frontier_hash,"legacy_reader_generation":self.legacy_reader_generation,"journal_reader_generation":self.journal_reader_generation,"catalog_snapshot_hash":self.catalog_snapshot_hash,"comparison_binary_hash":self.comparison_binary_hash}
    def mapping(self)->dict[str,Any]: return {**self.unsigned_mapping(),"key_id":self.key_id,"signature_hex":self.signature_hex}
    def verify(self,provider:InMemoryKeyProvider)->bool:
        return provider.verify(self.key_id,KeyPurpose.AUTHORITY_SIGNING,b"SITINA-CUTOVER-COMPARISON-V1\0"+canonical_json_bytes(self.unsigned_mapping()),bytes.fromhex(self.signature_hex)) and self.report_hash==domain_hash("CUTOVER_COMPARISON_REPORT",canonical_json_bytes(self.mapping()))
    def validate_current(self,*,signed_frontier_hash:str,profile_hash:str,catalog_snapshot_hash:str)->None:
        if signed_frontier_hash!=self.signed_frontier_hash or profile_hash!=self.result.profile_hash or catalog_snapshot_hash!=self.catalog_snapshot_hash:
            raise FixedFrontierComparisonError("comparison frontier, profile, or catalog snapshot drifted")


class _FrozenReader:
    def __init__(self,value:Mapping[str,Any]): self.value=dict(value)
    def read_run(self,_run_id:str,_frontier:str)->dict[str,Any]: return dict(self.value)


def compare_cutover_fixed_frontier(
    run_id:str,legacy_reader:SemanticReader,journal_reader:SemanticReader,*,signed_frontier:SignedFrontierVectorV1,
    profile:ComparisonProfile,legacy_reader_generation:str,journal_reader_generation:str,catalog_snapshot_hash:str,
    comparison_binary_hash:str,provider:InMemoryKeyProvider,approved_incomplete:Mapping[str,Mapping[str,Any]]|None=None,
)->FixedFrontierComparisonReport:
    frontier_hash=signed_frontier.frontier_hash
    legacy=legacy_reader.read_run(run_id,frontier_hash); journal=journal_reader.read_run(run_id,frontier_hash)
    missing=(set(profile.required_business_fields)-set(legacy)) | (set(profile.required_business_fields)-set(journal))
    if missing: raise FixedFrontierComparisonError(f"comparison required fields are missing: {sorted(missing)}")
    result=compare_run(run_id,_FrozenReader(legacy),_FrozenReader(journal),frontier_hash,profile,approved_incomplete=approved_incomplete)
    unsigned={"schema":"CUTOVER_FIXED_FRONTIER_COMPARISON_REPORT_V1","result":{**asdict(result),"disposition":result.disposition.value},"signed_frontier_hash":frontier_hash,"legacy_reader_generation":legacy_reader_generation,"journal_reader_generation":journal_reader_generation,"catalog_snapshot_hash":catalog_snapshot_hash,"comparison_binary_hash":comparison_binary_hash}
    key_id,signature=provider.sign(KeyPurpose.AUTHORITY_SIGNING,b"SITINA-CUTOVER-COMPARISON-V1\0"+canonical_json_bytes(unsigned))
    provisional=FixedFrontierComparisonReport(result,frontier_hash,legacy_reader_generation,journal_reader_generation,catalog_snapshot_hash,comparison_binary_hash,key_id,signature.hex(),"")
    return replace(provisional, report_hash=domain_hash("CUTOVER_COMPARISON_REPORT", canonical_json_bytes(provisional.mapping())))
