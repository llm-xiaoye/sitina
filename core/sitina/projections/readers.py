from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class ReaderError(RuntimeError): pass


class ReaderKind(str,Enum):
    JOURNAL_PROJECTION="JOURNAL_PROJECTION"
    LEGACY_READ_ONLY="LEGACY_READ_ONLY"


@dataclass(frozen=True)
class ReaderGeneration:
    generation_id: str
    kind: ReaderKind
    implementation_hash: str
    source_position: int

    def __post_init__(self)->None:
        validate_identifier(self.generation_id,field="reader generation_id")
        if self.source_position<0: raise ReaderError("reader source position is invalid")

    @property
    def generation_hash(self)->str:
        return domain_hash("READER_GENERATION",canonical_json_bytes({"generation_id":self.generation_id,"kind":self.kind.value,"implementation_hash":self.implementation_hash,"source_position":self.source_position}))

    def authoritative_precondition(self,purpose:str,_value:Mapping[str,object])->Mapping[str,object]:
        if self.kind is ReaderKind.LEGACY_READ_ONLY:
            raise ReaderError(f"Legacy reader cannot supply {purpose} authoritative preconditions")
        return dict(_value)


class ReaderGenerationRegistry:
    def __init__(self)->None: self._items:dict[str,ReaderGeneration]={}
    def register(self,generation:ReaderGeneration)->None:
        current=self._items.get(generation.generation_id)
        if current is not None and current.generation_hash!=generation.generation_hash: raise ReaderError("reader generation identity collision")
        self._items[generation.generation_id]=generation
    def render(self,generation_id:str,payload:Mapping[str,object],*,as_of_cutover_frontier:str,current_position:int)->dict[str,object]:
        if generation_id not in self._items: raise ReaderError("unknown reader generation")
        generation=self._items[generation_id]
        return {"schema":"READER_GENERATION_VIEW_V1","generation_id":generation.generation_id,"generation_hash":generation.generation_hash,"reader_kind":generation.kind.value,"as_of_cutover_frontier":as_of_cutover_frontier,"source_position":generation.source_position,"staleness_positions":max(0,current_position-generation.source_position),"payload":dict(payload),"authority":False}

