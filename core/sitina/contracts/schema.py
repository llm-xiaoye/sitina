from __future__ import annotations

from functools import reduce
from operator import or_
from typing import Any

from pydantic import TypeAdapter

from .models import CONTRACT_MODELS
from .ownership import CROSS_CUTTING_OWNERS


SCHEMA_BUNDLE_ID = "https://sitina.local/schemas/shared-contracts-v1.schema.json"


def contract_schema_bundle() -> dict[str, Any]:
    contract_union = reduce(or_, CONTRACT_MODELS.values())
    schema = TypeAdapter(contract_union).json_schema(union_format="any_of")
    schema.update(
        {
            "$id": SCHEMA_BUNDLE_ID,
            "title": "Sitina shared contracts V1",
            "x-sitina-unknown-field-strategy": "reject",
            "x-sitina-legacy-read-policy": "deterministic-v0-to-v1-upcast",
            "x-sitina-new-write-default": "disabled",
            "x-sitina-cross-cutting-owners": CROSS_CUTTING_OWNERS,
        }
    )
    return schema
