from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal, Protocol, Sequence

from sitina.contracts.models import TokenBudgetContract
from sitina.journal.model import canonical_json_bytes, validate_identifier, validate_timestamp

from .context import TokenEstimator


class ContextManagementError(RuntimeError):
    pass


class ProviderTokenizer(Protocol):
    name: str

    def count(self, text: str) -> int: ...


@dataclass(frozen=True)
class ContextWindowPlan:
    provider_model: str
    counting_mode: Literal["provider-tokenizer", "conservative-fallback"]
    tokenizer_name: str
    provider_context_limit: int
    budget_available_tokens: int
    system_tokens: int
    tool_schema_tokens: int
    history_tokens: int
    output_reserve_tokens: int
    input_tokens: int
    total_reserved_tokens: int


class ContextWindowPlanner:
    """Admission-only planning over the shared TokenBudget contract.

    Provider usage remains the post-call accounting authority. The offline
    counter is explicitly labelled as a conservative fallback and never
    becomes actual usage.
    """

    @staticmethod
    def plan(
        *,
        budget: TokenBudgetContract,
        provider_model: str,
        provider_context_limit: int,
        system_prompt: str,
        tool_schema: str,
        history: str,
        output_reserve_tokens: int,
        tokenizer: ProviderTokenizer | None = None,
    ) -> ContextWindowPlan:
        validate_identifier(provider_model, field="context_provider_model")
        if provider_context_limit < 1 or output_reserve_tokens < 1:
            raise ContextManagementError("context limit and output reserve must be positive")
        available_budget = budget.maximum_tokens - budget.consumed_tokens - budget.reserved_tokens
        available = min(provider_context_limit, available_budget)
        if available < 1:
            raise ContextManagementError("shared token budget has no available capacity")
        counter = tokenizer.count if tokenizer is not None else TokenEstimator.count
        values = tuple(counter(item) for item in (system_prompt, tool_schema, history))
        if any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in values):
            raise ContextManagementError("tokenizer returned an invalid count")
        input_tokens = sum(values)
        total = input_tokens + output_reserve_tokens
        if total > available:
            raise ContextManagementError("context input plus output reserve exceeds the effective hard limit")
        return ContextWindowPlan(
            provider_model,
            "provider-tokenizer" if tokenizer is not None else "conservative-fallback",
            tokenizer.name if tokenizer is not None else "sitina-conservative-offline-v1",
            provider_context_limit,
            available_budget,
            values[0],
            values[1],
            values[2],
            output_reserve_tokens,
            input_tokens,
            total,
        )


ContextCategory = Literal[
    "safety",
    "user_constraint",
    "unfinished_task",
    "evidence",
    "recent_history",
    "memory",
    "tool_output",
]


@dataclass(frozen=True)
class ContextCandidate:
    item_id: str
    category: ContextCategory
    content: str
    source_ref: str
    required: bool = False

    def __post_init__(self) -> None:
        validate_identifier(self.item_id, field="context_item_id")
        validate_identifier(self.source_ref, field="context_source_ref")
        if not self.content.strip():
            raise ContextManagementError("context candidate content is empty")


@dataclass(frozen=True)
class ContextSelection:
    selected: tuple[ContextCandidate, ...]
    omitted_item_ids: tuple[str, ...]
    token_count: int
    selection_hash: str


class DeterministicContextSelector:
    PRIORITY = {
        "safety": 0,
        "user_constraint": 1,
        "unfinished_task": 2,
        "evidence": 3,
        "recent_history": 4,
        "memory": 5,
        "tool_output": 6,
    }

    @classmethod
    def select(
        cls,
        candidates: Sequence[ContextCandidate],
        *,
        token_limit: int,
        tokenizer: ProviderTokenizer | None = None,
    ) -> ContextSelection:
        if token_limit < 1 or len({item.item_id for item in candidates}) != len(candidates):
            raise ContextManagementError("context selection limit or item identity is invalid")
        counter = tokenizer.count if tokenizer is not None else TokenEstimator.count
        always_required = {"safety", "user_constraint", "unfinished_task"}
        ordered = sorted(
            candidates,
            key=lambda item: (
                not (item.required or item.category in always_required),
                cls.PRIORITY[item.category],
                item.item_id,
            ),
        )
        selected: list[ContextCandidate] = []
        omitted: list[str] = []
        used = 0
        for candidate in ordered:
            count = counter(candidate.content)
            must_include = candidate.required or candidate.category in always_required
            if must_include and used + count > token_limit:
                raise ContextManagementError("required context cannot fit the hard token limit")
            if used + count <= token_limit:
                selected.append(candidate)
                used += count
            else:
                omitted.append(candidate.item_id)
        digest = hashlib.sha256(
            canonical_json_bytes(
                {
                    "selected": [item.item_id for item in selected],
                    "omitted": sorted(omitted),
                    "token_count": used,
                    "token_limit": token_limit,
                }
            )
        ).hexdigest()
        return ContextSelection(tuple(selected), tuple(sorted(omitted)), used, digest)


@dataclass(frozen=True)
class StructuredContextSummary:
    decisions: tuple[str, ...]
    constraints: tuple[str, ...]
    unfinished_tasks: tuple[str, ...]
    open_questions: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    source_refs: tuple[str, ...]
    dropped_detail_hashes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        collections = (
            self.decisions,
            self.constraints,
            self.unfinished_tasks,
            self.open_questions,
            self.evidence_refs,
            self.source_refs,
            self.dropped_detail_hashes,
        )
        if any(tuple(sorted(set(values))) != values for values in collections):
            raise ContextManagementError("structured summary collections must be unique and sorted")
        if any(not item.strip() for values in collections for item in values):
            raise ContextManagementError("structured summary values cannot be empty")

    @property
    def essential_facts(self) -> frozenset[str]:
        result = set()
        for name in ("decisions", "constraints", "unfinished_tasks", "open_questions", "evidence_refs", "source_refs"):
            result.update(f"{name}:{item}" for item in getattr(self, name))
        return frozenset(result)

    def render(self) -> str:
        lines = []
        for name in ("decisions", "constraints", "unfinished_tasks", "open_questions", "evidence_refs", "source_refs"):
            lines.append(f"[{name}]")
            lines.extend(f"- {item}" for item in getattr(self, name))
        return "\n".join(lines)


class StructuredSummaryCompressor:
    @staticmethod
    def compress(
        *,
        decisions: Sequence[str],
        constraints: Sequence[str],
        unfinished_tasks: Sequence[str],
        open_questions: Sequence[str],
        evidence_refs: Sequence[str],
        source_refs: Sequence[str],
        expendable_details: Sequence[str],
        token_limit: int,
        tokenizer: ProviderTokenizer | None = None,
    ) -> StructuredContextSummary:
        summary = StructuredContextSummary(
            tuple(sorted(set(decisions))),
            tuple(sorted(set(constraints))),
            tuple(sorted(set(unfinished_tasks))),
            tuple(sorted(set(open_questions))),
            tuple(sorted(set(evidence_refs))),
            tuple(sorted(set(source_refs))),
            tuple(sorted(hashlib.sha256(item.encode()).hexdigest() for item in expendable_details)),
        )
        counter = tokenizer.count if tokenizer is not None else TokenEstimator.count
        if token_limit < 1 or counter(summary.render()) > token_limit:
            raise ContextManagementError("essential structured summary cannot fit without fact loss")
        return summary


@dataclass(frozen=True)
class ContextAllocationRequest:
    component: str
    minimum_tokens: int
    requested_tokens: int
    priority: int

    def __post_init__(self) -> None:
        validate_identifier(self.component, field="context_allocation_component")
        if self.minimum_tokens < 0 or self.requested_tokens < self.minimum_tokens or self.priority < 0:
            raise ContextManagementError("context allocation request is invalid")


@dataclass(frozen=True)
class ContextAllocationPlan:
    allocations: tuple[tuple[str, int], ...]
    ceiling_tokens: int
    allocated_tokens: int
    reclaimed_tokens: int


class ContextBudgetAllocator:
    @staticmethod
    def allocate(
        budget: TokenBudgetContract,
        requests: Sequence[ContextAllocationRequest],
        *,
        reclaimed_tokens: int = 0,
    ) -> ContextAllocationPlan:
        if reclaimed_tokens < 0 or len({item.component for item in requests}) != len(requests):
            raise ContextManagementError("context allocation reclamation or identity is invalid")
        remaining_reserved = max(0, budget.reserved_tokens - reclaimed_tokens)
        available = budget.maximum_tokens - budget.consumed_tokens - remaining_reserved
        minimum = sum(item.minimum_tokens for item in requests)
        if minimum > available:
            raise ContextManagementError("minimum context allocations exceed the run ceiling")
        allocations = {item.component: item.minimum_tokens for item in requests}
        left = available - minimum
        for item in sorted(requests, key=lambda value: (value.priority, value.component)):
            extra = min(left, item.requested_tokens - item.minimum_tokens)
            allocations[item.component] += extra
            left -= extra
        result = tuple(sorted(allocations.items()))
        allocated = sum(value for _name, value in result)
        if allocated > available:
            raise ContextManagementError("context allocation exceeded its derived ceiling")
        return ContextAllocationPlan(result, available, allocated, reclaimed_tokens)


@dataclass(frozen=True)
class ContextHistoryEntry:
    position: int
    context_id: str
    occurred_at: str
    content_ref: str
    content_hash: str
    evidence_refs: tuple[str, ...]
    authorized_principals: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_identifier(self.context_id, field="context_history_id")
        validate_timestamp(self.occurred_at)
        if self.position < 1 or not self.content_ref.startswith("cas:") or len(self.content_hash) != 64:
            raise ContextManagementError("context history entry identity or reference is invalid")
        if tuple(sorted(set(self.evidence_refs))) != self.evidence_refs:
            raise ContextManagementError("context history evidence refs must be unique and sorted")
        if tuple(sorted(set(self.authorized_principals))) != self.authorized_principals:
            raise ContextManagementError("context history ACL must be unique and sorted")
        for principal in self.authorized_principals:
            validate_identifier(principal, field="context_history_principal")


@dataclass(frozen=True)
class ContextHistoryPage:
    entries: tuple[ContextHistoryEntry, ...]
    next_position: int | None
    auto_injected: Literal[False] = False


class AuthorizedContextHistory:
    """Read-only, rebuildable index over authoritative history facts."""

    def __init__(self, entries: Sequence[ContextHistoryEntry]):
        ordered = tuple(sorted(entries, key=lambda item: (item.position, item.context_id)))
        if len({(item.position, item.context_id) for item in ordered}) != len(ordered):
            raise ContextManagementError("context history contains duplicate identities")
        self._entries = ordered

    def query(
        self,
        *,
        actor: str,
        after_position: int = 0,
        limit: int = 50,
        evidence_ref: str | None = None,
    ) -> ContextHistoryPage:
        validate_identifier(actor, field="context_history_actor")
        if after_position < 0 or not 1 <= limit <= 1_000:
            raise ContextManagementError("context history cursor or limit is invalid")
        visible = [
            item
            for item in self._entries
            if item.position > after_position
            and actor in item.authorized_principals
            and (evidence_ref is None or evidence_ref in item.evidence_refs)
        ]
        page = tuple(visible[:limit])
        next_position = page[-1].position if len(visible) > len(page) else None
        return ContextHistoryPage(page, next_position)


__all__ = [
    "AuthorizedContextHistory",
    "ContextAllocationPlan",
    "ContextAllocationRequest",
    "ContextBudgetAllocator",
    "ContextCandidate",
    "ContextHistoryEntry",
    "ContextHistoryPage",
    "ContextManagementError",
    "ContextSelection",
    "ContextWindowPlan",
    "ContextWindowPlanner",
    "DeterministicContextSelector",
    "ProviderTokenizer",
    "StructuredContextSummary",
    "StructuredSummaryCompressor",
]
