from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ContractOwnership:
    contract_family: str
    canonical_runtime_owner: str
    responsibility_owner: str
    shared_contract_role: str = "validation-and-interchange-only"


CONTRACT_OWNERSHIP = (
    ContractOwnership("task-graph/task/dependency", "sitina.protocols.tasks.TaskGraphAggregate", "sitina.scheduling.scheduler.Scheduler"),
    ContractOwnership("failure", "sitina.orchestrator.retry.TypedFailure", "sitina.orchestrator.retry.RetryPolicy"),
    ContractOwnership("trace/span", "sitina.contracts.models.TraceContract", "sitina.journal.local.LocalJournal"),
    ContractOwnership("token-budget", "sitina.effects.budgets.BudgetBundle", "sitina.effects.budgets.BudgetBundle"),
    ContractOwnership("token-usage", "sitina.orchestrator.accounting.ProviderAccounting", "sitina.orchestrator.accounting.ProviderAccounting"),
    ContractOwnership("handoff", "sitina.protocols.handoff_contracts.HandoffContract", "sitina.protocols.handoff_contracts.HandoffContract"),
    ContractOwnership("blackboard-document", "sitina.protocols.blackboard.BlackboardDocument", "sitina.protocols.blackboard.Blackboard"),
    ContractOwnership("memory-record", "sitina.memory.native.MemoryDocument", "sitina.memory.native.NativeMemory"),
    ContractOwnership("evaluation-result", "sitina.protocols.proposals.ProposalEvaluation", "sitina.protocols.reviews.ReviewRequest"),
)


CROSS_CUTTING_OWNERS = {
    "concurrency_limits": "sitina.scheduling.scheduler.Scheduler",
    "token_budget_and_accounting": "sitina.effects.budgets.BudgetBundle + sitina.orchestrator.accounting.ProviderAccounting",
    "retry_and_circuit_reliability": "sitina.orchestrator.retry.RetryPolicy",
    "trace_events_and_spans": "sitina.contracts.models.TraceContract + sitina.journal.local.LocalJournal",
    "security_redaction": "sitina.security.redaction",
}
