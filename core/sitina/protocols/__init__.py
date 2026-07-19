"""Pure, hash-bound protocol state machines used by the B+ shadow runtime."""

from .runtime import ProtocolDefinition, ProtocolInstance, Transition, apply_transition
from .obligations import ObligationAggregate, ObligationState, ProtocolRegistryProjection
from .proposals import ProposalRound
from .claims import ClaimRegistry, KnowledgeClaim
from .debate import Debate
from .reviews import ArtifactAcceptanceProcess, ReviewRequest
from .handoffs import Handoff
from .merge import MergeProtocol
from .arbitration import Arbitration
from .rework import Rework
from .blackboard import Blackboard
from .coordinator import ProtocolCoordinator

__all__ = [
    "ProtocolDefinition", "ProtocolInstance", "Transition", "apply_transition",
    "ObligationAggregate", "ObligationState", "ProtocolRegistryProjection",
    "ProposalRound", "ClaimRegistry", "KnowledgeClaim", "Debate",
    "ReviewRequest", "ArtifactAcceptanceProcess", "Handoff", "MergeProtocol",
    "Arbitration", "Rework", "Blackboard", "ProtocolCoordinator",
]
