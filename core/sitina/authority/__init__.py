"""Fail-closed B+ writer-authority resolution."""

from .model import AuthorityControlFacts, AuthorityResolution, AuthorityState, LegacyAuthorityFact
from .resolver import AuthorityResolver, AuthorityResolverError

__all__ = ["AuthorityControlFacts", "AuthorityResolution", "AuthorityState", "LegacyAuthorityFact", "AuthorityResolver", "AuthorityResolverError"]

