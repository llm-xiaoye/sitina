"""Cross-version storage capability, upcaster, and writer-gate primitives."""

from .capabilities import FormatCapabilityRegistry
from .feature_flags import FeatureActivationRegistry
from .leases import CompatibilityLeaseRegistry, RuntimeCompatibilityLease
from .upcasters import UpcasterRegistry

__all__ = [
    "CompatibilityLeaseRegistry",
    "FeatureActivationRegistry",
    "FormatCapabilityRegistry",
    "RuntimeCompatibilityLease",
    "UpcasterRegistry",
]
