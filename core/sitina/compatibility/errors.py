from __future__ import annotations


class CompatibilityError(RuntimeError):
    pass


class FeatureGateError(CompatibilityError):
    pass


class StaleFencingToken(FeatureGateError):
    pass
