from __future__ import annotations

import unittest

from sitina.evidence.assessment import AssessmentStatus, EvidenceVerifier, ReadOnlyCoreView, VerifierIdentity
from sitina.evidence.completeness import CompletenessLevel, CompletenessProofs, SelfContainment, assess_completeness
from tests.test_evidence_package import core


def completeness(**changes: object):
    values = {name: True for name in CompletenessProofs.__dataclass_fields__}
    values.update(changes)
    return assess_completeness(CompletenessLevel.STREAM_CHAIN_VERIFIED, CompletenessProofs(**values), verify=SelfContainment.SELF_CONTAINED, replay=SelfContainment.HYBRID, inspect=SelfContainment.SELF_CONTAINED)


class EvidenceAssessmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = EvidenceVerifier(VerifierIdentity("verifier-1", "sitina-verifier", "1.0", "a" * 64, "SITINA_CANONICAL_JSON_V1"))

    def test_assessment_statuses_are_distinct_and_precedence_is_fail_closed(self) -> None:
        cases = [
            ({"integrity": True}, completeness(), False, False, AssessmentStatus.PASSED),
            ({"integrity": False}, completeness(), False, False, AssessmentStatus.FAILED),
            ({"integrity": True}, completeness(cas_closure=False), False, False, AssessmentStatus.INCOMPLETE),
            ({"integrity": True}, completeness(keys_available=False), False, True, AssessmentStatus.UNVERIFIABLE),
            ({"integrity": True}, completeness(), True, False, AssessmentStatus.CONTRADICTED),
        ]
        for predicates, complete, contradicted, unavailable, expected in cases:
            with self.subTest(expected=expected):
                assessment = self.verifier.verify(ReadOnlyCoreView(core()), completeness=complete, predicates=predicates, contradicted=contradicted, trust_unavailable=unavailable)
                self.assertEqual(assessment.status, expected)

    def test_assessment_binds_exact_core_and_verifier_profile(self) -> None:
        assessment = self.verifier.verify(ReadOnlyCoreView(core()), completeness=completeness(), predicates={"integrity": True})
        self.assertEqual(assessment.core_hash, core().core_hash)
        self.assertEqual(assessment.verifier.policy_hash, "a" * 64)
        self.assertEqual(len(assessment.assessment_hash), 64)

    def test_read_only_verifier_cannot_mutate_core(self) -> None:
        view = ReadOnlyCoreView(core())
        with self.assertRaises(PermissionError): view.write({"x": 1})

    def test_verifier_crash_emits_no_terminal_package_state(self) -> None:
        with self.assertRaises(RuntimeError):
            self.verifier.verify(ReadOnlyCoreView(core()), completeness=completeness(), predicates={"integrity": True}, fault="CRASH_BEFORE_ASSESSMENT")
        self.assertEqual(self.verifier.issued_assessments, ())


if __name__ == "__main__": unittest.main()
