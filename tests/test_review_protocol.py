from __future__ import annotations

import unittest

from sitina.protocols.reviews import (
    ArtifactAcceptanceProcess,
    ReviewError,
    ReviewRequest,
    ReviewVerdict,
)


class ReviewProtocolTests(unittest.TestCase):
    def request(self, *, high_risk: bool = False) -> ReviewRequest:
        return ReviewRequest.open(
            "review-1", "11" * 32, "author-1", "22" * 32,
            quorum=2, high_risk=high_risk, security_review_required=high_risk,
        )[0]

    def test_reviewer_independence_capability_and_lease_conflict(self) -> None:
        review = self.request()
        with self.assertRaises(ReviewError):
            review.respond("author-1", ("review",), False, ReviewVerdict.ACCEPT, "31" * 32)
        with self.assertRaises(ReviewError):
            review.respond("reviewer-1", ("code",), False, ReviewVerdict.ACCEPT, "31" * 32)
        with self.assertRaises(ReviewError):
            review.respond("reviewer-1", ("review",), True, ReviewVerdict.ACCEPT, "31" * 32)

    def test_high_risk_disposition_requires_security_reviewer(self) -> None:
        review = self.request(high_risk=True)
        review, _ = review.respond("reviewer-1", ("review",), False, ReviewVerdict.ACCEPT, "31" * 32)
        review, _ = review.respond("reviewer-2", ("review",), False, ReviewVerdict.ACCEPT, "32" * 32)
        with self.assertRaises(ReviewError):
            review.dispose()
        review, _ = review.respond("security-1", ("review", "security-review"), False, ReviewVerdict.ACCEPT, "33" * 32)
        disposed, event = review.dispose()
        self.assertEqual(event["disposition"], "ACCEPT")
        self.assertTrue(disposed.terminal)

    def test_review_disposition_does_not_accept_artifact(self) -> None:
        review = self.request()
        review, _ = review.respond("reviewer-1", ("review",), False, ReviewVerdict.ACCEPT, "31" * 32)
        review, _ = review.respond("reviewer-2", ("review",), False, ReviewVerdict.ACCEPT, "32" * 32)
        review, _ = review.dispose()
        self.assertFalse(review.artifact_accepted)
        process = ArtifactAcceptanceProcess.freeze(review, criteria_hash="41" * 32, policy_hash="42" * 32)
        accepted, event = process.accept(review.artifact_hash, approval_artifact_hash=review.artifact_hash)
        self.assertTrue(accepted.accepted)
        self.assertEqual(event["schema"], "ARTIFACT_ACCEPTED_V1")

    def test_old_approval_is_inapplicable_to_new_artifact_hash(self) -> None:
        review = self.request()
        review, _ = review.respond("reviewer-1", ("review",), False, ReviewVerdict.ACCEPT, "31" * 32)
        review, _ = review.respond("reviewer-2", ("review",), False, ReviewVerdict.ACCEPT, "32" * 32)
        review, _ = review.dispose()
        process = ArtifactAcceptanceProcess.freeze(review, criteria_hash="41" * 32, policy_hash="42" * 32)
        with self.assertRaises(ReviewError):
            process.accept("99" * 32, approval_artifact_hash=review.artifact_hash)
        with self.assertRaises(ReviewError):
            process.accept(review.artifact_hash, approval_artifact_hash="98" * 32)


if __name__ == "__main__":
    unittest.main()
