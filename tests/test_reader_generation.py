from __future__ import annotations

import unittest

from sitina.projections.readers import ReaderError, ReaderGeneration, ReaderGenerationRegistry, ReaderKind


class ReaderGenerationTests(unittest.TestCase):
    def test_new_and_legacy_readonly_generations_are_independent(self) -> None:
        registry=ReaderGenerationRegistry()
        registry.register(ReaderGeneration("new-v1",ReaderKind.JOURNAL_PROJECTION,"a"*64,0))
        registry.register(ReaderGeneration("legacy-ro-v1",ReaderKind.LEGACY_READ_ONLY,"b"*64,10))
        view=registry.render("legacy-ro-v1",{"run":"r"},as_of_cutover_frontier="c"*64,current_position=15)
        self.assertEqual(view["reader_kind"],"LEGACY_READ_ONLY"); self.assertEqual(view["staleness_positions"],5)
        self.assertEqual(view["as_of_cutover_frontier"],"c"*64)

    def test_legacy_reader_can_never_supply_authoritative_preconditions(self) -> None:
        generation=ReaderGeneration("legacy-ro-v1",ReaderKind.LEGACY_READ_ONLY,"b"*64,10)
        for purpose in ("EXPECTED_VERSION","APPROVAL","SCHEDULER","EFFECT","CLOSING","TERMINAL"):
            with self.subTest(purpose=purpose), self.assertRaises(ReaderError): generation.authoritative_precondition(purpose,{"x":1})

    def test_generation_identity_conflict_is_rejected(self) -> None:
        registry=ReaderGenerationRegistry(); registry.register(ReaderGeneration("reader-v1",ReaderKind.JOURNAL_PROJECTION,"a"*64,0))
        with self.assertRaises(ReaderError): registry.register(ReaderGeneration("reader-v1",ReaderKind.LEGACY_READ_ONLY,"b"*64,0))


if __name__ == "__main__": unittest.main()

