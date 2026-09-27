from __future__ import annotations

import unittest

from ico_evidence import EvidenceRecord, merge_evidence, structured_flag_hits


class EvidenceTests(unittest.TestCase):
    def test_structured_json_strings_are_decoded_and_marked(self):
        hits = structured_flag_hits(
            '{"result": "ico{json_fixture}", "nested": ["noise"]}',
            analyzer="json-tool",
            source="tool.log",
        )
        self.assertEqual({item["value"] for item in hits}, {"ico{json_fixture}"})
        self.assertTrue(hits[0]["structured"])
        self.assertEqual(hits[0]["format"], "json")

    def test_malformed_output_is_not_promoted(self):
        self.assertEqual(structured_flag_hits("{broken", analyzer="tool", source="x"), [])

    def test_merge_evidence_is_stable_and_deduplicated(self):
        records = [
            EvidenceRecord("b", "z", "ico{b}"),
            EvidenceRecord("a", "y", "ico{a}"),
            EvidenceRecord("b", "z", "ico{b}"),
        ]
        merged = merge_evidence(records)
        self.assertEqual([record.value for record in merged], ["ico{a}", "ico{b}"])


if __name__ == "__main__":
    unittest.main()
