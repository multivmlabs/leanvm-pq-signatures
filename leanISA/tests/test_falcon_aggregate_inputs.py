"""Native-input and claim-binding checks for the thirty-signature experiment."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from pqbench import falcon_aggregate_inputs as inputs


class FalconAggregateInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = [inputs.generate_record(index) for index in range(10)]

    def test_distinct_real_inputs_are_reproducible(self):
        self.assertEqual(self.records[0], inputs.generate_record(0))
        self.assertEqual(len({record["public_key_hex"] for record in self.records}), 10)
        self.assertEqual(len({record["message_hex"] for record in self.records}), 10)
        for record in self.records:
            self.assertEqual(len(bytes.fromhex(record["message_hex"])), 32)
            inputs.decoded_record(record)

    def test_same_source_independent_witness_and_claim(self):
        first = inputs.build_leaf(self.records[:5])
        second = inputs.build_leaf(self.records[5:])
        self.assertEqual(first["source"], second["source"])
        self.assertNotEqual(first["public_input"], second["public_input"])
        self.assertNotEqual(first["witness"], second["witness"])
        self.assertEqual(first["public_input"], inputs.f.halves(inputs.expected_leaf_digest(self.records[:5])))

    def test_native_message_mutation_and_recomputed_claim(self):
        record = copy.deepcopy(self.records[0])
        message = bytes.fromhex(record["message_hex"])
        record["message_hex"] = (bytes([message[0] ^ 1]) + message[1:]).hex()
        self.assertNotEqual(inputs.claim_record(record)["claim_hash"], inputs.claim_record(self.records[0])["claim_hash"])
        with self.assertRaises(ValueError):
            inputs.decoded_record(record)

    def test_order_is_bound(self):
        group = self.records[:5]
        self.assertNotEqual(inputs.expected_leaf_digest(group), inputs.expected_leaf_digest(group[::-1]))


if __name__ == "__main__":
    unittest.main()
