"""Adversarial tests for the full ethDilithium guest and independent reference."""
from __future__ import annotations
import copy
import json
import pathlib
import subprocess
import tempfile
import unittest

from pqbench import dilithium as d


class EthDilithiumTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = d.build(1)
        cls.runner = d.ROOT / "target/release/pq-leanbench"

    def execute(self, fixture, valid):
        if not self.runner.exists():
            self.skipTest("build pq-leanbench release runner to test constraints")
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / "fixture.json"
            p.write_text(json.dumps(fixture))
            r = subprocess.run([str(self.runner), "execute", "--input", str(p)], capture_output=True, text=True)
            self.assertEqual(r.returncode == 0, valid, (r.stdout + r.stderr)[-3000:])

    def test_replay_rebuilds_original_witness(self):
        rebuilt = d.replay({"scheme": self.fixture["scheme"], "metadata": self.fixture["metadata"]})
        for field in ["source", "public_input", "witness"]:
            self.assertEqual(rebuilt[field], self.fixture[field])
        self.assertGreater(rebuilt["metadata"]["native_verify_ns_per_signature"], 0)
        self.assertIsNot(rebuilt["metadata"]["records"], self.fixture["metadata"]["records"])

    def test_replay_rejects_invalid_compact_signature(self):
        saved = copy.deepcopy(self.fixture["metadata"]["records"])
        sig = bytearray.fromhex(saved[0]["compact_signature_hex"])
        sig[0] ^= 1
        saved[0]["compact_signature_hex"] = sig.hex()
        with self.assertRaises(ValueError):
            d.build(1, records=saved)

    def test_valid_signature(self):
        self.execute(self.fixture, True)

    def test_count_positive(self):
        with self.assertRaises(ValueError):
            d.build(0)

    def test_changed_message_even_when_public_commitment_matches(self):
        f = copy.deepcopy(self.fixture)
        message = bytearray.fromhex(f["metadata"]["records"][0]["message_hex"])
        message[0] ^= 1
        f["witness"]["message"][0] = d.cells(bytes(message))
        keyhash = bytes.fromhex(f["metadata"]["records"][0]["expanded_key_hash_hex"])
        f["public_input"] = d.cells(d.kh(d.kh(d.TAG) + keyhash + message))
        self.execute(f, False)

    def test_invalid_modular_witness(self):
        f = copy.deepcopy(self.fixture)
        # These four limbs still encode a canonical q residue; the modular
        # multiplication relation must reject a different residue.
        original = f["witness"]["q"][5120]
        old_lo = d.GP.index(original[0][0])
        old_hi = d.GP.index(original[1][0])
        v = (old_lo + 4096 * old_hi + 1) % d.Q
        complement = d.Q - 1 - v
        f["witness"]["q"][5120] = [d.ec(v & 4095), d.ec(v >> 12), d.ec(complement & 4095), d.ec(complement >> 12)]
        self.execute(f, False)

    def test_changed_challenge_rejection(self):
        f = copy.deepcopy(self.fixture)
        f["witness"]["accept"][0][0][0] ^= 1
        self.execute(f, False)

    def test_changed_hint(self):
        f = copy.deepcopy(self.fixture)
        f["witness"]["hint"][0][0][0] ^= 1
        self.execute(f, False)

    def test_z_out_of_range(self):
        f = copy.deepcopy(self.fixture)
        # First bounded17 call reads a z magnitude. A broken complement
        # cannot be used to certify an out-of-bound coefficient.
        f["witness"]["bounded17"][0][0] = d.ec(255)
        f["witness"]["bounded17"][0][1] = d.ec(511)
        self.execute(f, False)

    def test_nonboolean_multiplication_bit(self):
        f = copy.deepcopy(self.fixture)
        f["witness"]["mul_bits"][0][0] = d.cell(2)
        self.execute(f, False)

    def test_norm_and_rounding_boundaries(self):
        self.assertEqual(d.intt(d.ntt(list(range(256)))), list(range(256)))
        for r in [0, 1, 95231, 95232, 95233, d.Q - 95233, d.Q - 95232, d.Q - 2, d.Q - 1]:
            for hint in [0, 1]:
                w, high, low = d.use_hint(hint, r)
                self.assertTrue(0 <= high < 44)
                self.assertTrue(0 <= w < 44)
                self.assertEqual((high * 190464 + low) % d.Q, r)
                self.assertTrue(-95232 <= low <= 95232)
                if high != 0:
                    self.assertGreater(low, -95232)


if __name__ == "__main__":
    unittest.main()
