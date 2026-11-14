"""FIPS 204 vectors and adversarial checks for the registered-key guest."""
from __future__ import annotations

import copy
import inspect
import json
import pathlib
import subprocess
import tempfile
import unittest

from pqbench import dilithium as eth
from pqbench import mldsa as m


class MLDSA44Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = m.build(1)
        cls.record = cls.fixture["metadata"]["records"][0]
        cls.runner = m.ROOT / "target/release/pq-leanbench"

    def execute(self, fixture, valid):
        if not self.runner.exists():
            self.skipTest("build release pq-leanbench to test guest constraints")
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "fixture.json"
            path.write_text(json.dumps(fixture))
            result = subprocess.run([str(self.runner), "execute", "--input", str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode == 0, valid, (result.stdout + result.stderr)[-1500:])

    def test_fips204_acvp_internal_sigver_vectors(self):
        path = m.ROOT / "vendor/ETHDILITHIUM/pythonref/assets/ML-DSA-sigVer-FIPS204/internalProjection.json"
        data = json.loads(path.read_text())
        self.assertEqual(data["revision"], "FIPS204")
        groups = [g for g in data["testGroups"] if g["parameterSet"] == "ML-DSA-44"]
        self.assertTrue(groups)
        for group in groups:
            pk = bytes.fromhex(group["pk"])
            for test in group["tests"]:
                with self.subTest(tcId=test["tcId"], reason=test["reason"]):
                    message = bytes.fromhex(test["message"])
                    signature = bytes.fromhex(test["signature"])
                    self.assertEqual(m.native_accepts(pk, message, signature, internal=True), test["testPassed"])
                    self.assertEqual(m.verify_python(pk, message, signature, internal=True), test["testPassed"])

    def test_valid_pure_empty_context_guest(self):
        self.execute(self.fixture, True)
        self.assertIn("-DETHDILITHIUM=0", self.fixture["metadata"]["native_build"]["compile_flags"])
        self.assertEqual(self.fixture["metadata"]["sample_in_ball_candidate_cap"], 128)

    def test_replay_exact_and_public_claim_independent_of_signature(self):
        rebuilt = m.replay(self.fixture)
        for key in ["source", "witness", "public_input"]:
            self.assertEqual(rebuilt[key], self.fixture[key])
        public = m.public_claim(self.record)
        self.assertNotIn("compact_signature_hex", public)
        public["expanded_key_hash_hex"] = "ff" * 32
        self.assertEqual(m.expected_public_input([public]), self.fixture["public_input"])
        self.assertEqual(m.source(2).count("COUNT = 2"), 1)
        self.assertNotEqual(m.source(1), eth.source(1))

    def test_exact_count_and_nonempty(self):
        with self.assertRaises(ValueError):
            m.build_records([])
        with self.assertRaises(ValueError):
            m.build(2, [self.record])
        with self.assertRaises(ValueError):
            m.expected_public_input([])
        with self.assertRaises(ValueError):
            m.generate_record(-1)

    def test_compact_signature_native_replay_rejects_mutation(self):
        record = copy.deepcopy(self.record)
        signature = bytearray.fromhex(record["compact_signature_hex"])
        signature[0] ^= 1
        record["compact_signature_hex"] = signature.hex()
        with self.assertRaises(ValueError):
            m.build_records([record])

    def test_changed_message_with_recomputed_public_input(self):
        fixture = copy.deepcopy(self.fixture)
        record = copy.deepcopy(self.record)
        message = bytearray.fromhex(record["message_hex"])
        message[0] ^= 1
        record["message_hex"] = message.hex()
        fixture["witness"]["message"][0] = m.cells(bytes(message))
        fixture["public_input"] = m.expected_public_input([m.public_claim(record)])
        self.execute(fixture, False)

    def test_changed_challenge(self):
        fixture = copy.deepcopy(self.fixture)
        fixture["witness"]["ctilde"][0][0][0] ^= 1
        self.execute(fixture, False)

    def test_changed_sampler_rejection_advice(self):
        fixture = copy.deepcopy(self.fixture)
        fixture["witness"]["accept"][0][0][0] ^= 1
        self.execute(fixture, False)

    def test_changed_hint(self):
        fixture = copy.deepcopy(self.fixture)
        fixture["witness"]["hint"][0][0][0] ^= 1
        self.execute(fixture, False)

    def test_sampler_cannot_exceed_available_output(self):
        fixture = copy.deepcopy(self.fixture)
        fixture["witness"]["used"][0][0] = m.ec(129)
        self.execute(fixture, False)

    def test_changed_modular_arithmetic_advice(self):
        fixture = copy.deepcopy(self.fixture)
        original = fixture["witness"]["q"][5120]
        residue = (eth.GP.index(original[0][0]) + 4096 * eth.GP.index(original[1][0]) + 1) % m.Q
        complement = m.Q - 1 - residue
        fixture["witness"]["q"][5120] = [m.ec(residue & 4095), m.ec(residue >> 12), m.ec(complement & 4095), m.ec(complement >> 12)]
        self.execute(fixture, False)

    def test_cross_variant_native_and_guest_rejection(self):
        message = bytes.fromhex(self.record["message_hex"])
        standard_pk = bytes.fromhex(self.record["compact_public_key_hex"])
        standard_signature = bytes.fromhex(self.record["compact_signature_hex"])
        with self.assertRaises(ValueError):
            eth.native_verify(standard_pk, message, standard_signature)
        eth_pk, eth_signature, _ = eth.native_fixture(message)
        self.assertFalse(m.native_accepts(eth_pk, message, eth_signature))
        self.assertFalse(m.verify_python(eth_pk, message, eth_signature))
        # An adversary can supply well-formed modular arithmetic advice for an
        # ETH signature under the SHAKE relation. Generate exactly that advice
        # by disabling only the fixture generator's two host acceptance checks
        # in this test-local function. Production APIs retain both checks.
        text = inspect.getsource(m._build).replace("def _build(", "def test_only_unchecked_build(", 1)
        text = text.replace("verify_ns = native_verify(pk, message, sig)", "verify_ns = 0.0")
        text = text.replace('assert hashlib.shake_256(mu + wp).digest(32) == sig[:32], "independent Python verification disagrees with upstream C"', "pass  # test-only invalid signature witness")
        self.assertNotIn("assert hashlib.shake_256(mu + wp)", text)
        namespace = dict(vars(m))
        exec(compile(text, "<test-only-cross-variant-advice>", "exec"), namespace)
        record = {"compact_public_key_hex": eth_pk.hex(), "compact_signature_hex": eth_signature.hex(), "message_hex": message.hex()}
        invalid_fixture = namespace["test_only_unchecked_build"](1, [record])
        self.assertEqual(invalid_fixture["public_input"], m.expected_public_input([m.public_claim(record)]))
        self.execute(invalid_fixture, False)

        # The reciprocal control protects the frozen ETH relation as well:
        # give it a standard signature and all correctly recomputed ETH
        # arithmetic advice, then require its final ETH hash check to reject.
        text = inspect.getsource(eth.build).replace("def build(", "def test_only_unchecked_eth_build(", 1)
        text = text.replace("verify_ns = native_verify(pk, message, sig)", "verify_ns = 0.0")
        text = text.replace('assert prng(mu + wp, 32) == sig[:32], "independent Python verification disagrees with upstream C"', "pass  # test-only invalid signature witness")
        self.assertNotIn("assert prng(mu + wp", text)
        namespace = dict(vars(eth))
        exec(compile(text, "<test-only-reciprocal-advice>", "exec"), namespace)
        record = {key: self.record[key] for key in ["compact_public_key_hex", "compact_signature_hex", "message_hex"]}
        invalid_fixture = namespace["test_only_unchecked_eth_build"](1, [record])
        keyhash = bytes.fromhex(invalid_fixture["metadata"]["records"][0]["expanded_key_hash_hex"])
        self.assertEqual(invalid_fixture["public_input"], eth.cells(eth.kh(eth.kh(eth.TAG) + keyhash + message)))
        self.execute(invalid_fixture, False)


if __name__ == "__main__":
    unittest.main()
