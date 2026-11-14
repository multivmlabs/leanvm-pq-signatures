"""Constraint and public-statement regression checks for the research FORS guest."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from pqbench.fors import build, generate_record, mutate_fixture, native_verify

RUNNER = ROOT / "target" / "release" / "pq-leanbench"


class NativeForsTests(unittest.TestCase):
    def test_forest_paths_and_message_binding(self):
        record = generate_record(19)
        self.assertTrue(native_verify(record))
        for field in ("seed", "root", "message"):
            with self.subTest(field=field):
                bad = copy.deepcopy(record)
                value = bad[field]
                bad[field] = bytes([value[0] ^ 1]) + value[1:]
                self.assertFalse(native_verify(bad))
        for field in ("secret", "auth"):
            with self.subTest(field=field):
                bad = copy.deepcopy(record)
                opening = bad["signature"][0]
                if field == "secret":
                    value = opening[field]
                    opening[field] = bytes([value[0] ^ 1]) + value[1:]
                else:
                    value = opening[field][0]
                    opening[field][0] = bytes([value[0] ^ 1]) + value[1:]
                self.assertFalse(native_verify(bad))

    def test_parameter_bounds(self):
        for k, a in ((0, 8), (16, 0), (17, 8), (1, 13)):
            with self.subTest(k=k, a=a), self.assertRaises(ValueError):
                build(1, k=k, a=a)


@unittest.skipUnless(RUNNER.is_file(), "run cargo build --release --locked before integration tests")
class ForsIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="pqbench-fors-test-")
        cls.path = Path(cls.directory.name)
        cls.one = build(1)
        cls.three = build(3)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_guest(self, fixture, label, action="execute", proof=None, success=True):
        input_path = self.path / (label + ".json")
        input_path.write_text(json.dumps(fixture))
        command = [str(RUNNER), action, "--input", str(input_path)]
        if proof:
            command.extend(["--proof", str(proof)])
        env = dict(os.environ, LEANVM_NUM_THREADS="4")
        completed = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=60)
        if success:
            self.assertEqual(completed.returncode, 0, completed.stderr)
            return json.loads(completed.stdout)
        self.assertNotEqual(completed.returncode, 0, "an invalid witness/proof was accepted: " + label)
        return None

    def test_valid_single_and_three_record_batches(self):
        one = self.run_guest(self.one, "one")
        three = self.run_guest(self.three, "three")
        self.assertEqual(one["metadata"]["count"], 1)
        self.assertEqual(three["metadata"]["count"], 3)
        self.assertEqual(three["metadata"]["raw_signature_bytes"],
                         3 * three["metadata"]["signature_bytes_per_signature"])
        self.assertEqual(three["metadata"]["raw_key_bytes"],
                         3 * three["metadata"]["public_key_bytes_per_signature"])
        self.assertGreater(three["cycles"], one["cycles"])
        self.assertFalse(one["zero_knowledge"])

    def test_all_negative_witnesses(self):
        for mutation in ("auth", "secret", "message", "public-key", "noncanonical", "statement"):
            with self.subTest(mutation=mutation):
                self.run_guest(mutate_fixture(self.one, mutation), "bad-" + mutation, success=False)

    def test_guest_source_is_independent_of_signature_data(self):
        another = build(1, start=91)
        self.assertEqual(self.one["source"], another["source"])
        self.assertNotEqual(self.one["witness"], another["witness"])
        self.assertNotEqual(self.one["public_input"], another["public_input"])
        first = self.run_guest(self.one, "source-first")
        second = self.run_guest(another, "source-second")
        self.assertEqual(first["guest_hash"], second["guest_hash"])

    def test_witness_free_verification_and_corrupted_proof_or_statement(self):
        proof_path = self.path / "one.proof"
        measured = self.run_guest(self.one, "prove-one", action="prove", proof=proof_path)
        self.assertTrue(measured["verified"])
        statement_path = Path(str(proof_path) + ".statement.json")
        statement = json.loads(statement_path.read_text())
        self.assertFalse(statement.get("witness"))
        checked = self.run_guest(statement, "verify-one", action="verify", proof=proof_path)
        self.assertTrue(checked["verified"])
        self.assertEqual(checked["guest_hash"], measured["guest_hash"])
        self.assertEqual(proof_path.stat().st_size, measured["proof_bytes"])
        self.assertNotIn("log_inv_rate", checked)

        from pqbench.__main__ import dependency
        envelope = dependency(statement_path, proof_path)
        frame = bytes.fromhex(envelope["frame"]["data_hex"])
        self.assertEqual(len(frame), 96)
        self.assertEqual(frame[:32], bytes(31) + b"\x11")
        self.assertEqual(frame[64:].hex(), measured["guest_hash"])
        self.assertFalse(envelope["draft_eip_8288_valid"])
        self.assertTrue(envelope["requires_client_extension"])
        self.assertFalse(envelope["statement_pinned"])

        pinned = dependency(statement_path, proof_path, measured["guest_hash"], measured["public_input_hex"])
        self.assertTrue(pinned["statement_pinned"])
        for guest_hash, public_input in (("00" * 32, measured["public_input_hex"]),
                                         (measured["guest_hash"], "00" * 32)):
            with self.assertRaises(subprocess.CalledProcessError):
                dependency(statement_path, proof_path, guest_hash, public_input)

        extended = self.path / "trailing.proof"
        extended.write_bytes(proof_path.read_bytes() + b"unparsed suffix")
        self.run_guest(statement, "trailing-proof", action="verify", proof=extended, success=False)

        wrong_input = copy.deepcopy(statement)
        wrong_input["public_input"][0][0] ^= 1
        self.run_guest(wrong_input, "wrong-public-input", action="verify", proof=proof_path, success=False)

        corrupted = bytearray(proof_path.read_bytes())
        corrupted[-1] ^= 1
        bad_proof_path = self.path / "corrupted.proof"
        bad_proof_path.write_bytes(corrupted)
        self.run_guest(statement, "corrupted-proof", action="verify", proof=bad_proof_path, success=False)


if __name__ == "__main__":
    unittest.main()
