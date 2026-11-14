"""Fresh-process checks of a saved thirty-signature recursive root.

Run after the experiment produces aggregate.proof. These checks never prove and
copy only the root envelope, the intended public claims and trusted guest source.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import os
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "target/release/aggregate-falcon"
EXPERIMENT = ROOT / "artifacts/falcon-30-recursive"
ENVELOPE = EXPERIMENT / "proofs/aggregate.proof"
EXPECTED_LEAF = "4b4502f2a1a4231617baba69b86e1e4470cff3c3815c66eb8fdcb6e2c2db8a2e"


@unittest.skipUnless(RUNNER.is_file() and ENVELOPE.is_file(), "run the thirty-signature recursion experiment first")
class RecursiveEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="pqbench-public-root-test-")
        cls.path = Path(cls.directory.name)
        cls.manifest = json.loads((EXPERIMENT / "public.json").read_text())
        cls.source = (EXPERIMENT / "leaf-program.py").read_text()
        cls.envelope = ENVELOPE.read_bytes()
        # No leaf proof, compact signature, decoded signature or witness is copied.
        (cls.path / "leaf-program.py").write_text(cls.source)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def check(self, label, manifest=None, envelope=None, source=None, expected=True, pin=EXPECTED_LEAF):
        manifest_path = self.path / (label + ".public.json")
        proof_path = self.path / (label + ".root.proof")
        source_path = self.path / (label + ".guest.py")
        manifest_path.write_text(json.dumps(self.manifest if manifest is None else manifest))
        proof_path.write_bytes(self.envelope if envelope is None else envelope)
        source_path.write_text(self.source if source is None else source)
        result = subprocess.run(
            [str(RUNNER), "verify", "--manifest", str(manifest_path), "--leaf-source", str(source_path),
             "--proof", str(proof_path), "--expect-leaf-guest-hash", pin],
            cwd=self.path, env={**os.environ, "LEANVM_NUM_THREADS": "2"},
            capture_output=True, text=True, timeout=120)
        if expected:
            self.assertEqual(result.returncode, 0, result.stderr)
            answer = json.loads(result.stdout)
            self.assertTrue(answer["verified"])
            self.assertEqual(answer["signatures"], 30)
            self.assertEqual(answer["child_proofs"], 6)
            self.assertFalse(answer["verification_uses_child_proofs"])
            self.assertFalse(answer["verification_uses_signatures"])
            return answer
        self.assertNotEqual(result.returncode, 0, "accepted altered recursive root: " + label)
        return result.stderr

    def test_public_root_without_child_proofs_or_signature_witnesses(self):
        minimal = {field: self.manifest[field] for field in ("schema_version", "scheme", "leaf_size")}
        minimal["records"] = [{field: record[field] for field in ("public_key_hex", "message_hex")}
                              for record in self.manifest["records"]]
        self.check("public-only", manifest=minimal)

    def test_pi_metadata_is_not_trusted(self):
        changed = copy.deepcopy(self.manifest)
        for leaf in changed["leaves"]:
            leaf["public_input_hex"] = "00" * 32
        for record in changed["records"]:
            record["claim_hash"] = "ff" * 32
            record["key_hash"] = "00" * 32
        changed["source_sha256"] = "ff" * 32
        self.check("ignored-advisory-digests", manifest=changed)

    def test_claim_changes_reject_after_public_input_recomputation(self):
        message = copy.deepcopy(self.manifest)
        raw = bytes.fromhex(message["records"][0]["message_hex"])
        message["records"][0]["message_hex"] = (bytes([raw[0] ^ 1]) + raw[1:]).hex()
        error = self.check("changed-message", manifest=message, expected=False)
        self.assertIn("proof verification", error)
        key = copy.deepcopy(self.manifest)
        key["records"][0]["public_key_hex"] = key["records"][1]["public_key_hex"]
        self.check("changed-valid-key", manifest=key, expected=False)
        order = copy.deepcopy(self.manifest)
        order["records"][:5] = order["records"][:5][::-1]
        self.check("changed-order", manifest=order, expected=False)

    def test_duplicate_claim_and_shortened_manifest_reject(self):
        duplicate = copy.deepcopy(self.manifest)
        duplicate["records"][1] = duplicate["records"][0]
        error = self.check("duplicate-claim", manifest=duplicate, expected=False)
        self.assertIn("duplicate", error)
        shortened = copy.deepcopy(self.manifest)
        shortened["records"].pop()
        self.check("missing-claim", manifest=shortened, expected=False)

    def test_full_192_bit_deferred_point_is_bound(self):
        altered = bytearray(self.envelope)
        self.assertEqual(struct.unpack_from("<I", altered, 0)[0], 1)
        self.assertEqual(struct.unpack_from("<Q", altered, 36)[0], 5)
        self.assertEqual(struct.unpack_from("<Q", altered, 44)[0], 6)
        self.assertEqual(struct.unpack_from("<Q", altered, 52)[0], 22)
        # First point coordinate starts at byte60; its third limb starts at76.
        altered[76] ^= 1
        error = self.check("deferred-third-limb", envelope=altered, expected=False)
        self.assertIn("proof verification", error)

    def test_expected_program_identity_and_transport(self):
        self.check("wrong-leaf-pin", pin="00" * 32, expected=False)
        different = self.source.replace("GEN ** 34034726", "GEN ** 34034727", 1)
        self.assertNotEqual(different, self.source)
        self.check("changed-leaf-program", source=different, expected=False)
        changed_identity = bytearray(self.envelope)
        changed_identity[4] ^= 1
        self.check("changed-envelope-program", envelope=changed_identity, expected=False)
        self.check("trailing-proof-data", envelope=self.envelope + b"unparsed", expected=False)
        corrupted = bytearray(self.envelope)
        corrupted[-1] ^= 1
        self.check("corrupt-root-proof", envelope=corrupted, expected=False)


if __name__ == "__main__":
    unittest.main()
