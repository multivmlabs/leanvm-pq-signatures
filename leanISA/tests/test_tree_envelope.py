"""Independent public-plan derivation and adversarial tree-receipt controls.

No proofs are generated here. Point TREE_TEST_MANIFEST / TREE_TEST_PROOF at a
completed real run to exercise opaque root proofs and inherited obligations.
Public-only tests run whenever the release binaries and saved records exist.
"""
from __future__ import annotations

import copy
import json
import os
import pathlib
import re
import struct
import subprocess
import tempfile
import unittest

from pqbench import article_inputs as a
from pqbench import dilithium as d

ROOT = a.ROOT
TREE = ROOT / "target/release/aggregate-tree"
LEAF = ROOT / "target/release/pq-leanbench"


def independent_plan_hash(manifest):
    """Serialize the semantic contract, independently of the Rust report."""
    programs = {program["id"]: program for program in manifest["programs"]}
    semantic = {"format": "pqbench/tree-v1/all-edges/level-chunks", "schema_version": 1,
                "scheme": manifest["scheme"], "signatures": manifest["signatures"],
                "leaf_capacity": manifest["leaf_capacity"], "fan_in": manifest["fan_in"],
                "leaves": [{"signatures": leaf["signatures"],
                            "guest_hash": programs[leaf["program_id"]]["expected_guest_hash"].lower(),
                            "public_input_hex": leaf["public_input_hex"].lower(),
                            "min_log_committed": programs[leaf["program_id"]].get("min_log_committed", 22)}
                           for leaf in manifest["leaves"]]}
    return d.kh(b"pqbench/tree-plan/v1\0" + json.dumps(semantic, separators=(",", ":"), ensure_ascii=False).encode()).hex()


def unpack_envelope(encoded):
    """Decode only the documented fixed-width envelope; keep Proof opaque."""
    view = memoryview(encoded)
    position = 0

    def take(length):
        nonlocal position
        if position + length > len(view):
            raise ValueError("truncated envelope")
        value = bytes(view[position:position + length])
        position += length
        return value

    def length():
        value = struct.unpack("<Q", take(8))[0]
        if value > 4096:
            raise ValueError("unexpected vector dimension in test artifact")
        return value

    version = struct.unpack("<I", take(4))[0]
    plan_hash, guest_hash = take(32), take(32)
    points = [[[list(struct.unpack("<QQQ", take(24))) for _ in range(length())]
               for _ in range(length())] for _ in range(length())]
    return {"version": version, "plan_hash": plan_hash, "guest_hash": guest_hash,
            "points": points, "proof": bytes(view[position:])}


def pack_envelope(envelope):
    encoded = bytearray(struct.pack("<I", envelope["version"]))
    encoded += envelope["plan_hash"] + envelope["guest_hash"]
    encoded += struct.pack("<Q", len(envelope["points"]))
    for merge in envelope["points"]:
        encoded += struct.pack("<Q", len(merge))
        for point in merge:
            encoded += struct.pack("<Q", len(point))
            for value in point:
                encoded += struct.pack("<QQQ", *value)
    return bytes(encoded) + envelope["proof"]


class TreePublicPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TREE.exists() or not LEAF.exists():
            raise unittest.SkipTest("build aggregate-tree and pq-leanbench release binaries")
        record_path = a.ARTIFACTS / "fors/records.json"
        if not record_path.exists():
            raise unittest.SkipTest("generate the article's public FORS records")
        records = json.loads(record_path.read_text())
        if len(records) < 11:
            raise unittest.SkipTest("at least11 saved public records required")
        cls.public = [a.public_record("fors", record) for record in records[:11]]
        cls.directory = tempfile.TemporaryDirectory()
        cls.base = pathlib.Path(cls.directory.name)
        cls.manifest = a.make_manifest("fors", 11, 4, 5, directory=cls.base, public_only=cls.public)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def inspect(self, manifest, valid=True):
        path = self.base / "test-manifest.json"
        a.write(path, manifest)
        result = subprocess.run([str(TREE), "inspect", "--manifest", str(path)], text=True, capture_output=True)
        self.assertEqual(result.returncode == 0, valid, (result.stdout + result.stderr)[-2000:])
        return json.loads(result.stdout) if valid else result

    def test_canonical_plan_hash_and_exact_tail(self):
        report = self.inspect(self.manifest)
        self.assertEqual(independent_plan_hash(self.manifest), report["plan_hash"])
        self.assertEqual([leaf["signatures"] for leaf in self.manifest["leaves"]], [5, 5, 1])
        self.assertEqual(report["signatures"], 11)
        self.assertEqual(report["leaf_count"], 3)
        self.assertEqual(len(self.manifest["programs"]), 2)
        self.assertEqual(report["edge_count"], 3)
        self.assertTrue(all(not pathlib.Path(leaf["input_file"]).exists() for leaf in self.manifest["leaves"]))

    def test_public_messages_keys_order_and_tail_change_plan(self):
        expected = self.inspect(self.manifest)["plan_hash"]
        for kind in ["message", "key", "order", "tail"]:
            public = copy.deepcopy(self.public)
            if kind == "order":
                public[0], public[1] = public[1], public[0]
            else:
                index = -1 if kind == "tail" else 0
                field = "public_key_hex" if kind == "key" else "message_hex"
                value = bytearray.fromhex(public[index][field])
                value[0] ^= 1
                public[index][field] = value.hex()
            with self.subTest(kind=kind):
                changed = a.make_manifest("fors", 11, 4, 5, directory=self.base, public_only=public)
                self.assertNotEqual(self.inspect(changed)["plan_hash"], expected)

    def test_public_frontend_ignores_saved_programs_and_pi(self):
        public = copy.deepcopy(self.public)
        public[0]["expanded_key_hash_hex"] = "ff" * 32
        public[0]["public_input_hex"] = "ff" * 32
        public[0]["source"] = "malicious source"
        rebuilt = a.make_manifest("fors", 11, 4, 5, directory=self.base, public_only=public)
        self.assertEqual(self.inspect(rebuilt)["plan_hash"], self.inspect(self.manifest)["plan_hash"])

    def test_duplicate_missing_and_partial_claims_rejected(self):
        duplicate = copy.deepcopy(self.public)
        duplicate[-1] = duplicate[0]
        with self.assertRaises(ValueError):
            a.make_manifest("fors", 11, 4, 5, directory=self.base, public_only=duplicate)
        with self.assertRaises(ValueError):
            a.make_manifest("fors", 11, 4, 5, directory=self.base, public_only=self.public[:-1])
        for counts in [[4, 5, 2], [5, 5, 0], [5, 5, 2]]:
            manifest = copy.deepcopy(self.manifest)
            for leaf, count in zip(manifest["leaves"], counts):
                leaf["signatures"] = count
            with self.subTest(counts=counts):
                self.inspect(manifest, False)

    def test_missing_manifest_fields_rejected(self):
        for field in ["scheme", "signatures", "fan_in", "programs", "leaves"]:
            manifest = copy.deepcopy(self.manifest)
            del manifest[field]
            with self.subTest(field=field):
                self.inspect(manifest, False)

    def test_same_size_substitute_program_rejected_by_source_pin(self):
        manifest = copy.deepcopy(self.manifest)
        specification = manifest["programs"][0]
        original = pathlib.Path(specification["source_file"]).read_text()
        match = re.search(r"^DS_LEAF = ([0-9]+)$", original, flags=re.MULTILINE)
        self.assertIsNotNone(match)
        malicious = original[:match.start(1)] + str(int(match.group(1)) ^ 1) + original[match.end(1):]
        path = self.base / "substituted.py"
        path.write_text(malicious)
        specification["source_file"] = str(path)
        source_input = self.base / "substituted.input.json"
        a.write(source_input, {"scheme": "fors", "source": malicious, "public_input": [[0, 0, 0], [0, 0, 0]]})
        check = subprocess.run([str(LEAF), "inspect", "--input", str(source_input)], text=True, capture_output=True, check=True)
        changed = json.loads(check.stdout)
        original_report = self.inspect(self.manifest)
        row = next(row for row in original_report["source_table"] if row["guest_hash"] == specification["expected_guest_hash"])
        self.assertEqual(changed["bytecode_instructions"], row["bytecode_instructions"])
        self.assertNotEqual(changed["guest_hash"], specification["expected_guest_hash"])
        self.inspect(manifest, False)
        specification["expected_guest_hash"] = changed["guest_hash"]
        self.assertNotEqual(self.inspect(manifest)["plan_hash"], original_report["plan_hash"])


class RealTreeEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        manifest_path = os.environ.get("TREE_TEST_MANIFEST")
        proof_path = os.environ.get("TREE_TEST_PROOF")
        if not TREE.exists() or not manifest_path or not proof_path:
            raise unittest.SkipTest("set TREE_TEST_MANIFEST and TREE_TEST_PROOF to a completed tree run")
        cls.manifest_path = pathlib.Path(manifest_path).resolve()
        cls.manifest = json.loads(cls.manifest_path.read_text())
        # Make copied manifests independent of their temporary location.
        for specification in cls.manifest["programs"]:
            specification["source_file"] = str((cls.manifest_path.parent / specification["source_file"]).resolve())
        for leaf in cls.manifest["leaves"]:
            leaf["input_file"] = str((cls.manifest_path.parent / leaf["input_file"]).resolve())
        cls.encoded = pathlib.Path(proof_path).read_bytes()
        cls.envelope = unpack_envelope(cls.encoded)
        cls.plan_hash = independent_plan_hash(cls.manifest)
        cls.directory = tempfile.TemporaryDirectory()
        cls.base = pathlib.Path(cls.directory.name)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def verify(self, encoded, valid, manifest=None, plan_hash=None):
        manifest = self.manifest if manifest is None else manifest
        path, proof = self.base / "manifest.json", self.base / "envelope.proof"
        a.write(path, manifest)
        proof.write_bytes(encoded)
        result = subprocess.run([str(TREE), "verify", "--manifest", str(path), "--proof", str(proof),
                                 "--expect-plan-hash", plan_hash or independent_plan_hash(manifest)], text=True, capture_output=True)
        self.assertEqual(result.returncode == 0, valid, (result.stdout + result.stderr)[-2000:])
        return json.loads(result.stdout) if valid else result

    def test_positive_without_leaf_proofs_or_signature_fixtures(self):
        public = self.manifest.get("records")
        if not public:
            self.skipTest("manifest must retain intended public key/message records")
        manifest = a.make_manifest(self.manifest["scheme"], len(public), self.manifest["fan_in"],
                                   self.manifest["leaf_capacity"], directory=self.base / "public-only",
                                   public_only=public)
        self.assertEqual(independent_plan_hash(manifest), self.plan_hash)
        for leaf in manifest["leaves"]:
            leaf["input_file"] = "/does-not-exist/no-signature-or-leaf-proof.json"
        self.assertEqual(pack_envelope(self.envelope), self.encoded)
        result = self.verify(self.encoded, True, manifest)
        self.assertFalse(result["verification_uses_child_proofs"])
        self.assertFalse(result["verification_uses_signatures"])
        self.assertTrue(result["statement_pinned"])

    def test_changed_public_claims_rejected_with_recomputed_plan_pin(self):
        public = self.manifest.get("records")
        if not public:
            self.skipTest("manifest must retain public key/message records for frontend controls")
        for kind in ["message", "key", "order", "tail", "missing"]:
            changed = copy.deepcopy(public)
            if kind == "missing":
                changed.pop()
            elif kind == "order":
                changed[0], changed[1] = changed[1], changed[0]
            else:
                index = -1 if kind == "tail" else 0
                field = "public_key_hex" if kind == "key" else "message_hex"
                value = bytearray.fromhex(changed[index][field])
                value[0] ^= 1
                changed[index][field] = value.hex()
            manifest = a.make_manifest(self.manifest["scheme"], len(changed), self.manifest["fan_in"],
                                       self.manifest["leaf_capacity"], directory=self.base / kind, public_only=changed)
            with self.subTest(kind=kind):
                self.verify(self.encoded, False, manifest)

    def test_inherited_lower_edge_all_192_bits_bound(self):
        if len(self.envelope["points"]) < 2:
            self.skipTest("requires a tree with a merge below the root")
        self.assertTrue(self.envelope["points"][0][0])
        for limb in [0, 1, 2]:
            changed = copy.deepcopy(self.envelope)
            changed["points"][0][0][0][limb] ^= 1
            with self.subTest(limb=limb):
                self.verify(pack_envelope(changed), False)

    def test_missing_extra_and_wrong_dimension_obligations_rejected(self):
        mutations = []
        value = copy.deepcopy(self.envelope)
        value["points"].pop()
        mutations.append(value)
        value = copy.deepcopy(self.envelope)
        value["points"][0].pop()
        mutations.append(value)
        value = copy.deepcopy(self.envelope)
        value["points"][0][0].pop()
        mutations.append(value)
        value = copy.deepcopy(self.envelope)
        value["points"].append(copy.deepcopy(value["points"][-1]))
        mutations.append(value)
        for index, value in enumerate(mutations):
            with self.subTest(mutation=index):
                self.verify(pack_envelope(value), False)

    def test_header_identity_and_opaque_proof_mutations_rejected(self):
        for key in ["plan_hash", "guest_hash", "proof"]:
            changed = copy.deepcopy(self.envelope)
            value = bytearray(changed[key])
            value[len(value) // 2] ^= 1
            changed[key] = bytes(value)
            with self.subTest(field=key):
                self.verify(pack_envelope(changed), False)
        changed = copy.deepcopy(self.envelope)
        changed["version"] += 1
        self.verify(pack_envelope(changed), False)

    def test_truncation_trailing_data_and_wrong_external_pin_rejected(self):
        self.verify(self.encoded[:-1], False)
        self.verify(self.encoded + b"\0", False)
        self.verify(self.encoded, False, plan_hash="00" * 32)


if __name__ == "__main__":
    unittest.main()
