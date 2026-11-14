"""ETHFALCON vector compatibility and adversarial guest-witness checks."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from pqbench import falcon

RUNNER = ROOT / "target/release/pq-leanbench"


def record(vector):
    message = bytes.fromhex(vector["msg"])
    encoded = bytes.fromhex(vector["sm"])
    return (falcon.decode_key(bytes.fromhex(vector["pk"])),
            falcon.decode_signature(encoded[43 + len(message):]),
            encoded[2:42], message)


def bind(fixture, h, message):
    claim = falcon.digest(falcon.DOMAIN + falcon.digest(b"".join(x.to_bytes(2, "little") for x in h)) + falcon.digest(message))
    initial = falcon.digest(falcon.DOMAIN + (1).to_bytes(8, "big"))
    fixture["public_input"] = falcon.halves(falcon.digest(initial + claim))


def encode_key(h):
    payload = 0
    for value in h:
        payload = (payload << 14) | value
    return b"\x09" + payload.to_bytes(896, "big")


def encode_signature(s2):
    bits = "".join(str(int(x < 0)) + f"{abs(x) % 128:07b}" +
                   "0" * (abs(x) // 128) + "1" for x in s2)
    bits += "0" * (-len(bits) % 8)
    return int(bits, 2).to_bytes(len(bits) // 8, "big")


def signed_message(s2, salt, message):
    compressed = encode_signature(s2)
    return (len(compressed) + 1).to_bytes(2, "big") + salt + message + b"\x29" + compressed


class FalconNativeTests(unittest.TestCase):
    def test_upstream_keccak_vectors(self):
        for vector in falcon.kat_vectors()[:10]:
            with self.subTest(kat=vector["count"]):
                self.assertTrue(falcon.native_verify(*record(vector)))

    def test_upstream_c_verifier_and_mutated_signed_message(self):
        vector = falcon.kat_vectors()[0]
        signed = bytes.fromhex(vector["sm"])
        key = bytes.fromhex(vector["pk"])
        message = bytes.fromhex(vector["msg"])
        self.assertEqual(falcon.native_c_verify(signed, key), message)
        mutated = signed[:42] + bytes([signed[42] ^ 1]) + signed[43:]
        self.assertIsNone(falcon.native_c_verify(mutated, key))
        self.assertIsNone(falcon.native_c_verify(signed, key[:100]))
        self.assertGreater(falcon.native_c_timing(signed, key, message), 0)

    def test_signature_decoder_rejects_trailing_zero_bytes(self):
        vector = falcon.kat_vectors()[0]
        signed = bytes.fromhex(vector["sm"])
        message = bytes.fromhex(vector["msg"])
        key = bytes.fromhex(vector["pk"])
        compressed = signed[43 + len(message):]
        self.assertEqual(falcon.decode_signature(compressed), record(vector)[1])
        self.assertEqual(falcon.native_c_verify(signed, key), message)
        with self.assertRaisesRegex(ValueError, "trailing bytes"):
            falcon.decode_signature(compressed + b"\x00")
        altered = (int.from_bytes(signed[:2], "big") + 1).to_bytes(2, "big") + signed[2:] + b"\x00"
        self.assertIsNone(falcon.native_c_verify(altered, key))

    def test_mutated_signature_and_message_rejected(self):
        h, s2, salt, message = record(falcon.kat_vectors()[0])
        self.assertFalse(falcon.native_verify(h, [0] * 512, salt, message))
        self.assertFalse(falcon.native_verify(h, s2, salt, bytes([message[0] ^ 1]) + message[1:]))
        self.assertFalse(falcon.native_verify(h, [2048] + s2[1:], salt, message))

    def test_invalid_count_and_key_encoding(self):
        with self.assertRaises(ValueError):
            falcon.build(0)
        with self.assertRaises(ValueError):
            falcon.decode_key(b"\x09" + b"\xff" * 896)


@unittest.skipUnless(RUNNER.is_file(), "build the release runner before integration tests")
class FalconGuestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.one = falcon.build(1)
        cls.h, cls.s2, cls.salt, cls.message = record(falcon.kat_vectors()[0])
        cls.directory = tempfile.TemporaryDirectory(prefix="pqbench-falcon-test-")
        cls.path = Path(cls.directory.name)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def execute(self, fixture, label, expected=True):
        path = self.path / (label + ".json")
        path.write_text(json.dumps(fixture))
        result = subprocess.run([str(RUNNER), "execute", "--input", str(path)], capture_output=True, text=True, timeout=60, cwd=ROOT)
        if expected:
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        self.assertNotEqual(result.returncode, 0, "accepted invalid Falcon witness: " + label)

    def test_valid_batches(self):
        one = self.execute(self.one, "one")
        three = self.execute(falcon.build(3), "three")
        self.assertGreater(three["cycles"], one["cycles"])
        self.assertEqual(three["metadata"]["count"], 3)

    def test_reference_compressed_payload_sizes(self):
        challenge = falcon.point(self.salt, self.message)
        for a, expected_size in ((127, 576), (128, 640)):
            with self.subTest(coefficient=a):
                # (1-X)*(1+X+...+X^511)=2 in the negacyclic ring.
                # This constructs h independently of the witness NTT.
                inverse = pow(2 * a, -1, falcon.Q)
                h = [((challenge[0] + challenge[-1]) * inverse) % falcon.Q]
                h += [((challenge[i] - challenge[i - 1]) * inverse) % falcon.Q for i in range(1, falcon.N)]
                s2 = [a] * falcon.N
                self.assertEqual(falcon.convolution_schoolbook(h, s2), challenge)
                self.assertEqual(len(encode_signature(s2)), expected_size)
                self.assertEqual(falcon.native_c_verify(signed_message(s2, self.salt, self.message), encode_key(h)), self.message)
                self.assertTrue(falcon.native_verify(h, s2, self.salt, self.message))
                witness = falcon.Witness()
                witness.signature(h, s2, self.salt, self.message)
                fixture = copy.deepcopy(self.one)
                fixture["witness"] = witness.streams
                bind(fixture, h, self.message)
                self.execute(fixture, f"payload_{expected_size}")

    def test_fully_recomputed_coefficient_limit(self):
        challenge = falcon.point(self.salt, self.message)
        for a, valid in ((2047, True), (2048, False)):
            with self.subTest(coefficient=a):
                h = [(x * pow(a, -1, falcon.Q)) % falcon.Q for x in challenge]
                s2 = [a] + [0] * (falcon.N - 1)
                self.assertEqual(falcon.convolution_schoolbook(h, s2), challenge)
                recovered = falcon.native_c_verify(signed_message(s2, self.salt, self.message), encode_key(h))
                self.assertEqual(recovered, self.message if valid else None)
                self.assertEqual(falcon.native_verify(h, s2, self.salt, self.message), valid)
                witness = falcon.Witness()
                witness.signature(h, s2, self.salt, self.message)
                fixture = copy.deepcopy(self.one)
                fixture["witness"] = witness.streams
                bind(fixture, h, self.message)
                self.execute(fixture, f"coefficient_{a}", valid)

    def test_empty_message_matches_upstream(self):
        message = b""
        challenge = falcon.point(self.salt, message)
        a = 127
        inverse = pow(2 * a, -1, falcon.Q)
        h = [((challenge[0] + challenge[-1]) * inverse) % falcon.Q]
        h += [((challenge[i] - challenge[i - 1]) * inverse) % falcon.Q for i in range(1, falcon.N)]
        s2 = [a] * falcon.N
        self.assertEqual(falcon.native_c_verify(signed_message(s2, self.salt, message), encode_key(h)), message)
        self.assertTrue(falcon.native_verify(h, s2, self.salt, message))
        witness = falcon.Witness()
        witness.signature(h, s2, self.salt, message)
        initial = falcon.digest(falcon.DOMAIN + (1).to_bytes(8, "big"))
        fixture = {"scheme": "ethfalcon-512-keccak", "source": falcon.guest_source([message], initial),
                   "witness": witness.streams, "public_input": self.one["public_input"]}
        bind(fixture, h, message)
        self.execute(fixture, "empty_message")

    def test_quotient_remainder_and_ranges(self):
        for stream, value in (("quotient", falcon._GPOW[10]), ("remainder", falcon._GPOW[42]), ("h", falcon._GPOW[12289]), ("negative", 2), ("salt_msg", 256), ("norm_complement_high", falcon._GPOW[520])):
            with self.subTest(stream=stream):
                bad = copy.deepcopy(self.one)
                bad["witness"][stream][0] = [falcon.cell(value)]
                self.execute(bad, "bad_" + stream, False)

    def test_rejected_hash_candidate_cannot_be_accepted(self):
        bad = copy.deepcopy(self.one)
        stream = bad["witness"]["accepted"]
        index = next(i for i, entry in enumerate(stream) if entry[0][0] == 0)
        stream[index] = [falcon.cell(1)]
        self.execute(bad, "bad_hash_rejection", False)

    def test_changed_message_and_key_with_recomputed_public_statement(self):
        bad = copy.deepcopy(self.one)
        message = bytes([self.message[0] ^ 1]) + self.message[1:]
        bad["witness"]["salt_msg"][40] = [falcon.cell(message[0])]
        bind(bad, self.h, message)
        self.execute(bad, "self_consistent_changed_message", False)
        bad = copy.deepcopy(self.one)
        h = list(self.h)
        h[0] = (h[0] + 1) % falcon.Q
        bad["witness"]["h"][0] = [falcon.cell(falcon._GPOW[h[0]])]
        bind(bad, h, self.message)
        self.execute(bad, "self_consistent_changed_key", False)

    def test_fully_recomputed_zero_signature_fails_norm_check(self):
        # All hash and modular-arithmetic hints are recomputed for the false
        # signature. Only the claimed norm complement is fraudulent.
        bad = copy.deepcopy(self.one)
        challenge = falcon.point(self.salt, self.message)
        centered = [(x + falcon.Q // 2) % falcon.Q - falcon.Q // 2 for x in challenge]
        actual_norm = sum(x * x for x in centered)
        self.assertGreater(actual_norm, falcon.BOUND)
        witness = falcon.Witness()
        with patch.object(falcon, "BOUND", actual_norm):
            witness.signature(self.h, [0] * 512, self.salt, self.message)
        bad["witness"] = witness.streams
        self.execute(bad, "forged_norm", False)


if __name__ == "__main__":
    unittest.main()
