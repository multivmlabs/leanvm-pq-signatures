"""Standard Falcon and SHAKE constraints, independent of the ETH variant."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from pqbench import falcon as f, falcon_standard as standard, shake

RUNNER = ROOT / "target/release/pq-leanbench"


def execute(fixture):
    with tempfile.NamedTemporaryFile("w", suffix=".json", prefix="standard-falcon-") as file:
        json.dump(fixture, file)
        file.flush()
        return subprocess.run([str(RUNNER), "execute", "--input", file.name], cwd=ROOT,
                              text=True, capture_output=True, timeout=60)


def standard_kats():
    records, record = [], {}
    for line in (ROOT / "vendor/ETHFALCON/test/falcon512-KAT.rsp").read_text().splitlines() + [""]:
        if " = " in line:
            key, value = line.split(" = ", 1)
            record[key] = value
        elif not line.strip() and record:
            records.append(record)
            record = {}
    return records


class StandardFalconNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = [standard.generate_record(i) for i in range(2)]

    def test_native_standard_kats_and_independent_equation(self):
        for kat in standard_kats()[:3]:
            signed, pk, msg = (bytes.fromhex(kat[k]) for k in ("sm", "pk", "msg"))
            self.assertEqual(standard.native_c_verify(signed, pk), msg)
            self.assertTrue(standard.native_verify(f.decode_key(pk),
                            f.decode_signature(signed[43 + len(msg):]), signed[2:42], msg))
            self.assertIsNone(f.native_c_verify(signed, pk))

    def test_eth_signature_rejected_by_standard_verifier(self):
        kat = f.kat_vectors()[0]
        signed, pk = bytes.fromhex(kat["sm"]), bytes.fromhex(kat["pk"])
        self.assertIsNone(standard.native_c_verify(signed, pk))
        self.assertFalse(standard.native_verify(f.decode_key(pk),
                         f.decode_signature(signed[43 + len(bytes.fromhex(kat["msg"])):]),
                         signed[2:42], bytes.fromhex(kat["msg"])))

    def test_deterministic_distinct_records_and_public_derivation(self):
        again = standard.generate_record(0)
        for key in ("public_key_hex", "message_hex", "signed_message_hex"):
            self.assertEqual(again[key], self.records[0][key])
            self.assertNotEqual(self.records[0][key], self.records[1][key])
        public = [{key: record[key] for key in ("public_key_hex", "message_hex")} for record in self.records]
        public[0]["claim_hash"] = "ff" * 32
        self.assertEqual(standard.expected_public_input(public), standard.expected_public_input(self.records))
        self.assertNotEqual(standard.expected_digest(public), standard.expected_digest(public[::-1]))
        self.assertIn("-DETHFALCON=0", standard.NATIVE_BUILD_INFO["compile_flags"])


@unittest.skipUnless(RUNNER.is_file(), "build release runner for guest tests")
class ShakeGuestTests(unittest.TestCase):
    def fixture(self, bits, data, length):
        expected = shake.digest(data, length, bits)
        source = ("from snark_lib import *\n" + shake.dsl_helpers() +
                  shake.dsl_function("xof", len(data), length, bits) +
                  f"\ndef main():\n    data = HeapBuf({max(len(data), 1)})\n")
        if data:
            source += (f"    for i in mul_range(1, GEN ** {len(data)}):\n"
                       '        value = hint_witness("input")\n'
                       "        data[i] = value\n")
        source += "    out = xof(data)\n"
        source += "".join(f"    assert out[GEN ** {i}] == {value}\n" for i, value in enumerate(expected))
        source += "    p = GEN ** 0\n    p[1] = 0\n    p[GEN] = 0\n    return\n"
        return {"scheme": "shake-constraint-test", "source": source,
                "witness": {"input": [[f.cell(value)] for value in data]},
                "public_input": [[0, 0, 0], [0, 0, 0]]}

    def test_shake_absorb_squeeze_padding_and_layout_boundaries(self):
        for bits, rate in ((256, 136), (128, 168)):
            for size in (0, 1, rate - 1, rate, rate + 1, 2 * rate - 1, 2 * rate, 2 * rate + 1, 832):
                with self.subTest(bits=bits, input_bytes=size):
                    data = hashlib.shake_256(b"SHAKE boundary" + size.to_bytes(4, "little")).digest(size)
                    fixture = self.fixture(bits, data, rate + 1)
                    result = execute(fixture)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_nonbyte_input_and_false_xof_output_rejected(self):
        fixture = self.fixture(256, b"\x00", 32)
        self.assertEqual(execute(fixture).returncode, 0)
        fixture["witness"]["input"][0] = [f.cell(256)]
        result = execute(fixture)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("execution:", result.stderr)
        fixture = self.fixture(128, b"valid", 169)
        self.assertEqual(execute(fixture).returncode, 0)
        fixture["source"] = fixture["source"].replace("assert out[GEN ** 0] == ", "assert out[GEN ** 0] == 1 + ")
        result = execute(fixture)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("execution:", result.stderr)


@unittest.skipUnless(RUNNER.is_file(), "build release runner for guest tests")
class StandardFalconGuestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = standard.generate_record(0)
        cls.fixture = standard.build_records([cls.record])

    def test_valid_leaf_and_content_independent_source(self):
        result = execute(self.fixture)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.fixture["source"], standard.build_records([standard.generate_record(1)])["source"])

    def test_rejection_sampling_and_modular_advice_are_constrained(self):
        fixture = copy.deepcopy(self.fixture)
        rejected = next(i for i, entry in enumerate(fixture["witness"]["accepted"]) if entry[0][0] == 0)
        fixture["witness"]["accepted"][rejected] = [f.cell(1)]
        self.assertNotEqual(execute(fixture).returncode, 0)
        for stream, value in (("quotient", f._GPOW[10]), ("remainder", f._GPOW[42]),
                              ("salt_msg", 256), ("negative", 2), ("h", f._GPOW[f.Q])):
            with self.subTest(stream=stream):
                fixture = copy.deepcopy(self.fixture)
                fixture["witness"][stream][0] = [f.cell(value)]
                self.assertNotEqual(execute(fixture).returncode, 0)

    def test_changed_message_with_recomputed_public_claim_rejected(self):
        fixture, record = copy.deepcopy(self.fixture), copy.deepcopy(self.record)
        message = bytes.fromhex(record["message_hex"])
        message = bytes([message[0] ^ 1]) + message[1:]
        record["message_hex"] = message.hex()
        fixture["public_input"] = standard.expected_public_input([record])
        fixture["witness"]["salt_msg"][40] = [f.cell(message[0])]
        self.assertNotEqual(execute(fixture).returncode, 0)

    def test_fully_recomputed_zero_signature_rejected_by_norm(self):
        h, _, salt, message = standard.decoded_record(self.record)
        challenge = standard.point(salt, message)
        norm = sum(((x + f.Q // 2) % f.Q - f.Q // 2) ** 2 for x in challenge)
        self.assertGreater(norm, f.BOUND)
        witness = standard.Witness()
        with patch.object(f, "BOUND", norm):
            witness.signature(h, [0] * f.N, salt, message)
        fixture = copy.deepcopy(self.fixture)
        fixture["witness"] = witness.streams
        self.assertNotEqual(execute(fixture).returncode, 0)

    def test_final_s1_coordinate_is_included_in_terminal_norm(self):
        _, _, salt, message = standard.decoded_record(self.record)
        challenge = standard.point(salt, message)
        s2 = [128] + [0] * (f.N - 1)
        inverse = pow(128, -1, f.Q)
        # The only nonzero s1 coefficient is the final coordinate. Both cases
        # satisfy the full ring equation; only including coordinate 511 in the
        # terminal norm distinguishes the acceptable pair from the false one.
        for last, valid in ((5832, True), (5833, False)):
            with self.subTest(last=last, valid=valid):
                s1 = [0] * (f.N - 1) + [last]
                h = [((c - x) * inverse) % f.Q for c, x in zip(challenge, s1)]
                self.assertEqual(f.convolution_schoolbook(h, s2),
                                 [(c - x) % f.Q for c, x in zip(challenge, s1)])
                norm = 128 ** 2 + last ** 2
                self.assertEqual(norm <= f.BOUND, valid)
                packed = 0
                for value in h:
                    packed = (packed << 14) | value
                pk = b"\x09" + packed.to_bytes(896, "big")
                encoded_bits = "".join(str(int(x < 0)) + f"{abs(x) % 128:07b}" +
                                       "0" * (abs(x) // 128) + "1" for x in s2)
                encoded_bits += "0" * (-len(encoded_bits) % 8)
                body = int(encoded_bits, 2).to_bytes(len(encoded_bits) // 8, "big")
                signed = (len(body) + 1).to_bytes(2, "big") + salt + message + b"\x29" + body
                self.assertEqual(standard.native_c_verify(signed, pk), message if valid else None)
                witness = standard.Witness()
                # For the false pair, supply the norm complement a malicious
                # prover would choose if s1[511] were absent from the sum.
                # A verifier missing that final coordinate would then accept.
                omitted_last_complement = f.BOUND - 128 ** 2
                advice_bound = f.BOUND if valid else norm + omitted_last_complement
                with patch.object(f, "BOUND", advice_bound):
                    witness.signature(h, s2, salt, message)
                if not valid:
                    self.assertEqual(witness.streams["norm_complement_high"][0],
                                     [f.cell(f._GPOW[omitted_last_complement // 65536])])
                fixture = copy.deepcopy(self.fixture)
                fixture["witness"] = witness.streams
                fixture["public_input"] = standard.expected_public_input([
                    {"public_key_hex": pk.hex(), "message_hex": message.hex()}])
                result = execute(fixture)
                self.assertEqual(result.returncode == 0, valid, result.stderr)
                if not valid:
                    self.assertIn("execution:", result.stderr)


if __name__ == "__main__":
    unittest.main()
