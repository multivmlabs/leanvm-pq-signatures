"""Solinas limb kernel controls; none substitutes for Aerie verification."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from pqbench import aerie_kernels as k

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "target/release/pq-leanbench"


def execute(fixture):
    with tempfile.NamedTemporaryFile("w", suffix=".json", prefix="aerie-kernel-") as stream:
        json.dump(fixture, stream)
        stream.flush()
        return subprocess.run([str(RUNNER), "execute", "--input", stream.name], cwd=ROOT,
                              capture_output=True, text=True, timeout=60)


class AerieKernelHostTests(unittest.TestCase):
    def test_exact_unsigned_column_chains_for_boundaries_and_random_inputs(self):
        values = [0, 1, 4, 5, 58, 59, (1 << 22) - 1, 1 << 22,
                  (1 << 44) - 1, 1 << 44, 1 << 63, k.P - 2, k.P - 1]
        pairs = [(a, b) for a in values for b in values]
        for i in range(1000):
            h = hashlib.sha256(b"aerie-kernel-reference" + i.to_bytes(4, "little")).digest()
            pairs.append((int.from_bytes(h[:8], "little") % k.P,
                          int.from_bytes(h[8:16], "little") % k.P))
        for a, b in pairs:
            advice = k.arithmetic_advice(a, b)
            q, r = advice["q"], advice["r"]
            self.assertEqual(a * b, q * k.P + r)
            self.assertEqual(a * b + 59 * q, r + (q << 64))
            self.assertLess(r, k.P)
            self.assertLess(q, k.P)
            self.assertEqual(sum(d << (22 * i) for i, d in enumerate(k.limb_values(a))), a)

    def test_conservative_column_ranges_exclude_exponent_aliasing(self):
        B = k.B
        maximal_left = 3 * (B - 1) ** 2 + 59 * (B - 1) + (1 << 24) - 1
        maximal_right = (B - 1) + B * ((1 << 24) - 1)
        self.assertLess(maximal_left, 1 << 47)
        self.assertLess(maximal_right, 1 << 47)
        self.assertLess(1 << 47, (1 << 64) - 1)
        for bad in (-1, k.P, (1 << 64) - 1):
            with self.assertRaises(ValueError):
                k.arithmetic_advice(bad, 0)

    def test_statement_commits_inputs_outputs_order_and_count(self):
        records = k.generated_records(8)
        self.assertEqual(k.build(8)["public_input"], k.public_input(records))
        self.assertNotEqual(k.public_input(records), k.public_input(records[::-1]))
        self.assertNotEqual(k.public_input(records), k.public_input(records[:1]))
        changed = copy.deepcopy(records)
        changed[0]["r"] ^= 1
        self.assertNotEqual(k.public_input(records), k.public_input(changed))


@unittest.skipUnless(RUNNER.is_file(), "build release runner for constrained kernel checks")
class AerieKernelGuestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = k.build(8)

    def test_positive_boundary_and_random_kernel(self):
        fixture = k.build(16)
        result = execute(fixture)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_false_quotient_rejected(self):
        fixture = copy.deepcopy(self.fixture)
        fixture["witness"]["aerie_bits"][2][0][0] ^= 1
        result = execute(fixture)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("execution:", result.stderr)

    def test_false_carry_and_terminal_digit_rejected(self):
        for entry in (4, 7, 8, 9, 13):
            with self.subTest(entry=entry):
                fixture = copy.deepcopy(self.fixture)
                fixture["witness"]["aerie_bits"][entry][0][0] ^= 1
                result = execute(fixture)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("execution:", result.stderr)

    def test_noncanonical_operand_rejected_even_when_product_relation_holds(self):
        for name, entry in (("a", 0), ("b", 1)):
            for value in (k.P, (1 << 64) - 1):
                with self.subTest(operand=name, value=value):
                    record = k.arithmetic_advice(0, 0)
                    fixture = k.build(1, [record])
                    fixture["witness"]["aerie_bits"][entry] = [k.cell((value >> i) & 1) for i in range(64)]
                    claimed = {**record, name: value}
                    fixture["public_input"] = k.public_input([claimed])
                    result = execute(fixture)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("execution:", result.stderr)

    def test_noncanonical_result_rejected_with_consistent_quotient_and_carries(self):
        # 2 * ((p+1)/2) = p+1 is an exact integer equality with q=0. Thus all
        # product/carry constraints pass and ONLY canonical(rr) must reject.
        record = {"a": 2, "b": (k.P + 1) // 2, "q": 0, "r": k.P + 1,
                  "left_carries": [1, 1, 0, 0], "right_carries": [0, 0],
                  "high_digits": [(1 << 20) - 1, 0, 0, 0]}
        self.assertEqual(record["a"] * record["b"], record["r"])
        encoded = [(record[name], 64) for name in ("a", "b", "q", "r")]
        encoded += [(value, 24) for value in record["left_carries"]]
        encoded += [(value, 20) for value in record["right_carries"]]
        encoded += list(zip(record["high_digits"], (22, 22, 22, 18)))
        fixture = k.build(1)
        fixture["witness"]["aerie_bits"] = [[k.cell((value >> i) & 1) for i in range(width)]
                                             for value, width in encoded]
        fixture["public_input"] = k.public_input([record])
        result = execute(fixture)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("execution:", result.stderr)

    def test_nonboolean_bit_rejected(self):
        fixture = copy.deepcopy(self.fixture)
        fixture["witness"]["aerie_bits"][0][0] = k.cell(2)
        result = execute(fixture)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("execution:", result.stderr)

    def test_false_result_rejected_under_recomputed_public_commitment(self):
        fixture = copy.deepcopy(self.fixture)
        fixture["witness"]["aerie_bits"][3][0][0] ^= 1
        records = copy.deepcopy(fixture["metadata"]["records"])
        records[0]["r"] ^= 1
        fixture["public_input"] = k.public_input(records)
        result = execute(fixture)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("execution:", result.stderr)


if __name__ == "__main__":
    unittest.main()
