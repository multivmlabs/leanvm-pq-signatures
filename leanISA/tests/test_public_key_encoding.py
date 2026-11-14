"""Host encoding optimization retains the exact binary-field powers."""
import hashlib
import math
import unittest
from pqbench import dilithium as d


def reference(e):
    x, value = 2, 1
    while e:
        if e & 1:
            value = d.gm(value, x)
        x = d.gm(x, x)
        e >>= 1
    return value


class PublicCoefficientEncodingTests(unittest.TestCase):
    def test_generator_order_exceeds_all_bounded_lattice_products(self):
        order = (1 << 64) - 1
        factors = [3, 5, 17, 257, 641, 65537, 6700417]
        self.assertEqual(math.prod(factors), order)
        for p in factors:
            self.assertTrue(all(p % k for k in range(2, math.isqrt(p) + 1)))
            self.assertNotEqual(d.gpow(order // p), 1)
        self.assertEqual(d.gpow(order), 1)
        self.assertLess(d.Q * d.Q, order)
        self.assertLess(512 * (6144 ** 2 + 2047 ** 2) + 520 * 65536, order)

    def test_windowed_power_matches_independent_binary_exponentiation(self):
        values = [0, 1, 65535, 65536, 65537, 131071, d.Q - 1, 1 << 23, (1 << 24) - 1, 1 << 24]
        values += [int.from_bytes(hashlib.sha256(str(i).encode()).digest()[:3], "little") for i in range(24)]
        for e in values:
            with self.subTest(exponent=e):
                self.assertEqual(d.gpow(e), reference(e))
        with self.assertRaises(ValueError):
            d.gpow(-1)


if __name__ == "__main__":
    unittest.main()
