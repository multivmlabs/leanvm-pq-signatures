"""Public statement derivation, independent of prover metadata and witnesses."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pqbench import article_inputs as ai
from pqbench import falcon as f, fors


class ArticlePublicClaimsTests(unittest.TestCase):
    def test_ethfalcon_public_derivation_matches_known_fixture(self):
        fixture = f.build(1)
        item = fixture["metadata"]["records"][0]
        # Original KAT has a 33-byte message; the article interface is strictly32.
        public = {"public_key_hex": item["public_key_hex"], "message_hex": bytes(32).hex()}
        h = f.decode_key(bytes.fromhex(public["public_key_hex"]))
        keyhash = f.digest(b"".join(v.to_bytes(2, "little") for v in h))
        expected = f.digest(f.digest(f.DOMAIN + (1).to_bytes(8, "big")) +
                            f.digest(f.DOMAIN + keyhash + f.digest(bytes(32))))
        self.assertEqual(ai.pi_hex(ai.expected_pi("ethfalcon", [public])), expected.hex())
        public["claim_hash"] = "00" * 32
        public["key_hash"] = "00" * 32
        self.assertEqual(ai.pi_hex(ai.expected_pi("ethfalcon", [public])), expected.hex())

    def test_fors_public_key_message_and_order_binding(self):
        public = [{"public_key_hex": (bytes([i]) * 64).hex(), "message_hex": (bytes([i + 1]) * 32).hex()}
                  for i in range(2)]
        pi = ai.expected_pi("fors", public)
        data = fors.domain("BATCH", 16, 8) + b"".join(bytes.fromhex(r["public_key_hex"] + r["message_hex"]) for r in public)
        self.assertEqual(ai.pi_hex(pi), fors.hash256(data).hex())
        self.assertNotEqual(ai.expected_pi("fors", list(reversed(public))), pi)
        changed = copy.deepcopy(public)
        changed[0]["message_hex"] = "ff" * 32
        self.assertNotEqual(ai.expected_pi("fors", changed), pi)

    def test_noncanonical_lengths_rejected(self):
        for scheme in ("fors", "ethfalcon"):
            with self.assertRaises(ValueError):
                ai.expected_pi(scheme, [{"public_key_hex": "00" * 64, "message_hex": "00" * 31}])
        with self.assertRaises(ValueError):
            ai.expected_pi("fors", [{"public_key_hex": "00" * 63, "message_hex": "00" * 32}])

    def test_explicit_receiver_count_is_enforced_before_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "intended.json"
            path.write_text(json.dumps({"scheme": "fors", "records": []}))
            with patch("sys.argv", ["article_inputs", "verify", "--scheme", "fors", "--count", "30", "--public", str(path)]):
                with self.assertRaisesRegex(ValueError, "expected 30 intended claims"):
                    ai.main()


if __name__ == "__main__":
    unittest.main()
