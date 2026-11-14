"""Independent synthetic-key controls for the ETHFALCON guest, execute only.

Run with .venv/bin/python review/falcon/independent_audit.py.
Synthetic keys are chosen to make s0 zero and isolate codec constraints.
The all-equal polynomial a*(1+X+...+X^511) has inverse (1-X)/(2*a)
in Z_12289[X]/(X^512+1), so no NTT is used to construct these keys.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))
from pqbench import falcon as f


def encode_key(h):
    payload = 0
    for x in h:
        assert 0 <= x < f.Q
        payload = (payload << 14) | x
    return b"\x09" + payload.to_bytes(896, "big")


def encode_signature(s):
    if any(abs(x) > 2047 for x in s):
        return None
    bits = "".join(str(int(x < 0)) + f"{abs(x) % 128:07b}" +
                   "0" * (abs(x) // 128) + "1" for x in s)
    bits += "0" * (-len(bits) % 8)
    return int(bits, 2).to_bytes(len(bits) // 8, "big")


def synthetic_key(c, a):
    inverse = pow(2 * a, -1, f.Q)
    return [((c[0] + c[-1]) * inverse) % f.Q] + [
        ((c[i] - c[i - 1]) * inverse) % f.Q for i in range(1, f.N)]


def fixture(h, s, salt, msg):
    witness = f.Witness()
    witness.signature(h, s, salt, msg)
    initial = f.digest(f.DOMAIN + (1).to_bytes(8, "big"))
    kh = f.digest(b"".join(x.to_bytes(2, "little") for x in h))
    claim = f.digest(f.DOMAIN + kh + f.digest(msg))
    return {"scheme": "review-synthetic-ethfalcon", "source": f.guest_source([msg], initial),
            "witness": witness.streams,
            "public_input": f.halves(f.digest(initial + claim))}


def main():
    vector = f.kat_vectors()[0]
    sm = bytes.fromhex(vector["sm"])
    salt, msg = sm[2:42], bytes.fromhex(vector["msg"])
    c = f.point(salt, msg)
    results = []
    with tempfile.TemporaryDirectory(prefix="falcon-independent-") as directory:
        for a, expected in ((127, True), (128, True)):
            s = [a] * f.N
            h = synthetic_key(c, a)
            assert f.convolution_schoolbook(h, s) == c
            encoded = encode_signature(s)
            assert f.decode_signature(encoded) == s
            signed = (len(encoded) + 1).to_bytes(2, "big") + salt + msg + b"\x29" + encoded
            c_accept = f.native_c_verify(signed, encode_key(h)) == msg
            assert c_accept
            path = Path(directory) / f"all-{a}.json"
            path.write_text(json.dumps(fixture(h, s, salt, msg)))
            run = subprocess.run([str(ROOT / "target/release/pq-leanbench"), "execute", "--input", str(path)],
                                 cwd=ROOT, env={**os.environ, "LEANVM_NUM_THREADS": "1"},
                                 text=True, capture_output=True, timeout=60)
            vm_accept = run.returncode == 0
            assert vm_accept == expected, run.stderr
            results.append({"a": a, "norm": sum(x*x for x in s),
                            "payload_bytes": len(encoded), "C_accept": c_accept,
                            "Python_accept": f.native_verify(h, s, salt, msg),
                            "VM_accept": vm_accept, "VM_stderr": run.stderr.strip()})
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
