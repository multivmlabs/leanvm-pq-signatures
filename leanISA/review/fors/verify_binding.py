"""Re-verify a saved proof against boundary mutations; no proving."""
from __future__ import annotations
import copy
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
SOURCE = ROOT / 'artifacts/2026-11-03-fors/fors-1.proof'
STATEMENT = json.loads(Path(str(SOURCE) + '.statement.json').read_text())
results = []
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--strict', action='store_true', help='expect the hardened runner to reject trailing proof bytes')
args = parser.parse_args()

def run(label, statement, proof=SOURCE, accept=True):
    path = OUT / (label + '.statement.json')
    path.write_text(json.dumps(statement))
    cp = subprocess.run([str(ROOT / 'target/release/pq-leanbench'), 'verify', '--input', str(path), '--proof', str(proof)],
                        env=dict(os.environ, LEANVM_NUM_THREADS='2'), capture_output=True, text=True, timeout=60)
    actual = cp.returncode == 0
    item = {'label': label, 'expected_accept': accept, 'accepted': actual, 'matched': actual == accept, 'stderr': cp.stderr.strip()}
    if actual:
        value = json.loads(cp.stdout)
        item.update({key: value[key] for key in ('guest_hash', 'public_input_hex', 'scheme', 'metadata', 'proof_bytes', 'verified')})
    results.append(item)
    print(label, 'ACCEPT' if actual else 'REJECT', 'PASS' if actual == accept else 'FAIL', flush=True)

run('saved-proof-control', STATEMENT)
s = copy.deepcopy(STATEMENT)
s['scheme'] = 'ethfalcon-512-but-not-bound'
s['metadata'] = {'count': 1234567, 'parameters': {'claim': 'not cryptographically checked'}}
s['witness'] = {'fors_header': [[[0, 0, 0]] * 6]}
run('metadata-and-witness-ignored', s)
s = copy.deepcopy(STATEMENT)
s['public_input'][0][0] ^= 1
run('changed-statement', s, accept=False)
s = copy.deepcopy(STATEMENT)
s['source'] = 'from snark_lib import *\ndef main():\n    return\n'
run('changed-guest', s, accept=False)
p = OUT / 'appended.proof'
p.write_bytes(SOURCE.read_bytes() + b'UNAUTHENTICATED_TRAILER')
run('proof-trailing-bytes', STATEMENT, proof=p, accept=not args.strict)
p = OUT / 'corrupt.proof'
b = bytearray(SOURCE.read_bytes())
b[-1] ^= 1
p.write_bytes(b)
run('corrupt-proof', STATEMENT, proof=p, accept=False)
(OUT / ('verify-results.strict.json' if args.strict else 'verify-results.json')).write_text(json.dumps(results, indent=2) + '\n')
assert all(x['matched'] for x in results)
