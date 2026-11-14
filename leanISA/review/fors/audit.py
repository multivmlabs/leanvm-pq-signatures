"""Independent FORS byte/guest/advice and statement binding audit. No proofs created."""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'python'))
from pqbench.fors import build
from Crypto.Hash import keccak

OUT = Path(__file__).resolve().parent
RUNNER = ROOT / 'target/release/pq-leanbench'
RESULTS = []

def h(b):
    return keccak.new(data=b, digest_bits=256).digest()

def domain(label, k, a):
    return (b'FORS:' + label).ljust(12, b'\x00') + bytes((1, 32, k, a))

def cell_bytes(cell):
    assert len(cell) == 3 and cell[2] == 0
    return b''.join(x.to_bytes(8, 'little') for x in cell[:2])

def cellify(b):
    assert len(b) % 16 == 0
    return [[int.from_bytes(b[i:i+8], 'little'), int.from_bytes(b[i+8:i+16], 'little'), 0]
            for i in range(0, len(b), 16)]

def addr(t, height, index):
    return t.to_bytes(4, 'little') + height.to_bytes(4, 'little') + index.to_bytes(8, 'little')

def independent_records(count, k, a, messages=None):
    records = []
    for r in range(count):
        # Exercise zeros and high bytes without the project's secret derivation.
        seed = bytes(32) if r == 0 else bytes(range(32))
        message = messages[r] if messages is not None else bytes([255 - r]) * 32
        all_levels = []
        secrets = []
        for t in range(k):
            ss = [bytes(32) if (t, i) == (0, 0) else hashlib.sha512(bytes([r, t]) + i.to_bytes(2, 'little')).digest()[:32]
                  for i in range(1 << a)]
            levels = [[h(domain(b'LEAF', k, a) + seed + addr(t, 0, i) + s) for i, s in enumerate(ss)]]
            for height in range(1, a + 1):
                previous = levels[-1]
                levels.append([h(domain(b'NODE', k, a) + seed + addr(t, height, i // 2) + previous[i] + previous[i+1])
                               for i in range(0, len(previous), 2)])
            all_levels.append(levels)
            secrets.append(ss)
        root = h(domain(b'ROOT', k, a) + seed + b''.join(levels[-1][0] for levels in all_levels))
        digest = int.from_bytes(h(domain(b'MSG', k, a) + seed + root + message), 'little')
        chosen = [(digest >> (t * a)) % (1 << a) for t in range(k)]
        openings = [(secrets[t][i], [all_levels[t][j][(i >> j) ^ 1] for j in range(a)]) for t, i in enumerate(chosen)]
        records.append((seed, root, message, openings))
    return records

def from_records(records, k, a):
    f = build(len(records), k, a)
    f['witness'] = {'fors_header': [], 'fors_secret': [], 'fors_auth': []}
    for seed, root, message, openings in records:
        f['witness']['fors_header'].append(cellify(seed + root + message))
        for secret, auth in openings:
            f['witness']['fors_secret'].append(cellify(secret))
            f['witness']['fors_auth'].extend(cellify(s) for s in auth)
    f['public_input'] = cellify(h(domain(b'BATCH', k, a) + b''.join(s + r + m for s, r, m, _ in records)))
    return f

def execute(label, f, accept=True):
    p = OUT / (label + '.input.json')
    p.write_text(json.dumps(f))
    cp = subprocess.run([str(RUNNER), 'execute', '--input', str(p)], cwd=ROOT,
                        env=dict(os.environ, LEANVM_NUM_THREADS='2'), capture_output=True, text=True, timeout=90)
    actual = cp.returncode == 0
    item = {'label': label, 'expected_accept': accept, 'accepted': actual,
            'matched': accept == actual, 'stderr': cp.stderr.strip()}
    if actual:
        report = json.loads(cp.stdout)
        item.update({key: report[key] for key in ('cycles', 'guest_hash', 'public_input_hex', 'scheme', 'metadata')})
    RESULTS.append(item)
    print(label, 'ACCEPT' if actual else 'REJECT', 'PASS' if actual == accept else 'FAIL', flush=True)
    return item

def add_advice(f):
    f = copy.deepcopy(f)
    f['source'] = f['source'].replace('hint_f192_limbs(low, word)', 'hint_witness(low, "audit_low")')
    f['source'] = f['source'].replace('hint_decompose_bits(bits, word, 128)', 'hint_witness(bits, "audit_bits")')
    lows, bits = [], []
    k = f['parameters']['k']
    a = f['parameters']['a']
    w = f['witness']
    for r, header in enumerate(w['fors_header']):
        lows.extend([[c[0], 0, 0]] for c in header)
        digest = h(domain(b'MSG', k, a) + b''.join(cell_bytes(c) for c in header))
        value = int.from_bytes(digest[:16], 'little')
        bits.append([[value >> j & 1, 0, 0] for j in range(128)])
        for t in range(k):
            lows.extend([[c[0], 0, 0]] for c in w['fors_secret'][r*k+t])
            for j in range(a):
                lows.extend([[c[0], 0, 0]] for c in w['fors_auth'][(r*k+t)*a+j])
    w.update({'audit_low': lows, 'audit_bits': bits})
    return f

def main():
    # Published Ethereum empty-string vector guards the hash dialect.
    assert h(b'').hex() == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    base = build(1)
    honest = execute('base', base)
    advice = add_advice(base)
    adv_report = execute('external-advice-honest', advice)
    assert honest['guest_hash'] == adv_report['guest_hash'], 'advice substitution changed constrained bytecode'
    for what, pos in [('header', 0), ('secret', 6), ('auth', 8)]:
        f = copy.deepcopy(advice)
        f['witness']['audit_low'][pos][0][0] ^= 1
        execute('advice-low-' + what, f, False)
    for label, bit, val in [('low-bit', 0, None), ('high-bit', 127, None), ('nonboolean', 5, [2, 0, 0]), ('nonbase-field', 5, [0, 1, 0])]:
        f = copy.deepcopy(advice)
        if val is None:
            f['witness']['audit_bits'][0][bit][0] ^= 1
        else:
            f['witness']['audit_bits'][0][bit] = val
        execute('advice-bits-' + label, f, False)
    for stream, row, column in [('fors_header', 0, j) for j in range(6)] + [('fors_secret', 0, 1), ('fors_auth', -1, 1)]:
        f = copy.deepcopy(base)
        f['witness'][stream][row][column][2] = 1
        execute('noncanonical-' + stream + '-' + str(column), f, False)
    for k, a, n in [(1, 1, 1), (3, 5, 3), (16, 8, 1), (1, 12, 1), (128, 1, 1), (10, 12, 1)]:
        records = independent_records(n, k, a)
        f = from_records(records, k, a)
        execute(f'independent-{k}-{a}-{n}', f)
        # Reordering claims should fail against the original commitment.
        if n > 1:
            reversed_f = from_records(list(reversed(records)), k, a)
            reversed_f['public_input'] = f['public_input']
            execute('order-binding', reversed_f, False)
            shorter = from_records(records[:1], k, a)
            shorter['public_input'] = f['public_input']
            execute('count-binding', shorter, False)
    # Change claims and recompute their public commitment: rejection must occur
    # at the signature/root relation, not merely at the batch digest equality.
    records = independent_records(1, 16, 8)
    for pos, label in [(0, 'seed'), (1, 'root'), (2, 'message')]:
        altered = copy.deepcopy(records)
        row = list(altered[0])
        row[pos] = bytes([row[pos][0] ^ 1]) + row[pos][1:]
        altered[0] = tuple(row)
        execute('recommitted-' + label, from_records(altered, 16, 8), False)
    for label in ('secret', 'auth', 'tree-order'):
        altered = copy.deepcopy(records)
        openings = altered[0][3]
        if label == 'tree-order':
            openings[0], openings[1] = openings[1], openings[0]
        elif label == 'secret':
            secret, auth = openings[0]
            openings[0] = (bytes([secret[0] ^ 1]) + secret[1:], auth)
        else:
            sibling = openings[0][1][0]
            openings[0][1][0] = bytes([sibling[0] ^ 1]) + sibling[1:]
        execute('relation-' + label, from_records(altered, 16, 8), False)
    execute('duplicates-permitted', from_records(records * 2, 16, 8))
    # A reduced supported parameter set makes the exact signature-transfer
    # relation visible. Default-parameter attack complexity is derived separately.
    k, a = 1, 8
    seed, root, _, _ = independent_records(1, k, a)[0]
    seen = {}
    collision = None
    for attempt in range(10000):
        message = attempt.to_bytes(32, 'little')
        index = h(domain(b'MSG', k, a) + seed + root + message)[0]
        if index in seen:
            collision = (seen[index], message, index, attempt + 1)
            break
        seen[index] = message
    assert collision is not None
    first, second, index, attempts = collision
    original = independent_records(1, k, a, messages=[first])
    reused = [(seed, root, second, copy.deepcopy(original[0][3]))]
    control_message = next(m for i, m in seen.items() if i != index)
    control = [(seed, root, control_message, copy.deepcopy(original[0][3]))]
    assert first != second
    assert h(domain(b'MSG', k, a) + seed + root + first)[0] == index
    assert h(domain(b'MSG', k, a) + seed + root + second)[0] == index
    assert h(domain(b'MSG', k, a) + seed + root + control_message)[0] != index
    execute('collision-original-k1-a8', from_records(original, k, a))
    execute('collision-reused-signature-k1-a8', from_records(reused, k, a))
    execute('collision-control-distinct-index-k1-a8', from_records(control, k, a), False)
    (OUT / 'collision.json').write_text(json.dumps({
        'parameters': {'n': 32, 'k': k, 'a': a}, 'attempts': attempts,
        'seed': seed.hex(), 'root': root.hex(), 'message_1': first.hex(),
        'message_2': second.hex(), 'same_index': index,
        'control_message': control_message.hex(),
        'control_index': h(domain(b'MSG', k, a) + seed + root + control_message)[0],
        'note': 'Reduced supported parameters demonstrate the relation; default 2^64 work is an exact ideal-hash birthday estimate, not an executed attack.'
    }, indent=2) + '\n')
    f = copy.deepcopy(base)
    f['scheme'] = 'forged-label'
    f['metadata'] = {'count': 999999, 'verified_signers': 'untrusted-description'}
    execute('metadata-is-not-bound', f)
    f = copy.deepcopy(base)
    f['source'] = 'from snark_lib import *\ndef main():\n    return\n'
    execute('arbitrary-program-is-allowed', f)
    f = copy.deepcopy(base)
    f['public_input'][0][2] = 1
    execute('public-input-high-limb', f, False)
    (OUT / 'results.json').write_text(json.dumps({'coverage': 'execution with fixed compiled constraints; no new proof generated', 'results': RESULTS}, indent=2) + '\n')
    assert all(r['matched'] for r in RESULTS)

if __name__ == '__main__':
    main()
