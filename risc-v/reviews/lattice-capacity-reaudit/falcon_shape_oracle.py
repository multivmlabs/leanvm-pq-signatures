#!/usr/bin/env python3
"""Independently explain hash sampling and compressed decoding on actual inputs."""
import hashlib
import json
from pathlib import Path
import struct

BASE = Path(__file__).resolve().parent


def record_shape(record):
    nonce = b''.join(w.to_bytes(8, 'little') for w in record[116:121])
    message = b''.join(w.to_bytes(8, 'little') for w in record[112:116])
    stream = hashlib.shake_256(nonce+message).digest(8192)
    accepted = 0
    samples = 0
    for i in range(0, len(stream), 2):
        samples += 1
        if int.from_bytes(stream[i:i+2], 'big') < 61445:
            accepted += 1
            if accepted == 512:
                break
    assert accepted == 512
    permutations = (samples+67)//68
    body = b''.join(w.to_bytes(8, 'big') for w in record[121:])
    pos = 0
    unary_zeros = 0
    left = 64
    window_reloads = 0
    norm = 0
    def bit(at):
        return body[at//8] >> (7-at%8) & 1
    for _ in range(512):
        if left < 24:
            window_reloads += 1
            left = 64
        sign = bit(pos)
        low = sum(bit(pos+1+i) << (6-i) for i in range(7))
        high = 0
        while bit(pos+8+high) == 0:
            high += 1
            assert high < 16
        magnitude = low+128*high
        assert not(sign and magnitude == 0)
        norm += magnitude*magnitude
        unary_zeros += high
        pos += 9+high
        left -= 9+high
    assert pos <= 625*8
    assert all(bit(i) == 0 for i in range(pos, len(body)*8))
    return {'hash_samples': samples, 'hash_rejections': samples-512,
            'keccak_permutations': permutations, 'decompression_unary_zero_bits': unary_zeros,
            'compressed_body_used_bits': pos, 'decompression_window_reloads': window_reloads,
            's2_squared_norm': norm}


def main():
    raw = (BASE/'results/upstream-falcon129.advice.bin').read_bytes()
    words = struct.unpack('<'+'Q'*(len(raw)//8), raw)
    assert words[0] == 129 and len(words) == 1+129*201
    records = [words[1+i*201:1+(i+1)*201] for i in range(129)]
    proved_advice = struct.unpack('<'+'Q'*(1+33*201), (BASE/'results/falcon-33-start96-proved.advice.bin').read_bytes())
    assert tuple([33]+[w for r in records[96:129] for w in r]) == proved_advice
    shapes = [record_shape(r) for r in records]
    windows = []
    for start in (0,96):
        selected = shapes[start:start+33]
        aggregate = {key: sum(r[key] for r in selected) for key in selected[0]}
        name = f'falcon-33-start{start}'+('-proved' if start else '-instrumented')+'.json'
        diagnostic = json.loads((BASE/'results'/name).read_text())
        assert aggregate['keccak_permutations'] == diagnostic['keccak_permutation_calls']
        windows.append({'count':33,'start':start,'aggregate':aggregate,
                        'eight_permutation_records':sum(r['keccak_permutations']==8 for r in selected),
                        'nine_permutation_records':sum(r['keccak_permutations']==9 for r in selected)})
    report={'scope':'Independent Python hashlib SHAKE256 and bit-level Falcon compressed-codec parser on exact upstream-generated advice. Not a signature verifier or proof producer.',
            'upstream_corpus_advice_sha256':hashlib.sha256(raw).hexdigest(),
            'proved_window_is_exact_slice_of_upstream_corpus':True,'windows':windows,'records':shapes}
    (BASE/'falcon-shape-oracle.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(windows,indent=2))


if __name__ == '__main__':
    main()
