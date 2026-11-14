#!/usr/bin/env python3
"""Public-only saved-proof controls, with an independent BLAKE2s claim encoder."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def output(statement):
    scheme = statement['scheme']
    records = statement['public_records']
    data = bytearray()
    if scheme == 'mldsa':
        data += b'pqbench/mldsa44/compact/v1'.ljust(32, b'\0')
        data += len(records).to_bytes(8, 'little')
    elif scheme == 'fors':
        data += b'FORSv001' + b''.join(x.to_bytes(8, 'little') for x in (32, 16, 8))
        data += len(records).to_bytes(8, 'little')
    for record in records:
        if scheme == 'falcon':
            key = bytes.fromhex(record['public_key'])[1:]
            data += b''.join(key[i:i+8][::-1] for i in range(0, len(key), 8))
        elif scheme == 'mldsa':
            data += bytes.fromhex(record['public_key'])
        else:
            data += bytes.fromhex(record['seed']) + bytes.fromhex(record['root'])
        data += bytes.fromhex(record['message'])
    digest = hashlib.blake2s(data).digest()
    return [int.from_bytes(digest[i:i+8], 'little') for i in range(0, 32, 8)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runner', type=Path, required=True)
    parser.add_argument('--schemes', nargs='+', default=['falcon', 'mldsa', 'fors'])
    args = parser.parse_args()
    runner = args.runner.resolve()
    results = []
    with tempfile.TemporaryDirectory(prefix='riscv-public-only-') as directory:
        tmp = Path(directory)
        for scheme in args.schemes:
            completed = [json.loads(p.read_text()) for p in (ROOT/'risc-v/results/direct').glob(scheme+'-*.json')]
            largest = max(d['count'] for d in completed if d.get('verified'))
            for n in sorted({1, 2, largest}):
                source = ROOT / f'risc-v/artifacts/{scheme}-{n}.proof'
                statement = json.loads(Path(str(source)+'.statement.json').read_text())
                assert output(statement) == statement['expected_output'], 'independent public encoder mismatch'
                proof = source.read_bytes()
                cases = [('honest', statement, proof, True, statement['elf_sha256'])]
                for field in ('message', 'public_key' if scheme != 'fors' else 'seed'):
                    changed = copy.deepcopy(statement)
                    b = bytearray.fromhex(changed['public_records'][0][field]); b[-1] ^= 1
                    changed['public_records'][0][field] = b.hex()
                    changed['expected_output'] = output(changed)
                    cases.append(('changed-'+field, changed, proof, False, statement['elf_sha256']))
                wrong_count = copy.deepcopy(statement); wrong_count['count'] += 1
                cases.append(('wrong-count', wrong_count, proof, False, statement['elf_sha256']))
                wrong_digest = copy.deepcopy(statement); wrong_digest['expected_output'][0] ^= 1
                cases.append(('wrong-cached-output', wrong_digest, proof, False, statement['elf_sha256']))
                corrupted = bytearray(proof); corrupted[len(proof)//2] ^= 1
                cases += [('corrupt-proof', statement, corrupted, False, statement['elf_sha256']),
                          ('truncated-proof', statement, proof[:-1], False, statement['elf_sha256']),
                          ('trailing-proof-bytes', statement, proof+b'\0', False, statement['elf_sha256']),
                          ('wrong-program-pin', statement, proof, False, '00'*32)]
                if n >= 2:
                    reordered = copy.deepcopy(statement); reordered['public_records'].reverse()
                    reordered['expected_output'] = output(reordered)
                    cases.append(('reordered-claims', reordered, proof, False, statement['elf_sha256']))
                for name, public, proof_bytes, accepts, elf_hash in cases:
                    statement_path = tmp/'intended-public.json'; proof_path = tmp/'root.proof'
                    statement_path.write_text(json.dumps(public))
                    proof_path.write_bytes(proof_bytes)
                    command = [str(runner), 'verify', '--scheme', scheme, '--out', str(tmp/'report.json'),
                               '--statement', str(statement_path), '--expect-statement-sha256',
                               hashlib.sha256(statement_path.read_bytes()).hexdigest(), '--expect-elf-sha256', elf_hash,
                               '--proof', str(proof_path), '--repeat', '1', '--warmup', '0']
                    made = subprocess.run(command, cwd=tmp, text=True, capture_output=True)
                    passed = (made.returncode == 0) == accepts
                    results.append({'scheme': scheme, 'count': n, 'case': name, 'expected_accept': accepts,
                                    'returncode': made.returncode, 'passed': passed, 'stderr': made.stderr.strip()})
                    assert passed, results[-1]
    path = ROOT/'risc-v/results/consumer-controls.json'
    path.write_text(json.dumps({'description': 'Only trusted public records and one proof copied to isolated temporary directory; changed claims use independently recomputed digest and a fresh trusted statement pin.',
                               'runner_sha256': hashlib.sha256(runner.read_bytes()).hexdigest(),
                               'passed': all(r['passed'] for r in results), 'controls': results}, indent=2)+'\n')
    print(f'{len(results)} public-only controls passed')


if __name__ == '__main__':
    main()
