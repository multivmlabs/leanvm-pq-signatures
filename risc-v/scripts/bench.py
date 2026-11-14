#!/usr/bin/env python3
"""Run direct batches serially and retain all successful and rejected attempts."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
COUNTS = {'falcon': [1, 2, 4, 7, 8, 16, 24, 28, 29, 30, 31, 32, 33],
          'mldsa': [1, 2, 3, 4, 5, 6, 7], 'fors': list(range(1, 9))}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runner', type=Path, required=True)
    parser.add_argument('--schemes', nargs='+', choices=COUNTS, default=list(COUNTS))
    parser.add_argument('--skip-existing', action='store_true')
    args = parser.parse_args()
    runner = args.runner.resolve()
    binary_hash = hashlib.sha256(runner.read_bytes()).hexdigest()
    for scheme in args.schemes:
        for n in COUNTS[scheme]:
            output = ROOT/f'risc-v/results/direct/{scheme}-{n}.json'
            proof = ROOT/f'risc-v/artifacts/{scheme}-{n}.proof'
            if args.skip_existing and output.exists():
                previous = json.loads(output.read_text())
                if previous.get('status') == 'rejected' or (previous.get('verified') and proof.exists()):
                    print('Retained', output.name, flush=True)
                    continue
            command = [str(runner), 'prove', '--scheme', scheme, '--n', str(n),
                       '--out', str(output), '--proof', str(proof), '--threads', '8',
                       '--repeat', '3', '--warmup', '1']
            made = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
            output.parent.mkdir(parents=True, exist_ok=True)
            Path(str(output)+'.log').write_text(made.stdout+made.stderr)
            if made.returncode:
                raise RuntimeError(f'{scheme} n={n}: {made.stderr[-1000:]}')
            data = json.loads(output.read_text())
            data['host_binary_sha256'] = binary_hash
            data['command'] = command
            output.write_text(json.dumps(data, indent=2)+'\n')
            print(scheme, n, data['status'], data.get('prove_median_s'), data.get('proof_bytes'), flush=True)


if __name__ == '__main__':
    main()
