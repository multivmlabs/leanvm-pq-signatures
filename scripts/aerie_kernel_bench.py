#!/usr/bin/env python3
"""Sequential, resumable leanVM proofs of the Aerie Fp64 arithmetic kernel.

These are constrained modular-multiplication probes, not Aerie verification.
Run with --prepare-only to create fixtures without executing or proving a guest.
The default measurement is one warmup and three proofs, inverse-rate log one.
The core CLI verifies every generated proof and saves its final measured proof;
this script additionally verifies that saved proof in a fresh process from a
trusted public-only statement with independently regenerated source and digest.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from pqbench import aerie_kernels as kernel

RUNNER = ROOT / "target/release/pq-leanbench"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def pi_hex(pi) -> str:
    # cpu::public_input_bytes transports two 128-bit digest halves, unlike
    # internal 192-bit arithmetic words. A nonzero third limb is inadmissible.
    if len(pi) != 2 or any(len(word) != 3 or word[2] != 0 for word in pi):
        raise ValueError("expected two canonical 128-bit public digest halves")
    return b"".join(int(limb).to_bytes(8, "little") for word in pi for limb in word[:2]).hex()


def run(command, log: Path, timeout=1800):
    log.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    with log.open("w") as stream:
        process = subprocess.run([str(item) for item in command], cwd=ROOT,
                                 stdout=stream, stderr=subprocess.STDOUT,
                                 env={**os.environ, "PYTHONPATH": str(ROOT / "python")},
                                 timeout=timeout)
    return process.returncode, time.perf_counter() - started


def inspect(public_input: Path):
    result = subprocess.run([str(RUNNER), "inspect", "--input", str(public_input)],
                            cwd=ROOT, text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def prepare(count: int, directory: Path):
    fixture = kernel.build(count)
    # Regeneration, rather than producer-provided metadata, defines the source
    # and expected ordered commitment used by the independent receiver below.
    trusted_source = kernel.source(count)
    trusted_pi = kernel.public_input(kernel.generated_records(count))
    assert fixture["source"] == trusted_source and fixture["public_input"] == trusted_pi
    input_path = directory / f"fp64mul-{count}.json"
    public_path = directory / f"fp64mul-{count}.public.json"
    encoded = json.dumps(fixture) + "\n"
    directory.mkdir(parents=True, exist_ok=True)
    if not input_path.exists() or input_path.read_text() != encoded:
        input_path.write_text(encoded)
    public = {"scheme": fixture["scheme"], "source": trusted_source,
              "public_input": trusted_pi, "witness": {}}
    write(public_path, public)
    return input_path, public_path, hashlib.sha256(trusted_source.encode()).hexdigest(), pi_hex(trusted_pi)


def compatible_saved(report: Path, verification: Path, proof: Path, expected):
    if not all(path.is_file() for path in (report, verification, proof)):
        return False
    data = json.loads(report.read_text())
    verified = json.loads(verification.read_text())
    return (data.get("verified") is True and verified.get("verified") is True
            and all(data.get(key) == value for key, value in expected.items())
            and data.get("saved_proof_sha256") == sha(proof)
            and verified.get("guest_hash") == expected["trusted_guest_hash"]
            and verified.get("public_input_hex") == expected["trusted_public_input_hex"]
            and verified.get("statement_pinned") is True)


def measure(count, args):
    input_path, public_path, source_hash, expected_pi = prepare(count, args.artifacts)
    if args.prepare_only:
        print(json.dumps({"action": "prepare-only", "count": count,
                          "input": str(input_path), "source_sha256": source_hash,
                          "input_sha256": sha(input_path), "proof_jobs": 0}), flush=True)
        return
    trusted = inspect(public_path)
    if trusted["public_input_hex"] != expected_pi:
        raise RuntimeError("compiled inspection differs from trusted public commitment")
    guest_hash = trusted["guest_hash"]
    name = f"fp64mul-{count}"
    report = args.out / f"{name}.json"
    verification = args.out / f"{name}.verify.json"
    proof = args.artifacts / f"{name}.proof"
    expected = {"kernel_count": count, "trusted_source_sha256": source_hash,
                "input_sha256": sha(input_path), "public_statement_sha256": sha(public_path),
                "runner_sha256": sha(RUNNER),
                "trusted_guest_hash": guest_hash, "trusted_public_input_hex": expected_pi,
                "requested_repeats": args.repeat, "requested_warmups": args.warmup,
                "requested_log_inv_rate": 1}
    if compatible_saved(report, verification, proof, expected):
        print(f"KERNEL N={count}: resume verified saved proof and matching source/input hashes", flush=True)
        return
    print(f"KERNEL N={count}: {args.warmup} warmup + {args.repeat} measured proofs", flush=True)
    command = [RUNNER, "prove", "--input", input_path, "--proof", proof,
               "--report", report, "--repeat", args.repeat, "--warmup", args.warmup, "--rate", 1]
    code, elapsed = run(command, args.out / f"{name}.log")
    if code:
        log = args.out / f"{name}.log"
        error = log.read_text()[-6000:]
        write(args.out / f"{name}.failed.json", {"status": "failed", **expected,
              "command": [str(x) for x in command], "elapsed_s": elapsed, "error": error})
        if "WitnessOutOfRange" in error:
            print(f"KERNEL N={count}: recorded backend capacity failure", flush=True)
            return
        raise RuntimeError(f"kernel proving failed: {log}\n{error}")
    data = json.loads(report.read_text())
    if not data.get("verified") or data["guest_hash"] != guest_hash or data["public_input_hex"] != expected_pi:
        raise RuntimeError("produced kernel statement differs from trusted source/public input")
    if len(data["prove_s"]) != args.repeat:
        raise RuntimeError("missing measured kernel proof samples")
    data.update(expected)
    data.update({"scope": "Constrained Fp64 multiplication plus public Keccak binding; not an Aerie verifier",
                 "experiment_process_elapsed_s": elapsed, "saved_proof_sha256": sha(proof),
                 "saved_proof_scope": "Final measured proof; core CLI self-verifies every generated proof",
                 "proving_excludes": "Python fixture/advice preparation, source compilation, proof serialization and verification",
                 "derived_log_committed_ceiling": (int(data["committed_cells"]) - 1).bit_length(),
                 "record_binding_keccak_calls": count,
                 "date_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()})
    write(report, data)
    verify_command = [RUNNER, "verify", "--input", public_path, "--proof", proof,
                      "--expect-guest-hash", guest_hash, "--expect-public-input", expected_pi,
                      "--report", verification, "--repeat", args.repeat, "--warmup", args.warmup]
    code, verify_elapsed = run(verify_command, args.out / f"{name}.verify.log")
    if code:
        raise RuntimeError(f"fresh public-only kernel verification failed: {verification}")
    checked = json.loads(verification.read_text())
    if (not checked.get("verified") or not checked.get("statement_pinned")
            or checked["guest_hash"] != guest_hash or checked["public_input_hex"] != expected_pi):
        raise RuntimeError("fresh kernel verifier did not establish the intended statement")
    checked.update({"verification_input_contains_witness": False,
                    "public_statement_sha256": sha(public_path),
                    "saved_proof_sha256": sha(proof),
                    "verification_process_elapsed_s": verify_elapsed})
    write(verification, checked)
    failure = args.out / f"{name}.failed.json"
    if failure.exists():
        failure.unlink()
    print(f"KERNEL N={count}: proved {data['cycles']} cycles; saved proof {data['proof_bytes']} bytes; fresh verification passed", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--counts", nargs="+", type=int, default=[1, 8, 64, 256])
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--out", type=Path, default=ROOT / "results/aerie/kernels")
    parser.add_argument("--artifacts", type=Path, default=ROOT / "artifacts/aerie/kernels")
    args = parser.parse_args()
    if any(count < 1 for count in args.counts) or args.repeat < 1 or args.warmup < 0:
        parser.error("counts/repeat must be positive and warmup nonnegative")
    for count in args.counts:
        measure(count, args)


if __name__ == "__main__":
    main()
