#!/usr/bin/env python3
"""Sequential, resumable actual measurements for the ethresearch article."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from pqbench import article_inputs as ai
from pqbench import dilithium as d, falcon as f, falcon_standard as fs, mldsa, fors

OUT = ROOT / "results/article"
RUNNER = ROOT / "target/release/pq-leanbench"
TREE = ROOT / "target/release/aggregate-tree"


def write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def run(cmd, log, timeout=3600):
    log = Path(log)
    log.parent.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter()
    with log.open("w") as stream:
        done = subprocess.run([str(v) for v in cmd], stdout=stream, stderr=subprocess.STDOUT,
                              cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT / "python")}, timeout=timeout)
    return done.returncode, time.perf_counter() - start


def direct(schemes, repeats, warmup):
    for scheme in schemes:
        for n in [*range(1, 31), *([70, 100] if scheme == "fors" else [])]:
            report = OUT / "direct" / f"{scheme}-{n}.json"
            failure = report.with_suffix(".failed.json")
            if failure.exists():
                if scheme != "fors":
                    break
                continue
            if report.exists() and json.loads(report.read_text()).get("verified"):
                continue
            print(f"DIRECT {scheme} N={n}", flush=True)
            inp = ai.ARTIFACTS / scheme / f"direct-{n}.json"
            if not inp.exists():
                ai.write(inp, ai.build(scheme, ai.records(scheme, n)))
            proof = inp.with_suffix(".proof")
            cmd = [RUNNER, "prove", "--input", inp, "--proof", proof, "--report", report,
                   "--repeat", repeats, "--warmup", warmup, "--rate", 1]
            code, wall = run(cmd, report.with_suffix(".log"))
            if code:
                error = report.with_suffix(".log").read_text()[-6000:]
                write(failure, {"status": "failed", "scheme": scheme, "count": n,
                                "command": [str(v) for v in cmd], "elapsed_s": wall, "error": error})
                if "WitnessOutOfRange" not in error:
                    raise RuntimeError(error)
                print(f"  capacity limit: {error[-150:]}", flush=True)
                if scheme != "fors":
                    break
                continue
            data = json.loads(report.read_text())
            data.update({"input_sha256": hashlib.sha256(inp.read_bytes()).hexdigest(),
                         "experiment_process_elapsed_s": wall, "article_scheme": scheme})
            write(report, data)
            verify = report.with_suffix(".verify.json")
            code, _ = run([RUNNER, "verify", "--input", str(proof) + ".statement.json", "--proof", proof,
                           "--expect-guest-hash", data["guest_hash"], "--expect-public-input", data["public_input_hex"],
                           "--report", verify, "--repeat", 3, "--warmup", 1], verify.with_suffix(".log"))
            if code:
                raise RuntimeError("fresh verification failed: " + str(verify))
            print(f"  {statistics.median(data['prove_s']):.3f}s, {data['proof_bytes']/1024:.1f}KiB", flush=True)


def inspect(path):
    done = subprocess.run([str(TREE), "inspect", "--manifest", str(path)],
                          text=True, capture_output=True, check=True, cwd=ROOT)
    return json.loads(done.stdout)


def tree_case(scheme, n, b, repeats, warmup, capacity=None, label=None, merge_only=False):
    cap = capacity or ai.CAPACITIES[scheme]
    label = label or f"{scheme}-{n}-b{b}"
    directory = OUT / "trees" / label
    artifacts = ai.ARTIFACTS / scheme / "trees" / label
    manifest_path = artifacts / "manifest.json"
    manifest = ai.make_manifest(scheme, n, b, cap)
    ai.write(manifest_path, manifest)
    plan = inspect(manifest_path)
    write(directory / "plan.json", plan)
    ai.write(artifacts / "public.json", {"scheme": scheme, "records": manifest["records"]})
    cold = b == 4 and not merge_only
    passes = range(-warmup, repeats) if cold else [0]
    for sample in passes:
        name = ("warmup" if sample == -1 else f"warmup-{abs(sample)}") if sample < 0 else f"sample-{sample}"
        report = directory / f"{name}.json"
        if report.exists() and json.loads(report.read_text()).get("verification", {}).get("verified"):
            continue
        print(f"TREE {label} {name}", flush=True)
        out = artifacts / name
        cache = artifacts / f"{name}-leaves" if cold else ai.ARTIFACTS / scheme / "merge-only-leaf-cache"
        cmd = [TREE, "prove", "--manifest", manifest_path, "--expect-plan-hash", plan["plan_hash"],
               "--leaf-cache-dir", cache, "--out-dir", out, "--rate", 1, "--report", report,
               "--repeat", 1 if cold else repeats, "--warmup", 0 if cold else warmup]
        if cold:
            cmd.append("--fresh-leaves")
        code, wall = run(cmd, directory / f"{name}.log")
        if code:
            error = (directory / f"{name}.log").read_text()[-6000:]
            write(directory / f"{name}.failed.json", {"status": "failed", "scheme": scheme, "count": n,
                   "fan_in": b, "leaf_capacity": cap, "error": error, "elapsed_s": wall})
            if "WitnessOutOfRange" in error or "capacity" in error:
                print(f"  unsupported layout: {error[-250:]}", flush=True)
                return
            raise RuntimeError(error)
        data = json.loads(report.read_text())
        data.update({"article_scheme": scheme, "article_count": n, "article_fan_in": b,
                     "article_leaf_capacity": cap, "experiment_process_elapsed_s": wall,
                     "measurement_scope": "complete fresh pipeline" if cold else "repeated merges with checked reusable leaves"})
        write(report, data)
        # Cache only actually verified leaves for the fan-in sensitivity.
        if cold and sample >= 0:
            target = ai.ARTIFACTS / scheme / "merge-only-leaf-cache"
            target.mkdir(parents=True, exist_ok=True)
            import shutil
            for src in cache.glob("*"):
                if src.is_file() and not (target / src.name).exists():
                    shutil.copyfile(src, target / src.name)
        if sample < 0:
            continue
        verification = directory / f"{name}.fresh-verification.json"
        code, _ = run([sys.executable, "-m", "pqbench.article_inputs", "verify", "--scheme", scheme,
                       "--count", n,
                       "--public", artifacts / "public.json", "--proof", out / "aggregate.proof",
                       "--fan-in", b, "--capacity", cap, "--out", artifacts / "receiver.json",
                       "--report", verification], directory / f"{name}.fresh-verification.log")
        if code:
            raise RuntimeError("public-only tree verification failed: " + str(verification))
        print(f"  complete process {wall:.2f}s, edges={plan.get('edges', plan.get('edge_count'))}", flush=True)


def trees(schemes, counts, fans, repeats, warmup):
    for scheme in schemes:
        for n in counts:
            for b in sorted(fans, key=lambda x: x != 4):
                tree_case(scheme, n, b, repeats, warmup)
                if b == 4:
                    tree_case(scheme, n, b, repeats, warmup, label=f"{scheme}-{n}-b4-merge-only", merge_only=True)


def native(schemes):
    result = {}
    for scheme in schemes:
        print(f"NATIVE {scheme}", flush=True)
        r = ai.records(scheme, 1)[0]
        times = []
        if scheme == "fors":
            record = ai._raw_fors(r)
            for _ in range(3):
                start = time.perf_counter_ns()
                for _ in range(1000):
                    if not fors.native_verify(record):
                        raise RuntimeError("invalid FORS")
                times.append((time.perf_counter_ns() - start) / 1000)
            kind = "Python reference with PyCryptodome Keccak; not native C"
        elif scheme in ("falcon", "ethfalcon"):
            m = fs if scheme == "falcon" else f
            pk, msg, sig = (bytes.fromhex(r[k]) for k in ("public_key_hex", "message_hex", "signed_message_hex"))
            for _ in range(3):
                times.append(m.native_c_timing(sig, pk, msg, repeats=1000))
            kind = "pinned C verifier, preallocated output; includes ctypes calls"
        else:
            m = mldsa if scheme == "mldsa" else d
            lib = m._native()
            pk, msg, sig = (bytes.fromhex(r[k]) for k in ("compact_public_key_hex", "message_hex", "compact_signature_hex"))
            fn = lib.pqcrystals_dilithium2_ref_verify
            for _ in range(3):
                start = time.perf_counter_ns()
                for _ in range(1000):
                    if fn(sig, len(sig), msg, len(msg), b"", 0, pk):
                        raise RuntimeError("invalid native lattice record")
                times.append((time.perf_counter_ns() - start) / 1000)
            kind = "pinned C verifier; includes ctypes calls"
        keys, signs = signing_samples(scheme) if scheme != "fors" else ([], [])
        result[scheme] = {"verify_ns_samples": times, "verify_ns_median": statistics.median(times),
                           "repeats_per_sample": 1000, "implementation": kind,
                           "keygen_ns_samples": keys, "sign_ns_samples": signs,
                           "signing_scope": "30 fresh test keys; C calls include FFI, entropy setup outside Falcon keygen; buffers preallocated",
                           "signing_hardware": "Apple M4 Pro host, not a phone or hardware-wallet measurement"}
        write(OUT / "native.json", result)


def signing_samples(scheme):
    """Matched host C sampling; never serialize a signing key."""
    key_times, sign_times = [], []
    for i in range(31):
        message = hashlib.sha256(f"article/native-sign/{i}".encode()).digest()
        if scheme in ("falcon", "ethfalcon"):
            lib = fs._native_c() if scheme == "falcon" else f._native_c()
            lib.crypto_sign_keypair_from_seed.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
            lib.randombytes_init.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
            lib.crypto_sign.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_char_p,
                                       ctypes.c_ulonglong, ctypes.c_void_p]
            entropy = ctypes.create_string_buffer(hashlib.shake_256(message + b"rng").digest(48))
            lib.randombytes_init(entropy, None, 256)
            pk, sk = ctypes.create_string_buffer(897), ctypes.create_string_buffer(1281)
            sig, size = ctypes.create_string_buffer(800), ctypes.c_ulonglong()
            start = time.perf_counter_ns()
            if lib.crypto_sign_keypair_from_seed(pk, sk, hashlib.shake_256(message).digest(48), 48):
                raise RuntimeError("native Falcon keygen failed")
            kt = time.perf_counter_ns() - start
            start = time.perf_counter_ns()
            for _ in range(16):
                if lib.crypto_sign(sig, ctypes.byref(size), message, 32, sk) == 0:
                    break
            else:
                raise RuntimeError("native Falcon signing retries exhausted")
            st = time.perf_counter_ns() - start
            checked = fs.native_c_verify if scheme == "falcon" else f.native_c_verify
            if checked(sig.raw[:size.value], pk.raw) != message:
                raise RuntimeError("native signature did not verify")
        else:
            lib = mldsa._native() if scheme == "mldsa" else d._native()
            pk, sk = ctypes.create_string_buffer(1312), ctypes.create_string_buffer(2560)
            sig, size = ctypes.create_string_buffer(2420), ctypes.c_size_t()
            start = time.perf_counter_ns()
            if lib.pqcrystals_dilithium2_ref_keypair(pk, sk):
                raise RuntimeError("native ML-DSA-family keygen failed")
            kt = time.perf_counter_ns() - start
            with d._quiet_c_stdout():
                start = time.perf_counter_ns()
                status = lib.pqcrystals_dilithium2_ref_signature(sig, ctypes.byref(size), message, 32, b"", 0, sk)
                st = time.perf_counter_ns() - start
            if status or lib.pqcrystals_dilithium2_ref_verify(sig, size.value, message, 32, b"", 0, pk):
                raise RuntimeError("native ML-DSA-family signature failed")
        ctypes.memset(ctypes.addressof(sk), 0, len(sk))
        if i:
            key_times.append(kt)
            sign_times.append(st)
    return key_times, sign_times


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["native", "direct", "trees", "sensitivity", "all"])
    p.add_argument("--schemes", nargs="+", choices=ai.SCHEMES, default=list(ai.SCHEMES))
    p.add_argument("--counts", nargs="+", type=int, default=[10, 30, 70, 100])
    p.add_argument("--fan-ins", nargs="+", type=int, default=[4, 2, 8])
    p.add_argument("--repeat", type=int, default=3)
    p.add_argument("--warmup", type=int, default=1)
    a = p.parse_args()
    if a.action in ("native", "all"):
        native(a.schemes)
    if a.action in ("direct", "all"):
        direct(a.schemes, a.repeat, a.warmup)
    if a.action in ("trees", "all"):
        trees(a.schemes, a.counts, a.fan_ins, a.repeat, a.warmup)
    if a.action in ("sensitivity", "all"):
        if "ethfalcon" in a.schemes and 100 in a.counts:
            for cap in (1, 2, 4):
                tree_case("ethfalcon", 100, 4, a.repeat, a.warmup, cap, f"ethfalcon-100-b4-leaf{cap}")
        if "fors" in a.schemes:
            for n in a.counts:
                tree_case("fors", n, 4, a.repeat, a.warmup, 16, f"fors-{n}-b4-leaf16")


if __name__ == "__main__":
    main()
