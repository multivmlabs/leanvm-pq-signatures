"""Reproducible records and independently derived public claims for the article.

The public-only verification path regenerates the authorized leaf code and
derives its expected statement from actual keys/messages. Saved PI/hash metadata
are never authorization inputs. Benchmark keys are unsuitable for funds.
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import importlib
import json
import subprocess
from pathlib import Path
from time import perf_counter

from . import dilithium as d, falcon as f, fors
from . import falcon_aggregate_inputs as ef

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "artifacts/article"
SCHEMES = ("ethfalcon", "falcon", "ethdilithium", "mldsa", "fors")
CAPACITIES = {"ethfalcon": 5, "falcon": 5, "ethdilithium": 1, "mldsa": 1, "fors": 5}


def write(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, separators=(",", ":")) + "\n")


def pi_hex(pi):
    return b"".join((c[0] | c[1] << 64).to_bytes(16, "little") for c in pi).hex()


def module(scheme):
    return importlib.import_module("pqbench." + {"falcon": "falcon_standard", "mldsa": "mldsa"}[scheme])


def _json_fors(record):
    return {"seed": record["seed"].hex(), "root": record["root"].hex(),
            "message_hex": record["message"].hex(),
            "signature": [{"secret": o["secret"].hex(), "auth": [v.hex() for v in o["auth"]]}
                          for o in record["signature"]]}


def _raw_fors(record):
    return {"seed": bytes.fromhex(record["seed"]), "root": bytes.fromhex(record["root"]),
            "message": bytes.fromhex(record["message_hex"]),
            "signature": [{"secret": bytes.fromhex(o["secret"]),
                           "auth": [bytes.fromhex(v) for v in o["auth"]]}
                          for o in record["signature"]]}


def records(scheme, count=100):
    path = ARTIFACTS / scheme / "records.json"
    replay = ROOT / "results/article/inputs" / f"{scheme}-records.json"
    saved = json.loads(path.read_text()) if path.exists() else (json.loads(replay.read_text()) if replay.exists() else [])
    if len(saved) >= count:
        if not path.exists():
            write(path, saved)
        return saved[:count]
    for i in range(len(saved), count):
        started = perf_counter()
        if scheme == "ethfalcon":
            item = ef.generate_record(i)
        elif scheme == "ethdilithium":
            message = hashlib.sha256(f"article/ethdilithium/{i}".encode()).digest()
            pk, sig, ns = d.native_fixture(message)
            item = {"message_hex": message.hex(), "compact_public_key_hex": pk.hex(),
                    "compact_signature_hex": sig.hex(), "native_verify_ns": ns}
        elif scheme == "fors":
            item = _json_fors(fors.generate_record(i))
        else:
            item = module(scheme).generate_record(i)
        item["record_generation_s"] = perf_counter() - started
        saved.append(item)
        write(path, saved)
        print(f"record {scheme} {i + 1}/{count}", flush=True)
    return saved


def public_record(scheme, record):
    if scheme == "fors":
        key = record["seed"] + record["root"]
    else:
        key = record.get("public_key_hex", record.get("compact_public_key_hex"))
    if not key:
        raise ValueError("record has no canonical public key")
    return {"public_key_hex": key, "message_hex": record["message_hex"]}


@functools.lru_cache(maxsize=256)
def _ethdili_keyhash(key: bytes):
    if len(key) != 1312:
        raise ValueError("expected compact ML-DSA-family public key")
    a, t, tr, _, _ = d.unpack(key, bytes(2420))
    return d.kh(d.raw([d.ec(v) for p in a + t for v in p] + d.cells(tr)))


def expected_pi(scheme, public):
    if not public or any(len(bytes.fromhex(r["message_hex"])) != 32 for r in public):
        raise ValueError("article claims require nonempty batches of 32-byte messages")
    if scheme == "ethfalcon":
        acc = f.digest(f.DOMAIN + len(public).to_bytes(8, "big"))
        for r in public:
            h = f.decode_key(bytes.fromhex(r["public_key_hex"]))
            kh = f.digest(b"".join(x.to_bytes(2, "little") for x in h))
            acc = f.digest(acc + f.digest(f.DOMAIN + kh + f.digest(bytes.fromhex(r["message_hex"]))))
        return f.halves(acc)
    if scheme == "ethdilithium":
        acc = d.kh(d.TAG)
        for r in public:
            acc = d.kh(acc + _ethdili_keyhash(bytes.fromhex(r["public_key_hex"]))
                       + bytes.fromhex(r["message_hex"]))
        return d.cells(acc)
    if scheme == "fors":
        data = fors.domain("BATCH", 16, 8)
        for r in public:
            key = bytes.fromhex(r["public_key_hex"])
            if len(key) != 64:
                raise ValueError("expected 64-byte FORS public key")
            data += key + bytes.fromhex(r["message_hex"])
        return fors.cells(fors.hash256(data))
    return module(scheme).expected_public_input(public)


def build(scheme, group):
    started = perf_counter()
    if scheme == "ethdilithium":
        result = d.build(len(group), records=group)
    elif scheme in ("falcon", "mldsa"):
        result = module(scheme).build_records(group)
    elif scheme == "ethfalcon":
        witness = f.Witness()
        total = 0
        messages = []
        for r in group:
            h, s2, salt, message = ef.decoded_record(r)
            witness.signature(h, s2, salt, message)
            messages.append(message)
            total += len(bytes.fromhex(r["signed_message_hex"])) - len(message) - 2
        initial = f.digest(f.DOMAIN + len(group).to_bytes(8, "big"))
        result = {"scheme": "ethfalcon-512-keccak", "source": f.guest_source(messages, initial),
                  "witness": witness.streams,
                  "public_input": expected_pi(scheme, [public_record(scheme, r) for r in group]),
                  "metadata": {"count": len(group), "signature_bytes": total,
                               "raw_signature_bytes": total, "public_key_bytes": len(group) * 897,
                               "raw_key_bytes": len(group) * 897, "message_bytes": len(group) * 32}}
    elif scheme == "fors":
        decoded = [_raw_fors(r) for r in group]
        if not all(fors.native_verify(r) for r in decoded):
            raise ValueError("invalid FORS record")
        source = leaf_source(scheme, len(group))
        witness = {"fors_header": [], "fors_secret": [], "fors_auth": []}
        for r in decoded:
            witness["fors_header"].append(fors.cells(r["seed"] + r["root"] + r["message"]))
            for opening in r["signature"]:
                witness["fors_secret"].append(fors.cells(opening["secret"]))
                witness["fors_auth"].extend(fors.cells(v) for v in opening["auth"])
        result = {"scheme": fors.SCHEME, "source": source, "witness": witness,
                  "public_input": expected_pi(scheme, [public_record(scheme, r) for r in group]),
                  "metadata": {"count": len(group), "signature_bytes": 4608 * len(group),
                               "raw_signature_bytes": 4608 * len(group), "public_key_bytes": 64 * len(group),
                               "raw_key_bytes": 64 * len(group), "parameters": {"n": 32, "k": 16, "a": 8}}}
    else:
        raise ValueError("unknown scheme")
    expected = expected_pi(scheme, [public_record(scheme, r) for r in group])
    if result["public_input"] != expected:
        raise ValueError("fixture PI differs from independent public claim derivation")
    result.setdefault("metadata", {})["fixture_generation_s"] = perf_counter() - started
    return result


def leaf_source(scheme, count):
    if scheme == "ethfalcon":
        return f.guest_source([bytes(32)] * count, f.digest(f.DOMAIN + count.to_bytes(8, "big")))
    if scheme == "ethdilithium":
        return d.source(count)
    if scheme in ("falcon", "mldsa"):
        return module(scheme).source(count)
    source = (ROOT / "guests/fors.py").read_text()
    for name, value in {"COUNT": count, "K": 16, "A": 8}.items():
        source = source.replace(name + "_PLACEHOLDER", str(value))
    for name in ("LEAF", "NODE", "ROOT", "MSG", "BATCH"):
        source = source.replace("DS_" + name + "_PLACEHOLDER", str(int.from_bytes(fors.domain(name, 16, 8), "little")))
    return source


def program(scheme, count, directory):
    source = leaf_source(scheme, count)
    digest = hashlib.sha256(source.encode()).hexdigest()
    source_path = directory / "programs" / f"{digest}.py"
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text(source)
    cache = directory / "programs" / f"{digest}.inspect.json"
    if cache.exists():
        report = json.loads(cache.read_text())
    else:
        inp = source_path.with_suffix(".input.json")
        write(inp, {"scheme": scheme, "source": source, "public_input": [[0, 0, 0], [0, 0, 0]]})
        checked = subprocess.run([str(ROOT / "target/release/pq-leanbench"), "inspect", "--input", str(inp)],
                                 text=True, capture_output=True, check=True)
        report = json.loads(checked.stdout)
        write(cache, report)
    return {"id": digest, "source_file": str(source_path.resolve()),
            "expected_guest_hash": report["guest_hash"], "min_log_committed": 22}


def make_manifest(scheme, count, fan_in=4, capacity=None, directory=None, public_only=None):
    capacity = capacity or CAPACITIES[scheme]
    directory = Path(directory or ARTIFACTS / scheme)
    raw = None if public_only is not None else records(scheme, count)
    public = public_only if public_only is not None else [public_record(scheme, r) for r in raw]
    public = [{"public_key_hex": bytes.fromhex(r["public_key_hex"]).hex(),
               "message_hex": bytes.fromhex(r["message_hex"]).hex()} for r in public]
    if len(public) != count or len({(r["public_key_hex"].lower(), r["message_hex"].lower()) for r in public}) != count:
        raise ValueError("expected distinct public key/message claims")
    programs, leaves = {}, []
    for start in range(0, count, capacity):
        group = public[start:start + capacity]
        p = program(scheme, len(group), directory)
        programs[p["id"]] = p
        input_path = directory / "leaves" / f"{start}-{len(group)}.json"
        if raw is not None and not input_path.exists():
            write(input_path, build(scheme, raw[start:start + capacity]))
        expected = expected_pi(scheme, group)
        if raw is not None:
            fixture = json.loads(input_path.read_text())
            if fixture["source"] != leaf_source(scheme, len(group)) or fixture["public_input"] != expected:
                raise ValueError("stale fixture does not match trusted source/claims")
        leaves.append({"program_id": p["id"], "signatures": len(group),
                       "public_input_hex": pi_hex(expected), "input_file": str(input_path.resolve())})
    return {"schema_version": 1, "scheme": scheme, "signatures": count, "leaf_capacity": capacity,
            "fan_in": fan_in, "programs": list(programs.values()), "leaves": leaves, "records": public}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["records", "fixture", "manifest", "verify"])
    p.add_argument("--scheme", choices=SCHEMES, required=True)
    p.add_argument("--count", type=int)
    p.add_argument("--capacity", type=int)
    p.add_argument("--fan-in", type=int, choices=[2, 4, 8], default=4)
    p.add_argument("--out")
    p.add_argument("--public")
    p.add_argument("--proof")
    p.add_argument("--report")
    a = p.parse_args()
    requested_count = a.count
    a.count = a.count if a.count is not None else 100
    if a.action == "records":
        records(a.scheme, a.count)
    elif a.action == "fixture":
        write(Path(a.out), build(a.scheme, records(a.scheme, a.count)))
    elif a.action == "manifest":
        write(Path(a.out), make_manifest(a.scheme, a.count, a.fan_in, a.capacity))
    else:
        receiver_started = perf_counter()
        claimed = json.loads(Path(a.public).read_text())
        if claimed["scheme"] != a.scheme:
            raise ValueError("unexpected scheme")
        if requested_count is not None and len(claimed["records"]) != requested_count:
            raise ValueError(f"expected {requested_count} intended claims")
        # Regenerate authorized source and expected public statements. Neither
        # saved programs nor saved leaf public-input metadata are consulted.
        manifest = make_manifest(a.scheme, len(claimed["records"]), a.fan_in, a.capacity,
                                 public_only=claimed["records"])
        claim_derivation_s = perf_counter() - receiver_started
        out = Path(a.out or ARTIFACTS / "verify-public.json")
        write(out, manifest)
        runner = str(ROOT / "target/release/aggregate-tree")
        inspected = subprocess.run([runner, "inspect", "--manifest", str(out)], check=True, text=True, capture_output=True)
        pin = json.loads(inspected.stdout)["plan_hash"]
        cmd = [runner, "verify", "--manifest", str(out), "--proof", a.proof, "--expect-plan-hash", pin,
               "--repeat", "3", "--warmup", "1"]
        if a.report:
            cmd += ["--report", a.report]
        subprocess.run(cmd, check=True)
        if a.report:
            report = json.loads(Path(a.report).read_text())
            report["public_claim_derivation_s"] = claim_derivation_s
            report["public_receiver_process_s"] = perf_counter() - receiver_started
            report["public_receiver_scope"] = "derive claims and authorized sources, inspect trusted plan, then fresh native verify including timing repetitions"
            write(Path(a.report), report)


if __name__ == "__main__":
    main()
