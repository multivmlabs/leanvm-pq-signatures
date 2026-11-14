#!/usr/bin/env python3
"""Independent public-only saved-STARK controls. Never generates a proof."""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def output(statement):
    records = statement["public_records"]
    data = b"pqbench/mldsa44/compact/v1".ljust(32, b"\0") + struct.pack("<Q", len(records))
    for record in records:
        data += bytes.fromhex(record["public_key"]) + bytes.fromhex(record["message"])
    return list(struct.unpack("<4Q", hashlib.blake2s(data).digest()))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner", type=Path, required=True)
    args = parser.parse_args()
    runner = args.runner.resolve()
    controls = []
    artifacts = {}
    with tempfile.TemporaryDirectory(prefix="mldsa-review-public-only-") as directory:
        temp = Path(directory)
        for count in [1, 2, 6]:
            source = ROOT / f"risc-v/artifacts/mldsa-{count}.proof"
            statement = json.loads(Path(str(source) + ".statement.json").read_text())
            proof = source.read_bytes()
            assert statement["count"] == count
            assert statement["expected_output"] == output(statement)
            artifacts[str(source.relative_to(ROOT))] = hashlib.sha256(proof).hexdigest()
            elf_hash = statement["elf_sha256"]
            cases = [("honest", statement, proof, True, elf_hash, None)]
            for field in ["public_key", "message"]:
                changed = copy.deepcopy(statement)
                data = bytearray.fromhex(changed["public_records"][0][field])
                data[0] ^= 1
                changed["public_records"][0][field] = data.hex()
                changed["expected_output"] = output(changed)
                cases.append((f"changed-{field}-recomputed-claim", changed, proof, False, elf_hash, None))
            changed = copy.deepcopy(statement)
            changed["public_records"].append(copy.deepcopy(changed["public_records"][0]))
            changed["count"] += 1
            changed["expected_output"] = output(changed)
            cases.append(("added-record-recomputed-count-and-claim", changed, proof, False, elf_hash, None))
            if count > 1:
                changed = copy.deepcopy(statement)
                changed["public_records"].pop()
                changed["count"] -= 1
                changed["expected_output"] = output(changed)
                cases.append(("removed-record-recomputed-count-and-claim", changed, proof, False, elf_hash, None))
                changed = copy.deepcopy(statement)
                changed["public_records"].reverse()
                changed["expected_output"] = output(changed)
                cases.append(("reordered-records-recomputed-claim", changed, proof, False, elf_hash, None))
            changed = copy.deepcopy(statement)
            changed["expected_output"][0] ^= 1
            cases.append(("cached-output-mismatch", changed, proof, False, elf_hash, None))
            changed = copy.deepcopy(statement)
            changed["public_records"][0]["message"] = "é" + changed["public_records"][0]["message"][1:]
            cases.append(("non-ascii-hex", changed, proof, False, elf_hash, None))
            corrupted = bytearray(proof)
            corrupted[len(corrupted) // 2] ^= 1
            cases.extend([
                ("corrupt-proof", statement, corrupted, False, elf_hash, None),
                ("truncated-proof", statement, proof[:-1], False, elf_hash, None),
                ("trailing-proof-byte", statement, proof + b"\0", False, elf_hash, None),
                ("wrong-program-pin", statement, proof, False, "00" * 32, None),
                ("wrong-statement-pin", statement, proof, False, elf_hash, "00" * 32),
            ])
            for name, intended, encoded, accepts, program_pin, statement_pin in cases:
                statement_path = temp / "intended-public.json"
                proof_path = temp / "root.proof"
                statement_path.write_text(json.dumps(intended))
                proof_path.write_bytes(encoded)
                pin = statement_pin or hashlib.sha256(statement_path.read_bytes()).hexdigest()
                command = [str(runner), "verify", "--scheme", "mldsa", "--out", str(temp / "report.json"),
                           "--statement", str(statement_path), "--expect-statement-sha256", pin,
                           "--expect-elf-sha256", program_pin, "--proof", str(proof_path),
                           "--repeat", "1", "--warmup", "0", "--threads", "1"]
                done = subprocess.run(command, cwd=temp, capture_output=True, text=True)
                passed = (done.returncode == 0) == accepts
                # Recomputed, well-formed claims must reach proof verification.
                if "recomputed" in name:
                    passed = passed and "the proof does not verify" in done.stderr
                controls.append({"count": count, "case": name, "expected_accepts": accepts,
                                 "exit_code": done.returncode, "stderr": done.stderr.strip(), "passed": passed})
                assert passed, controls[-1]
    report = {"scope": "Separate process, public-only full Program::verify controls; no STARK generation",
              "runner_sha256": hashlib.sha256(runner.read_bytes()).hexdigest(),
              "proof_sha256": artifacts, "passed": all(c["passed"] for c in controls), "controls": controls}
    (ROOT / "risc-v/reviews/mldsa-receipt-controls.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": sum(c["passed"] for c in controls), "total": len(controls),
                      "runner_sha256": report["runner_sha256"]}))


if __name__ == "__main__":
    main()
