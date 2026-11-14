#!/usr/bin/env python3
"""Independent public-only consumer controls on saved FORS proofs."""
from pathlib import Path
import copy
import hashlib
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / ".cache/aerie-wrapper-host-target/release/riscv-pqbench"
ELF_PIN = "64480a3bf424f97578f6477a7a4045c2452853a0801f45fc191648eb253e36da"


def expected(records):
    data = bytearray(b"FORSv001")
    for value in (32, 16, 8, len(records)):
        data.extend(value.to_bytes(8, "little"))
    for record in records:
        assert set(record) == {"seed", "root", "message"}
        for field in ("seed", "root", "message"):
            value = bytes.fromhex(record[field])
            assert len(value) == 32
            data.extend(value)
    digest = hashlib.blake2s(data).digest()
    return [int.from_bytes(digest[i:i+8], "little") for i in range(0, 32, 8)]


def main():
    controls = []
    for count in (1, 2, 7):
        source = ROOT / f"risc-v/artifacts/fors-{count}.proof"
        proof = source.read_bytes()
        statement = json.loads(source.with_suffix(".proof.statement.json").read_text())
        assert statement["elf_sha256"] == ELF_PIN
        assert statement["count"] == count == len(statement["public_records"])
        assert statement["expected_output"] == expected(statement["public_records"])
        cases = [("honest", statement, proof, True, ELF_PIN)]
        for field in ("seed", "root", "message"):
            changed = copy.deepcopy(statement)
            value = bytearray.fromhex(changed["public_records"][0][field])
            value[-1] ^= 0x80
            changed["public_records"][0][field] = value.hex()
            changed["expected_output"] = expected(changed["public_records"])
            cases.append(("changed-" + field, changed, proof, False, ELF_PIN))
        if count > 1:
            changed = copy.deepcopy(statement)
            changed["public_records"].reverse()
            changed["expected_output"] = expected(changed["public_records"])
            cases.append(("reordered-claims", changed, proof, False, ELF_PIN))
            changed = copy.deepcopy(statement)
            changed["public_records"][1] = copy.deepcopy(changed["public_records"][0])
            changed["expected_output"] = expected(changed["public_records"])
            cases.append(("substituted-duplicate-claim", changed, proof, False, ELF_PIN))
        changed = copy.deepcopy(statement)
        changed["count"] += 1
        cases.append(("wrong-count", changed, proof, False, ELF_PIN))
        changed = copy.deepcopy(statement)
        changed["expected_output"][3] ^= 1 << 63
        cases.append(("wrong-cached-output", changed, proof, False, ELF_PIN))
        for encoding in ("gg" * 32, "00" * 31, "00" * 33, "é" * 64):
            changed = copy.deepcopy(statement)
            changed["public_records"][0]["message"] = encoding
            cases.append(("malformed-public-encoding-" + str(len(cases)), changed, proof, False, ELF_PIN))
        corrupted = bytearray(proof)
        corrupted[len(proof)//2] ^= 1
        cases.extend([
            ("corrupted-proof", statement, corrupted, False, ELF_PIN),
            ("truncated-proof", statement, proof[:-1], False, ELF_PIN),
            ("trailing-proof-byte", statement, proof + b"\0", False, ELF_PIN),
            ("wrong-ELF-pin", statement, proof, False, "00" * 32),
        ])
        for case, public, proof_bytes, accepts, pin in cases:
            with tempfile.TemporaryDirectory(prefix="fors-reviewed-public-only-") as temporary:
                directory = Path(temporary)
                public_path = directory / "expected-public.json"
                proof_path = directory / "root.proof"
                public_path.write_text(json.dumps(public))
                proof_path.write_bytes(proof_bytes)
                command = [
                    str(RUNNER), "verify", "--scheme", "fors",
                    "--out", str(directory / "report.json"),
                    "--statement", str(public_path),
                    "--expect-statement-sha256", hashlib.sha256(public_path.read_bytes()).hexdigest(),
                    "--expect-elf-sha256", pin,
                    "--proof", str(proof_path), "--repeat", "1", "--warmup", "0",
                ]
                process = subprocess.run(command, cwd=directory, text=True, capture_output=True)
                passed = (process.returncode == 0) == accepts
                controls.append({
                    "count": count, "case": case, "expected_accept": accepts,
                    "returncode": process.returncode, "passed": passed,
                    "stderr": process.stderr.strip(),
                })
                assert passed, controls[-1]
    result = {
        "runner_sha256": hashlib.sha256(RUNNER.read_bytes()).hexdigest(),
        "elf_sha256": ELF_PIN,
        "passed": all(control["passed"] for control in controls),
        "controls": controls,
        "scope": "Only intended public seed/root/message records and one saved proof are copied into each isolated directory. Changed claims use an independently recomputed Python BLAKE2s output and a fresh trusted statement pin, so they exercise real proof binding rather than a stale cached-output check.",
    }
    Path(__file__).with_name("receipt-controls.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"{len(controls)} FORS saved-proof consumer controls passed")


if __name__ == "__main__":
    main()
