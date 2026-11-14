#!/usr/bin/env python3
"""Review-only native ASan/UBSan probe of the pinned compact verifier."""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "risc-v/mldsa"
REF = ROOT / "vendor/ETHDILITHIUM/c-ref"


def main():
    record = json.loads((BASE / "fixture-0.json").read_text())
    arrays = []
    for name, field in [("pk", "compact_public_key_hex"), ("sig", "compact_signature_hex"), ("msg", "message_hex")]:
        value = bytes.fromhex(record[field])
        arrays.append(f"unsigned char {name}[{len(value)}] = {{{','.join(map(str, value))}}};")
    code = '#include "sign.h"\n#include "params.h"\n' + '\n'.join(arrays) + '''
int main(void) {
  if (crypto_sign_verify(sig, CRYPTO_BYTES, msg, 32, 0, 0, pk)) return 10;
  for (unsigned i = 0; i < CRYPTO_BYTES; ++i) {
    sig[i] ^= 1;
    int result = crypto_sign_verify(sig, CRYPTO_BYTES, msg, 32, 0, 0, pk);
    sig[i] ^= 1;
    if (!result) return 11;
  }
  for (unsigned i = 0; i < CRYPTO_PUBLICKEYBYTES; ++i) pk[i] = 255;
  if (!crypto_sign_verify(sig, CRYPTO_BYTES, msg, 32, 0, 0, pk)) return 12;
  for (unsigned i = 0; i < CRYPTO_PUBLICKEYBYTES; ++i) pk[i] = 0;
  if (!crypto_sign_verify(sig, CRYPTO_BYTES, msg, 32, 0, 0, pk)) return 13;
  return 0;
}
'''
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "test.c"
        binary = Path(directory) / "test"
        source.write_text(code)
        command = ["clang", "-O1", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                   "-fno-strict-aliasing", "-ffunction-sections", "-fdata-sections", "-Wl,-dead_strip",
                   "-DETHDILITHIUM=0", "-DDILITHIUM_MODE=2",
                   "-I", str(BASE / "c/include"), "-I", str(REF), str(source),
                   str(BASE / "c/adapter.c")]
        command += [str(REF / (name + ".c")) for name in
                    ("sign", "packing", "polyvec", "poly", "ntt", "reduce", "rounding", "fips202", "symmetric-shake")]
        command += ["-o", str(binary)]
        subprocess.run(command, check=True)
        done = subprocess.run([str(binary)], capture_output=True, text=True)
        report = {"scope": "Native C ASan/UBSan verification, not RISC-V or STARK verification",
                  "compiler": subprocess.check_output(["clang", "--version"], text=True).strip(),
                  "source_sha256": hashlib.sha256(code.encode()).hexdigest(),
                  "positive_controls": 1, "negative_controls": 2422,
                  "exit_code": done.returncode, "stdout": done.stdout, "stderr": done.stderr,
                  "passed": done.returncode == 0}
        (ROOT / "risc-v/reviews/mldsa-native-sanitizers.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({k: report[k] for k in ("positive_controls", "negative_controls", "exit_code", "passed")}))
        if done.returncode:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
