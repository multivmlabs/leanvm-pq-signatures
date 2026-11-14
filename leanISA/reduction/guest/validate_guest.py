#!/usr/bin/env python3
"""Execute the constrained DSL reduction against independent reference vectors.

Small trusted tables are evaluated explicitly inside the test guest, so mutated
claims must fail the reduction plus terminal check, not an oracle-output assert.
Separate positive codec probes also check every reference digest and challenge.
This is execution/constraint evidence; it creates no STARK proof.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def literal(v):
    return "f192(" + ",".join(map(str, v)) + ")"


def halves(text):
    raw = bytes.fromhex(text)
    return [[int.from_bytes(raw[i:i + 8], "little"),
             int.from_bytes(raw[i + 8:i + 16], "little"), 0] for i in (0, 16)]


def source(vector, codec=False):
    n, m = vector["n"], vector["m"]
    poly, context = halves(vector["poly_id_hex"]), halves(vector["context_hex"])
    header = ", ".join(literal(v) for v in poly + context)
    lines = ["", "def main():", f"    points = HeapBuf({n*m})",
             f"    hint_witness(points[0:{n*m}], \"test_points\")",
             f"    values = HeapBuf({m})", f"    hint_witness(values[0:{m}], \"test_values\")",
             f"    point = HeapBuf({n})"]
    if codec:
        initial = halves(vector["instance_digest_hex"])
        lines += [f"    initial = red_instance({header}, points, values, {n}, {m})",
                  f"    assert initial[0] == {literal(initial[0])}",
                  f"    assert initial[1] == {literal(initial[1])}"]
    lines += [f"    terminal = red_reduce_claims({header}, points, values, point, {n}, {m})",
              "    evaluated = 0"]
    for i, value in enumerate(vector["table"]):
        lines.append(f"    term{i} = 1")
        for j in range(n):
            factor = f"point[GEN ** {j}]" if i >> j & 1 else f"(1 + point[GEN ** {j}])"
            lines.append(f"    term{i} = term{i} * {factor}")
        lines.append(f"    evaluated = evaluated + {literal(value)} * term{i}")
    lines.append("    assert terminal == evaluated")
    if codec:
        lines.append(f"    assert terminal == {literal(vector['new_value'])}")
        for j, coordinate in enumerate(vector["new_point"]):
            lines.append(f"    assert point[GEN ** {j}] == {literal(coordinate)}")
    lines += ["    public = GEN ** 0", "    public[1] = 0", "    public[GEN] = 0", "    return", ""]
    return (HERE / "sumcheck.py").read_text() + "\n".join(lines)


def honest(vector, codec=False):
    return {"scheme": "leanisa-reduction-primitive", "source": source(vector, codec),
            "public_input": [[0, 0, 0], [0, 0, 0]], "witness": {
                "test_points": [[coordinate for point in vector["points"] for coordinate in point]],
                "test_values": [vector["values"]],
                "reduce_rounds": [[coefficient for pair in vector["rounds"] for coefficient in pair]],
                "reduce_value": [[vector["new_value"]]]}}


def main():
    vectors_path = HERE.parent / "review/oracle-vectors.json"
    vectors = json.loads(vectors_path.read_text())["vectors"]
    output = HERE / "controls"
    output.mkdir(parents=True, exist_ok=True)
    binary = ROOT / "leanISA/target/release/pq-leanbench"
    results = []
    for index, vector in enumerate(vectors):
        base = honest(vector)
        cases = [("honest", base, True), ("codec", honest(vector, True), True)]
        for name, stream, at, limb in [
                ("round-c0-top", "reduce_rounds", 0, 2),
                ("round-c2-top", "reduce_rounds", 1, 2),
                ("terminal-top", "reduce_value", 0, 2),
                ("input-point-top", "test_points", 0, 2),
                ("input-value-top", "test_values", 0, 2)]:
            altered = copy.deepcopy(base)
            altered["witness"][stream][0][at][limb] ^= 1
            cases.append((name, altered, False))
        if vector["n"] > 1:
            altered = copy.deepcopy(base)
            rounds = altered["witness"]["reduce_rounds"][0]
            rounds[:2], rounds[2:4] = rounds[2:4], rounds[:2]
            cases.append(("round-order", altered, False))
        for name, fixture, expected in cases:
            stem = f"n{vector['n']}-m{vector['m']}-{name}"
            input_path, report_path = output / f"{stem}.input.json", output / f"{stem}.report.json"
            input_path.write_text(json.dumps(fixture) + "\n")
            command = [str(binary), "execute", "--input", str(input_path), "--report", str(report_path)]
            ran = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
            accepted = ran.returncode == 0
            result = {"case": stem, "expected_accept": expected, "accepted": accepted,
                      "passed": accepted == expected, "exit_code": ran.returncode,
                      "source_sha256": hashlib.sha256(fixture["source"].encode()).hexdigest(),
                      "stderr": ran.stderr.strip()}
            if accepted:
                report = json.loads(report_path.read_text())
                result.update(guest_hash=report["guest_hash"], cycles=report["cycles"],
                              opcode_rows=report["opcode_rows"])
            results.append(result)
            if accepted != expected:
                raise RuntimeError(f"Unexpected guest outcome: {result}")
    summary = {"schema": 1, "scope": "Actual DSL execution with explicit trusted-table terminal evaluation; no STARK production",
               "backend_revision": "575df819d9c857f38068cecf7b1640e0ce4bfb29",
               "guest_source_sha256": hashlib.sha256((HERE / "sumcheck.py").read_bytes()).hexdigest(),
               "oracle_vectors_sha256": hashlib.sha256(vectors_path.read_bytes()).hexdigest(),
               "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
               "positive_controls": sum(r["expected_accept"] for r in results),
               "negative_controls": sum(not r["expected_accept"] for r in results),
               "all_passed": all(r["passed"] for r in results), "cases": results}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "cases"}))


if __name__ == "__main__":
    main()
