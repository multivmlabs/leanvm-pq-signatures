#!/usr/bin/env python3
"""Serial native-Aerie -> full-verifier leanVM proof benchmarks.

The receiver uses only its intended statement, trusted ELF and outer proof.
Native Aerie setup/generation, guest execution, outer proof generation and
receipt verification retain separate timers. No host acceptance bit is used.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
FORMAT = ROOT / "experiments/aerie-wrapper-format/src/lib.rs"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2) + "\n")
    temp.replace(path)


def load(path):
    return json.loads(Path(path).read_text())


def expected_claim(records, statement):
    """Independent Python SHAKE, over fixed source-controlled profile bytes."""
    source = FORMAT.read_text()
    def constant(name):
        match = re.search(r"pub const " + name + r': &\[u8\] = b"([^"]+)";', source)
        if not match:
            raise ValueError("cannot read trusted format constant " + name)
        return ast.literal_eval('b"' + match.group(1) + '"')
    profile, domain = constant("PROFILE"), constant("DOMAIN")
    return hashlib.shake_256(domain + len(profile).to_bytes(4, "little") + profile
        + records.to_bytes(8, "little") + len(statement).to_bytes(8, "little") + statement).digest(32)


def run(command, log, timeout=3600, threads=12):
    log = Path(log)
    log.parent.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter()
    with log.open("w") as stream:
        process = subprocess.run([str(v) for v in command], cwd=ROOT,
            env={**os.environ, "RAYON_NUM_THREADS": str(threads)}, stdout=stream,
            stderr=subprocess.STDOUT, timeout=timeout)
    return process.returncode, time.perf_counter() - start


def paths(args, records):
    return args.inputs / f"n{records}", args.out / f"n{records}", args.proofs / f"n{records}"


def prepare(args, records):
    directory, reports, _ = paths(args, records)
    fixtures = list(args.fixtures.glob(f"*falcon512-{records}-*.bin"))
    if len(fixtures) != 1:
        raise ValueError(f"expected one exact native fixture for N={records}, got {fixtures}")
    fixture = fixtures[0]
    integrity = directory / "integrity.json"
    expected = {"fixture_sha256": sha(fixture), "producer_sha256": sha(args.producer),
        "format_source_sha256": sha(FORMAT), "repeat": args.repeat, "warmup": args.warmup,
        "controls_prepared": records == args.controls_at}
    if integrity.exists() and (directory / "metadata.json").exists():
        old = load(integrity)
        if all(old.get(k) == v for k, v in expected.items()) and all(
                Path(p).is_file() and sha(p) == h for p, h in old.get("input_sha256", {}).items()):
            save(reports / "inputs.json", old)
            return load(directory / "metadata.json")
    command = [args.producer, fixture, directory, "--repeat", args.repeat, "--warmup", args.warmup]
    if records != args.controls_at:
        command.append("--no-controls")
    code, wall = run(command, reports / "native-producer.log", args.timeout, args.threads)
    if code:
        raise RuntimeError(f"native producer failed N={records}; see {reports}")
    metadata = load(directory / "metadata.json")
    statement = (directory / "statement.bin").read_bytes()
    if metadata["records"] != records or metadata["claim_digest_hex"] != expected_claim(records, statement).hex():
        raise RuntimeError("native output differs from independent intended-claim digest")
    files = [directory / "statement.bin", directory / "claim-digest.bin", directory / "metadata.json"]
    for i in range(args.repeat):
        files.extend([directory / f"sample-{i}/input.frame", directory / f"sample-{i}/aggregate.aerie"])
    if records == args.controls_at:
        files.append(directory / "controls.json")
        files.extend(p for p in (directory / "controls").glob("*") if p.is_file())
    generated={**expected, "native_process_wall_s": wall,
        "command": [str(v) for v in command], "input_sha256": {str(p): sha(p) for p in files},
        "scope": "Actual native Aerie proofs; no guest or outer STARK is implied by preparation"}
    save(integrity, generated)
    save(reports / "inputs.json", generated)
    return metadata


def host(args, mode, frame=None, proof=None, statement=None, records=None, report=None, repeat=1, warmup=0, raw_negative=False, nonzero_padding=False, profile_counts=False):
    report=Path(report)
    if report.exists():
        report.unlink()  # A failed child must never inherit a previous successful report.
    command = [args.host, mode, "--elf", args.elf, "--expect-elf-sha256", sha(args.elf),
        "--report", report, "--repeat", repeat, "--warmup", warmup, "--threads", args.threads]
    if frame is not None:
        command += ["--input", frame]
    if proof is not None:
        command += ["--proof", proof]
    if statement is not None:
        command += ["--statement", statement, "--records", records]
    if args.zk:
        command.append("--zk")
    if raw_negative:
        command.append("--raw-negative-input")
    if nonzero_padding:
        command.append("--nonzero-advice-padding")
    if profile_counts:
        command.append("--profile-counts")
    code, wall = run(command, Path(report).with_suffix(".log"), args.timeout, args.threads)
    data = load(report) if Path(report).exists() else {"status": "error", "error_kind": "no_report", "exit_code": code}
    data["orchestrator_process_wall_s"] = wall
    data["command"] = [str(v) for v in command]
    save(report, data)
    return code, data


def capacity_failure(report):
    return report.get("error_kind") in ("leanvm_capacity", "advice_capacity")


def record_failure(args, records, expected, failure, label):
    directory,reports,_=paths(args,records)
    capacity=capacity_failure(failure)
    report={"status":"measured_capacity_failure" if capacity else label,
        **expected,"records":records,"failure":failure,"outer_proof_generated":False}
    metadata_path=directory/"metadata.json"
    if metadata_path.exists():
        native=load(metadata_path)
        report.update({"padded_records":native["padded_records"],
            "inner_setup_s":native["inner_setup_s"],
            "inner_prove_median_s":native["inner_prove_median_s"],
            "native_samples":native["samples"],
            "canonical_statement_bytes":native["canonical_statement_bytes"],
            "public_claim_digest_hex":native["claim_digest_hex"],
            "native_metadata_sha256":sha(metadata_path)})
    if capacity:
        # An actual failed Prover call is distinct from a count-only refusal.
        code,attempt=host(args,"prove",frame=directory/"sample-0/input.frame",
            proof=paths(args,records)[2]/"capacity-attempt.proof",report=reports/"capacity-prover-attempt.json")
        if code==0 or not capacity_failure(attempt):
            raise RuntimeError(f"count/prover capacity disagreement N={records}: {attempt}")
        report["failed_outer_prover_attempt"]=attempt
        for i in range(args.warmup):
            code,warm=host(args,"interpret",frame=directory/"sample-0/input.frame",
                report=reports/f"interpreter-warmup-{i}.json")
            if code or not warm.get("public_output_checked"):
                raise RuntimeError(f"honest interpreter warmup failed N={records}: {warm}")
        interpreted_samples=[]
        for i in range(args.repeat):
            code,interpreted=host(args,"interpret",frame=directory/f"sample-{i}/input.frame",
                report=reports/f"sample-{i}.interpretation.json")
            if code or interpreted.get("status")!="ok" or not interpreted.get("public_output_checked"):
                raise RuntimeError(f"honest complete interpretation failed N={records}: {interpreted}")
            interpreted_samples.append(interpreted)
        report["complete_guest_interpretation"]=interpreted_samples[0]
        report["complete_guest_interpretations"]=interpreted_samples
        report["interpreter_median_s"]=statistics.median(x["interpret_samples_s"][0] for x in interpreted_samples)
        report["interpreter_instruction_samples"]=[x["interpreter_instructions"] for x in interpreted_samples]
        report["scope"]="Full guest execution and output checked for every native input. Actual outer Prover refuses commitment capacity. No successful outer proving time, proof size, or receipt verification is inferred."
        artifacts=[reports/"inputs.json",reports/"execution.json",reports/"capacity-prover-attempt.json"]
        artifacts.extend(reports/f"sample-{i}.interpretation.json" for i in range(args.repeat))
        report["artifact_sha256"]={str(p):sha(p) for p in artifacts}
    save(reports/"summary.json",report)
    return capacity


def verify_case(args, records):
    directory, reports, proofs = paths(args, records)
    for i in range(args.repeat):
        code, result = host(args, "verify", proof=proofs / f"sample-{i}.proof",
            statement=directory / "statement.bin", records=records,
            report=reports / f"sample-{i}.fresh-verification.json", repeat=args.repeat, warmup=args.warmup)
        if code or result.get("status") != "ok" or not result.get("public_output_checked"):
            raise RuntimeError(f"fresh outer verification failed N={records} sample={i}")


def prove_case(args, records):
    directory, reports, proofs = paths(args, records)
    metadata = prepare(args, records)
    summary_path = reports / "summary.json"
    expected = {"elf_sha256": sha(args.elf), "outer_host_sha256": sha(args.host),
        "native_inputs_integrity_sha256": sha(reports / "inputs.json"),
        "requested_zero_knowledge": args.zk, "repeat": args.repeat, "warmup": args.warmup}
    if summary_path.exists():
        old = load(summary_path)
        if old.get("status") == "complete" and all(old.get(k) == v for k,v in expected.items()) and all(
                Path(p).is_file() and sha(p) == h for p,h in old.get("artifact_sha256", {}).items()):
            print(f"N={records}: compatible completed native/outer/fresh verification reports", flush=True)
            return
    code, execution = host(args, "execute", frame=directory / "sample-0/input.frame",
        report=reports / "execution.json")
    if code:
        if not record_failure(args,records,expected,execution,"honest_execution_failure"):
            raise RuntimeError(f"honest complete verifier execution failed N={records}; see {reports}")
        print(f"N={records}: measured execute capacity failure", flush=True)
        return
    # Warmups are actual outer proofs, excluded from the measured sample table.
    for i in range(args.warmup):
        code, result = host(args, "prove", frame=directory / "sample-0/input.frame",
            proof=proofs / f"warmup-{i}.proof", report=reports / f"warmup-{i}.json")
        if code:
            if not record_failure(args,records,expected,result,"honest_proof_failure"):
                raise RuntimeError(f"honest outer proof failed N={records}")
            return
    samples = []
    for i in range(args.repeat):
        code, result = host(args, "prove", frame=directory / f"sample-{i}/input.frame",
            proof=proofs / f"sample-{i}.proof", report=reports / f"sample-{i}.json")
        if code or result.get("status") != "ok" or not result.get("public_output_checked"):
            if not record_failure(args,records,expected,result,"honest_proof_failure"):
                raise RuntimeError(f"honest outer proof failed N={records} sample={i}")
            return
        inner = metadata["samples"][i]
        outer_s = result["prove_samples_s"][0]
        samples.append({"sample":i,"inner_prove_s":inner["inner_prove_s"],
            "outer_prove_s":outer_s,"sum_prover_stage_work_s":inner["inner_prove_s"]+outer_s,
            "inner_proof_bytes":inner["inner_proof_bytes"],"outer_proof_bytes":result["proof_bytes"],
            "cycles":result["stats"]["cycles"],"peak_rss_bytes":result["peak_rss_bytes"]})
    verify_case(args, records)
    artifacts = [directory / "statement.bin", reports / "inputs.json", reports / "execution.json"]
    for i in range(args.repeat):
        artifacts.extend([reports / f"sample-{i}.json", reports / f"sample-{i}.fresh-verification.json", proofs / f"sample-{i}.proof"])
    save(summary_path, {"status":"complete",**expected,"records":records,"padded_records":metadata["padded_records"],
        "public_claim_digest_hex":metadata["claim_digest_hex"],"inner_setup_s":metadata["inner_setup_s"],
        "canonical_statement_bytes":metadata["canonical_statement_bytes"],"samples":samples,
        "inner_prove_median_s":statistics.median(x["inner_prove_s"] for x in samples),
        "outer_prove_median_s":statistics.median(x["outer_prove_s"] for x in samples),
        "sum_prover_stage_work_median_s":statistics.median(x["sum_prover_stage_work_s"] for x in samples),
        "outer_proof_bytes_median":statistics.median(x["outer_proof_bytes"] for x in samples),
        "artifact_sha256":{str(p):sha(p) for p in artifacts},
        "scope":"Matched native and outer proof samples from actual complete verifier inputs. Sum is measured stage work, not distributed latency. Outer verifier receives only intended statement, count, trusted ELF and outer proof."})
    print(f"N={records}: complete full-verifier outer proofs and fresh public-only verification",flush=True)


def controls(args, records, receipt_available=True):
    directory, reports, proofs = paths(args, records)
    prepare(args, records)
    native = load(directory / "controls.json")
    observed=[]
    for case in native["controls"]:
        raw=case.get("format_rejected",False)
        code, result = host(args,"interpret",frame=directory / case["path"],
            report=reports / "controls" / (case["name"]+".json"),raw_negative=raw)
        assert not capacity_failure(result), "capacity rejection cannot validate a guest rejection predicate"
        actual=code==0 and result.get("status")=="ok"
        assert actual==case["expected_guest_accept"],(case["name"],result)
        if actual and case["name"]=="valid-other-claims":
            alternate=(directory/"controls/valid-other-claims.statement.bin").read_bytes()
            assert result.get("public_output_checked") is True
            assert result["public_claim_digest_hex"]==expected_claim(records,alternate).hex()
            assert result["public_claim_digest_hex"]!=expected_claim(records,(directory/"statement.bin").read_bytes()).hex()
        if not actual:
            assert result.get("error_kind")=="guest_trap", "only an actual guest trap validates this rejection control"
        observed.append({"name":case["name"],"guest_accepted":actual,"expected_guest_accept":case["expected_guest_accept"],
            "raw_negative_input":raw,"error_kind":result.get("error_kind")})
        if case["name"]=="valid-other-claims" and receipt_available:
            proof=proofs / "valid-other-claims.proof"
            code,p=host(args,"prove",frame=directory / case["path"],proof=proof,
                report=reports / "controls/valid-other-claims.proof.json")
            assert code==0 and p["status"]=="ok"
            code,v=host(args,"verify",proof=proof,statement=directory / "statement.bin",records=records,
                report=reports / "controls/valid-other-claims.original-claim.json")
            assert code!=0 and v["status"]=="error","wrong intended statement must reject outer proof"
            assert v.get("proof_sha256")==sha(proof),"receipt must actually reach the verifier"
            code,v=host(args,"verify",proof=proof,statement=directory / "controls/valid-other-claims.statement.bin",records=records,
                report=reports / "controls/valid-other-claims.actual-claim.json")
            assert code==0 and v["status"]=="ok","same proof must verify under its actual alternate statement"
            observed[-1]["actual_claim_receipt_verified"]=True
            observed[-1]["original_claim_receipt_rejected"]=True
    alternate_path=directory/"controls/valid-other-claims.statement.bin"
    if alternate_path.exists():
        alternate=alternate_path.read_bytes()
        original_proof=(directory/"sample-0/aggregate.aerie").read_bytes()
        frame=b"AERLVM01"+b"".join(v.to_bytes(8,"little") for v in (records,len(alternate),len(original_proof)))+alternate+original_proof
        order_path=directory/"controls/changed-record-order.frame"
        order_path.write_bytes(frame)
        code,result=host(args,"interpret",frame=order_path,report=reports/"controls/changed-record-order.json")
        assert code!=0 and result.get("error_kind")=="guest_trap", "changed order with original proof must trap in guest"
        observed.append({"name":"changed-record-order","guest_accepted":False,"expected_guest_accept":False,
            "error_kind":result["error_kind"],"frame_sha256":sha(order_path)})
    positive_frame=directory/"sample-0/input.frame"
    if positive_frame.stat().st_size%8:
        code,result=host(args,"interpret",frame=positive_frame,
            report=reports/"controls/nonzero-advice-padding.json",nonzero_padding=True)
        assert code!=0 and result.get("error_kind")=="guest_trap", "nonzero transport padding must trap in unchanged guest"
        observed.append({"name":"nonzero-advice-padding","guest_accepted":False,
            "expected_guest_accept":False,"error_kind":result["error_kind"]})
    if not receipt_available:
        save(reports/"controls/summary.json",{"status":"guest_controls_complete_receipts_unavailable",
            "records":records,"elf_sha256":sha(args.elf),"cases":observed,"receipt_controls":[],
            "reason":"Actual full guest execution/rejection controls completed. No full outer proof fits this backend, so Aerie receipt verification controls cannot run. Host/backend synthetic-proof tests are separate evidence.",
            "scope":"Actual reference guest execution, not a STARK or native prevalidation alone."})
        return
    # Even N=1 must bind the actual receiver's intended statement and count.
    intended = bytearray((directory / "statement.bin").read_bytes())
    intended[-1] ^= 1  # Raw message bytes have no restricted alphabet.
    wrong_statement = directory / "controls/wrong-receiver-statement.bin"
    wrong_statement.write_bytes(intended)
    receipt_controls=[]
    for label, statement, count in (("changed-receiver-message",wrong_statement,records),
                                    ("changed-receiver-count",directory / "statement.bin",records+1)):
        code,v=host(args,"verify",proof=proofs / "sample-0.proof",statement=statement,records=count,
            report=reports / "controls" / (label+".json"))
        assert code!=0 and v["status"]=="error", "wrong receiver statement must reject the genuine outer proof"
        assert v.get("proof_sha256")==sha(proofs / "sample-0.proof"),"receipt must actually reach the verifier"
        receipt_controls.append({"name":label,"rejected":True,"error_kind":v.get("error_kind")})
    tampered=bytearray((proofs / "sample-0.proof").read_bytes());tampered[len(tampered)//2]^=1
    tampered_path=proofs / "changed-outer.proof";tampered_path.write_bytes(tampered)
    code,v=host(args,"verify",proof=tampered_path,statement=directory / "statement.bin",records=records,
        report=reports / "controls/changed-outer-proof.json")
    assert code!=0 and v["status"]=="error", "tampered outer proof must reject"
    assert v.get("proof_sha256")==sha(tampered_path),"tampered receipt must actually reach the verifier"
    receipt_controls.append({"name":"changed-outer-proof","rejected":True,"error_kind":v.get("error_kind")})
    save(reports / "controls/summary.json",{"status":"complete","records":records,"elf_sha256":sha(args.elf),
        "cases":observed,"receipt_controls":receipt_controls,
        "scope":"Actual complete guest execution and public-receipt binding controls, not only native prevalidation."})


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=("prepare","execute","prove","verify","controls","all"))
    parser.add_argument("--counts",nargs="+",type=int,default=[1,10,30,70,100])
    parser.add_argument("--producer",type=Path,default=ROOT/".cache/aerie-target/release/aerie-wrapper-inputs")
    parser.add_argument("--host",type=Path)
    parser.add_argument("--elf",type=Path)
    parser.add_argument("--fixtures",type=Path,default=ROOT/"artifacts/aerie/honest-fixtures")
    parser.add_argument("--inputs",type=Path,default=ROOT/"artifacts/aerie-wrapper/inputs")
    parser.add_argument("--out",type=Path,default=ROOT/"results/aerie-wrapper")
    parser.add_argument("--proofs",type=Path,default=ROOT/"artifacts/aerie-wrapper/proofs")
    parser.add_argument("--repeat",type=int,default=3);parser.add_argument("--warmup",type=int,default=1)
    parser.add_argument("--threads",type=int,default=12);parser.add_argument("--timeout",type=int,default=3600)
    parser.add_argument("--controls-at",type=int,default=10);parser.add_argument("--zk",action="store_true")
    args=parser.parse_args()
    if any(n<1 or n>65536 for n in args.counts) or args.repeat<1 or args.warmup<0 or args.threads<1:
        parser.error("unsupported count/repetition/thread settings")
    if args.action!="prepare" and (args.host is None or args.elf is None):parser.error("outer actions require --host and --elf")
    mode="zk" if args.zk else "non-zk";args.out=args.out/mode;args.proofs=args.proofs/mode
    for n in args.counts:
        if args.action=="prepare":prepare(args,n)
        elif args.action=="execute":
            prepare(args,n);directory,reports,_=paths(args,n)
            code,result=host(args,"execute",frame=directory/"sample-0/input.frame",report=reports/"execution.json")
            print(json.dumps({"records":n,"status":result["status"],"exit_code":code}),flush=True)
        elif args.action in ("prove","all"):prove_case(args,n)
        elif args.action=="verify":verify_case(args,n)
    if args.action in ("controls","all"):
        if args.controls_at not in args.counts:parser.error("--controls-at must be in selected counts")
        _,reports,_=paths(args,args.controls_at)
        summary=reports/"summary.json"
        controls(args,args.controls_at,receipt_available=summary.exists() and load(summary).get("status")=="complete")


if __name__=="__main__":main()
