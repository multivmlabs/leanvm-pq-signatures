#!/usr/bin/env python3
"""Render mine.md figures from verified RISC-V lattice and leanISA FORS reports.

This script never runs a prover or invents unmeasured tree results. Original
reports and figures are read only. All output goes to results/mine/figures.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parents[2]
RV_PIN = "06e5c9cd6981103786f9d0a17324241b559a50d3"
ISA_PIN = "575df819d9c857f38068cecf7b1640e0ce4bfb29"
RV_GUESTS = {
    "falcon": "421470c0aef38d3b2c2ca392edd7786c7425085f6a430b0286a679c69f0f9a4c",
    "mldsa": "73fa19d855adbd0ad6d8368260b5e1b173cc57a854e52624dd1b8e65d95f69d6",
}
CAP = 2**28
COUNTS = (10, 30, 70, 100)
SOURCES = {}


def read(path):
    raw = path.read_bytes()
    SOURCES[str(path.relative_to(ROOT))] = hashlib.sha256(raw).hexdigest()
    return json.loads(raw)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def stats(row, name, values):
    values = [float(value) for value in values]
    require(bool(values), f"No samples for {name}")
    center = statistics.median(values)
    row[name] = center
    row[name + "_min"] = min(values)
    row[name + "_max"] = max(values)
    row[name + "_error_minus"] = center - min(values)
    row[name + "_error_plus"] = max(values) - center


def measurements(scheme, count, proof_sizes, proves, verifies, rss, words, cycles):
    require(len(proves) == len(verifies) == len(proof_sizes) == 3,
            f"Expected three samples: {scheme} {count}")
    row = {"scheme": scheme, "count": count,
           "proof_kib": statistics.median(proof_sizes) / 1024,
           "rss_gib": rss / 2**30,
           "committed_words": words, "capacity_percent": 100 * words / CAP,
           "cycles": cycles}
    stats(row, "prove_s", proves)
    stats(row, "verify_ms", [1000 * value for value in verifies])
    stats(row, "prove_per_signature_ms", [1000 * value / count for value in proves])
    # Column names used by the existing LaTeX renderer.
    for name, unit in (("prove", "s"), ("verify", "ms"), ("prove_per_signature", "ms")):
        for end in ("minus", "plus"):
            row[f"{name}_error_{end}_{unit}"] = row[f"{name}_{unit}_error_{end}"]
    return row


def direct():
    rows = []
    for scheme in ("falcon", "mldsa"):
        guest_hashes = set()
        for path in sorted((ROOT / "risc-v/results/direct").glob(f"{scheme}-*.json")):
            report = read(path)
            if report.get("status") != "accepted":
                continue
            require(report.get("action") == "prove" and report.get("verified") is True,
                    f"Not an accepted verified proof: {path}")
            require(report["leanvm_revision"] == RV_PIN and report["scheme"] == scheme,
                    f"Unexpected backend or scheme: {path}")
            require(report["elf_sha256"] == RV_GUESTS[scheme], f"Changed baseline guest: {path}")
            require(report["threads"] == 8 and report["log_inverse_rate"] == 1
                    and report["warmup"] == 1, f"Mixed RISC-V settings: {path}")
            count = report["count"]
            require(path.name == f"{scheme}-{count}.json", f"Count mismatch: {path}")
            guest_hashes.add(report["elf_sha256"])
            statement_path = ROOT / f"risc-v/artifacts/{scheme}-{count}.proof.statement.json"
            statement_raw = statement_path.read_bytes()
            require(hashlib.sha256(statement_raw).hexdigest() == report["statement_sha256"],
                    f"Public statement digest mismatch: {path}")
            statement = read(statement_path)
            require(statement["scheme"] == scheme and statement["count"] == count
                    and statement["elf_sha256"] == report["elf_sha256"],
                    f"Public statement identity mismatch: {path}")
            proof = ROOT / f"risc-v/artifacts/{scheme}-{count}.proof"
            require(proof.stat().st_size == report["proof_bytes"], f"Proof size mismatch: {path}")
            rows.append(measurements(scheme, count, report["proof_bytes_samples"],
                         report["prove_s"], report["verify_s"], report["peak_rss_bytes"],
                         report["execution"]["committed_words"], report["execution"]["cycles"]))
        require(len(guest_hashes) == 1, f"Mixed guest programs for {scheme}")
    for count in (*range(1, 31), 70, 100):
        path = ROOT / f"leanISA/results/article/direct/fors-{count}.json"
        report, verifier = read(path), read(path.with_name(f"fors-{count}.verify.json"))
        require(report.get("action") == "prove" and report.get("verified") is True
                and verifier.get("verified") is True and verifier.get("statement_pinned") is True,
                f"Missing verified, pinned public receiver: {path}")
        require(report["leanvm_revision"] == verifier["leanvm_revision"] == ISA_PIN,
                f"Unexpected leanISA pin: {path}")
        require(report["metadata"]["count"] == count
                and report["metadata"]["parameters"] == {"n": 32, "k": 16, "a": 8}
                and report["scheme"] == "fors-keccak-research", f"Wrong FORS profile: {path}")
        require(report["guest_hash"] == verifier["guest_hash"]
                and report["public_input_hex"] == verifier["public_input_hex"]
                and report["proof_bytes"] == verifier["proof_bytes"], f"Receiver mismatch: {path}")
        require(report["warmup_passes"] == 1 and report["log_inv_rate"] == 1
                and report["threads_env"] is None, f"Mixed FORS settings: {path}")
        rows.append(measurements("fors", count, report["proof_bytes_samples"],
                    report["prove_s"], verifier["verify_cached_s"],
                    report["process_peak_rss_bytes"], report["committed_cells"], report["cycles"]))
    return sorted(rows, key=lambda row: (("falcon", "mldsa", "fors").index(row["scheme"]), row["count"]))


def trees():
    environment = read(ROOT / "leanISA/results/article/environment.json")
    require(environment["upstream"]["leanVM"]["rev"] == ISA_PIN,
            "Unexpected backend pin for archived FORS tree runs")
    rows, samples = [], []
    for count in COUNTS:
        selected = []
        for sample in range(3):
            path = ROOT / f"leanISA/results/article/trees/fors-{count}-b4/sample-{sample}.json"
            report = read(path)
            verification = read(path.with_name(f"sample-{sample}.fresh-verification.json"))
            require(report["scheme"] == "fors" and report["signatures"] == count
                    and report["fan_in"] == 4 and report["leaf_capacity"] == 5
                    and report["rate"] == 1 and report["leaf_reuse_count"] == 0
                    and report["merge_reuse_count"] == 0 and len(report["merge_passes"]) == 1,
                    f"Not the fresh FORS main-tree workload: {path}")
            require(verification.get("verified") is True
                    and verification.get("statement_pinned") is True
                    and verification.get("verification_uses_child_proofs") is False
                    and verification.get("verification_uses_signatures") is False,
                    f"Missing complete public-only verification: {path}")
            for field in ("plan_hash", "root_guest_hash"):
                require(report[field] == verification[field], f"Tree identity mismatch: {path}")
            require(report["edge_count"] == verification["deferred_edge_count"],
                    f"Deferred edge count mismatch: {path}")
            leaves = report["leaf_reports"]
            require(len(leaves) == report["leaf_count"] and all(not leaf["reused"] for leaf in leaves),
                    f"Reused or missing leaves: {path}")
            merge_nodes = report["merge_passes"][0]["nodes"]
            require(len(merge_nodes) == report["merge_count"], f"Missing merge nodes: {path}")
            evaluation = statistics.median(verification["deferred_evaluation_s"])
            core_cold = statistics.median(verification["root_core_verify_cold_s"])
            core_cached = statistics.median(verification["root_core_verify_cached_s"])
            selected.append({"count": count, "sample": sample,
                "prove_s": sum(leaf["prove_s"] for leaf in leaves) + sum(node["prove_s"] for node in merge_nodes),
                "proof_kib": verification["aggregate_wire_bytes"] / 1024,
                "core_kib": verification["root_core_proof_bytes"] / 1024,
                "auxiliary_kib": (verification["aggregate_wire_bytes"] - verification["root_core_proof_bytes"]) / 1024,
                "verify_cold_ms": 1000 * (verification["compile_plan_s"] + verification["deferred_bytecode_prepare_s"] + evaluation + core_cold),
                "verify_cached_ms": 1000 * (evaluation + core_cached),
                "claim_ms": 1000 * verification["public_claim_derivation_s"],
                "rss_gib": report["process_peak_rss_bytes"] / 2**30,
                "leaf_count": report["leaf_count"], "merge_count": report["merge_count"],
                "edge_count": report["edge_count"]})
        samples.extend(selected)
        row = {"count": count}
        for field in selected[0]:
            if field not in ("count", "sample"):
                stats(row, field, [entry[field] for entry in selected])
        rows.append(row)
    return rows, samples


def riscv_trees(schemes=("falcon", "mldsa"), counts=COUNTS):
    """Read fresh RISC-V pipelines and their independent public-only receivers."""
    rows, samples = [], []
    for scheme in schemes:
        for count in counts:
            directory = ROOT / f"risc-v/results/trees/{scheme}-{count}"
            leaf_size = 10 if scheme == "falcon" else 2
            statement_path = directory / "statement.json"
            statement = read(statement_path)
            statement_hash = SOURCES[str(statement_path.relative_to(ROOT))]
            require(statement["backend_revision"] == RV_PIN
                    and statement["scheme"] == scheme and statement["signatures"] == count
                    and statement["elf_sha256"] == RV_GUESTS[scheme]
                    and statement["leaf_size"] == leaf_size
                    and statement["arity_0"] == statement["arity"] == 2
                    and statement["log_inverse_rate"] == 1,
                    f"Unexpected trusted tree statement: {statement_path}")
            actual = count // leaf_size
            slots = max(2, 1 << (actual - 1).bit_length())
            require(statement["actual_leaves"] == actual and statement["leaf_slots"] == slots
                    and len(statement["public_records"]) == count
                    and len(statement["expected_leaf_outputs"]) == actual,
                    f"Wrong distinct-count or padding configuration: {statement_path}")
            keys = [record["public_key"] for record in statement["public_records"]]
            require(len(set(keys)) == count, f"Repeated signers in intended public claims: {statement_path}")
            selected = []
            for sample in range(3):
                run = directory / f"sample-{sample}"
                report, verifier = read(run / "report.json"), read(run / "verification.json")
                require(report.get("action") == "prove" and report.get("status") == "accepted"
                        and report.get("verified") is True and report.get("all_folded_claims_settled") is True,
                        f"Missing complete accepted RISC-V tree: {run}")
                require(verifier.get("action") == "verify" and verifier.get("verified") is True
                        and verifier.get("statement_pinned") is True
                        and verifier.get("all_folded_claims_settled") is True
                        and verifier.get("verification_uses_child_proofs") is False
                        and verifier.get("verification_uses_signatures") is False,
                        f"Missing complete public-only tree receiver: {run}")
                for item in (report, verifier):
                    require(item["backend_revision"] == RV_PIN and item["scheme"] == scheme
                            and item["signatures"] == count and item["actual_leaves"] == actual
                            and item["leaf_slots"] == slots
                            and item["elf_sha256"] == statement["elf_sha256"]
                            and item["statement_sha256"] == statement_hash,
                            f"Producer/receiver statement identity mismatch: {run}")
                require(report["leaf_size"] == leaf_size and report["padding_slots"] == slots - actual
                        and report["arity_0"] == report["arity"] == 2
                        and report["log_inverse_rate"] == 1
                        and report["threads_requested"] == verifier["threads_requested"] == 8,
                        f"Mixed RISC-V tree settings: {run}")
                leaves, merges = report["leaf_reports"], report["merge_reports"]
                require(len(leaves) == actual and len(merges) == report["merge_count"] == slots - 1
                        and all(leaf["signatures"] == leaf_size for leaf in leaves),
                        f"Missing real leaves or charged merge work: {run}")
                work = sum(leaf["prove_s"] for leaf in leaves) + sum(node["prove_s"] for node in merges)
                require(abs(work - report["total_prove_s"]) < 1e-8,
                        f"Proving-work accounting mismatch: {run}")
                proof_path = run / "root.proof"
                proof = proof_path.read_bytes()
                require(hashlib.sha256(proof).hexdigest() == report["root_proof_sha256"]
                        == verifier["root_proof_sha256"]
                        and len(proof) == report["root_proof_bytes"] == verifier["root_proof_bytes"],
                        f"Root proof identity mismatch: {run}")
                SOURCES[str(proof_path.relative_to(ROOT))] = report["root_proof_sha256"]
                prepared = verifier["prepared_complete_verify_s"]
                require(len(prepared) == 3, f"Missing prepared verification samples: {run}")
                cold = verifier["program_load_s"] + verifier["tree_setup_s"] + verifier["first_complete_verify_s"]
                require(abs(cold - verifier["cold_complete_verify_s"]) < 1e-8,
                        f"Incomplete cold verification accounting: {run}")
                selected.append({"scheme": scheme, "backend": "RISC-V", "count": count, "sample": sample,
                    "prove_s": work, "proof_kib": len(proof) / 1024,
                    "core_kib": len(proof) / 1024, "auxiliary_kib": 0,
                    "verify_cold_ms": 1000 * cold,
                    "verify_cached_ms": 1000 * statistics.median(prepared),
                    "claim_ms": 1000 * verifier["public_claim_derivation_s"],
                    "rss_gib": report["peak_rss_bytes"] / 2**30,
                    "leaf_size": leaf_size, "leaf_count": actual, "leaf_slots": slots, "padding_slots": slots - actual,
                    "merge_count": len(merges), "edge_count": 2 * (slots - 1)})
            samples.extend(selected)
            row = {"scheme": scheme, "backend": "RISC-V", "count": count}
            for field in selected[0]:
                if field not in ("scheme", "backend", "count", "sample"):
                    stats(row, field, [entry[field] for entry in selected])
            rows.append(row)
    return rows, samples


def write_csv(path, rows):
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(dict.fromkeys(key for row in rows for key in row)))
        writer.writeheader()
        writer.writerows(rows)


def tree_tex(verification=False):
    if verification:
        panels = [("verify_cold_ms", "Complete tree verification (ms)", "Cold setup", "tree.csv", "FORS, cold", "mldsaorange"),
                  ("verify_cached_ms", "Complete tree verification (ms)", "Prepared programs and tables", "tree.csv", "FORS, prepared", "forsgreen")]
    else:
        panels = [("prove_s", "Proving work (s)", "Fresh leaves and merges", "tree.csv", "FORS tree", "forsgreen"),
                  ("proof_kib", "Proof size (KiB)", "Root STARK plus auxiliary data", "tree.csv", "FORS tree", "forsgreen")]
    axes = []
    for index, (field, ylabel, title, file, label, color) in enumerate(panels):
        axes.append(r"\begin{axis}[" + f"at={{({index * 8.6}cm,0cm)}},width=7.1cm,height=5.3cm,"
                    + f"title={{{title}}},ylabel={{{ylabel}}},"
                    + r"xlabel={Signatures in the tree},xmin=5,xmax=105,xtick={10,30,70,100},ymin=0,grid=major,grid style={gray!15},"
                    + r"axis line style={gray!65},tick style={gray!65},line width=0.9pt,tick label style={font=\small},"
                    + r"label style={font=\small},title style={font=\small},scaled y ticks=false,"
                    + r"legend style={font=\small,draw=none,fill=none,at={(0.5,1.15)},anchor=south,legend columns=-1},legend cell align=left]")
        error = "" if field == "proof_kib" else r",error bars/.cd,y dir=both,y explicit,error bar style={line width=0.65pt},error mark options={rotate=90,mark size=2pt}"
        columns = f"x=count,y={field},col sep=comma"
        if error:
            columns += f",y error minus={field}_error_minus,y error plus={field}_error_plus"
        axes.append(f"\\addplot+[color={color},mark=triangle*,mark size=2.1pt{error}] table[{columns}] {{{file}}};")
        axes.append(f"\\addlegendentry{{{label}}}")
        if not verification:
            direct_columns = f"x=count,y={field},col sep=comma"
            if error:
                direct_columns += f",y error minus={field}_error_minus,y error plus={field}_error_plus"
            axes.append(f"\\addplot+[color=falconblue,dashed,mark=*,mark size=2.1pt{error}] table[{direct_columns}] {{fors-matched.csv}};")
            axes.append(r"\addlegendentry{FORS direct batch}")
        axes.append(r"\end{axis}")
    return r"""\documentclass[tikz,border=5pt]{standalone}
\usepackage{pgfplots}
\pgfplotsset{compat=1.18}
\definecolor{falconblue}{HTML}{0072B2}
\definecolor{mldsaorange}{HTML}{D55E00}
\definecolor{forsgreen}{HTML}{009E73}
\begin{document}
\begin{tikzpicture}
AXES
\end{tikzpicture}
\end{document}
""".replace("AXES", "\n".join(axes))


def recursive_tree_tex(rows, verification=False):
    """Comparable plot quantities, with the differing proof protocols documented."""
    panels = [("verify_cold_ms", "Complete verification (ms)", "Including program setup"),
              ("verify_cached_ms", "Complete verification (ms)", "Prepared programs and tables")] if verification else [
              ("prove_s", "Proving work (s)", "Fresh leaves and merges"),
              ("proof_kib", "Complete aggregate (KiB)", "Serialized aggregate proof")]
    labels = (("falcon", "Falcon-512 (RISC-V)", "falconblue", "*"),
              ("mldsa", "ML-DSA-44 (RISC-V)", "mldsaorange", "square"),
              ("fors", "FORS (leanISA + Keccak)", "forsgreen", "triangle*"))
    axes = []
    for index, (field, ylabel, title) in enumerate(panels):
        if field == "proof_kib":
            scale = "ymin=0,"
        else:
            minimum = min(row[field + "_min"] for row in rows)
            require(minimum > 0, "Nonpositive recursive timing")
            scale = f"ymode=log,log basis y=10,ymin={minimum * 0.75:.12g},"
            if field == "verify_cold_ms":
                scale += "ytick={50,100,200,500,1000},yticklabels={50,100,200,500,1000},"
            elif field == "verify_cached_ms":
                scale += "ytick={1,2,5,10,20,50},yticklabels={1,2,5,10,20,50},"
        axes.append(r"\begin{axis}[" + f"at={{({index * 8.6}cm,0cm)}},width=7.1cm,height=5.3cm,"
                    + f"title={{{title}}},ylabel={{{ylabel}}},{scale}"
                    + r"xlabel={Distinct signatures},xmin=5,xmax=105,xtick={10,30,70,100},grid=major,grid style={gray!15},"
                    + r"axis line style={gray!65},tick style={gray!65},line width=0.9pt,tick label style={font=\small},"
                    + r"label style={font=\small},title style={font=\small},scaled y ticks=false,"
                    + r"legend style={font=\scriptsize,draw=none,fill=none,at={(1.15,1.22)},anchor=south,legend columns=-1},legend cell align=left]")
        for scheme, label, color, mark in labels:
            error = "" if field == "proof_kib" else r",error bars/.cd,y dir=both,y explicit,error bar style={line width=0.65pt},error mark options={rotate=90,mark size=2pt}"
            columns = f"x=count,y={field},col sep=comma"
            if error:
                columns += f",y error minus={field}_error_minus,y error plus={field}_error_plus"
            axes.append(f"\\addplot+[color={color},mark={mark},mark size=2.1pt{error}] table[{columns}] {{tree-{scheme}.csv}};")
            if index == 0:
                axes.append(f"\\addlegendentry{{{label}}}")
        axes.append(r"\end{axis}")
    return r"""\documentclass[tikz,border=5pt]{standalone}
\usepackage{pgfplots}
\pgfplotsset{compat=1.18}
\definecolor{falconblue}{HTML}{0072B2}
\definecolor{mldsaorange}{HTML}{D55E00}
\definecolor{forsgreen}{HTML}{009E73}
\begin{document}
\begin{tikzpicture}
AXES
\node[font=\scriptsize,align=center,anchor=north] at (7.85cm,-1.0cm)
{Falcon: 10 signatures/leaf; ML-DSA: 2; both binary with padding charged.\\FORS: 5 signatures/leaf, fan-in 4.};
\end{tikzpicture}
\end{document}
""".replace("AXES", "\n".join(axes))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "results/mine/figures")
    parser.add_argument("--render", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    module_spec = importlib.util.spec_from_file_location("rv_figures", ROOT / "risc-v/scripts/figures.py")
    helper = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(helper)
    helper.SCHEMES = {"falcon": ("Falcon-512 (RISC-V)", "falconblue", "*"),
                      "mldsa": ("ML-DSA-44 (RISC-V)", "mldsaorange", "square*"),
                      "fors": ("FORS (leanISA + Keccak)", "forsgreen", "triangle*")}
    rows = direct()
    tree_rows, tree_samples = trees()
    rv_tree_rows, rv_tree_samples = riscv_trees()
    recursive_rows = rv_tree_rows + [{"scheme": "fors", "backend": "leanISA", **row} for row in tree_rows]
    recursive_samples = rv_tree_samples + [{"scheme": "fors", "backend": "leanISA", **row} for row in tree_samples]
    write_csv(output / "measurements.csv", rows)
    # Keep the original FORS-only CSVs available for the earlier figure artifacts.
    write_csv(output / "tree.csv", tree_rows)
    write_csv(output / "tree-samples.csv", tree_samples)
    write_csv(output / "recursive-trees.csv", recursive_rows)
    write_csv(output / "recursive-tree-samples.csv", recursive_samples)
    for scheme in helper.SCHEMES:
        write_csv(output / f"{scheme}.csv", [row for row in rows if row["scheme"] == scheme])
        write_csv(output / f"tree-{scheme}.csv", [row for row in recursive_rows if row["scheme"] == scheme])
    write_csv(output / "fors-matched.csv", [row for row in rows if row["scheme"] == "fors" and row["count"] in COUNTS])
    definitions = {
        "figure-1-batching": (("proof_kib", "Proof size (KiB)", "Direct batch proof size"), ("prove_s", "Proving time (s)", "Direct batch proving")),
        "figure-2-verification-memory": (("verify_ms", "Verification time (ms)", "Direct batch verification"), ("rss_gib", "Peak process RSS (GiB)", "Prover memory")),
        "figure-3-capacity-efficiency": (("capacity_percent", "Commitment budget used (\\%)", "Capacity"), ("prove_per_signature_ms", "Proving time per signature (ms)", "Amortized proving time")),
    }
    documents = {name: helper.tex_document(left, right, rows, output)
                 for name, (left, right) in definitions.items()}
    for name, title, field in (
            ("figure-1-batching", "Direct batch proving", "prove_s"),
            ("figure-3-capacity-efficiency", "Amortized proving time", "prove_per_signature_ms")):
        # Timing spans several orders of magnitude across the two backends.
        # Apply log y only to this timing panel, retaining linear proof/capacity axes.
        minimum = min(row[field + "_min"] for row in rows)
        require(minimum > 0, f"Nonpositive logarithmic timing measurement: {name}")
        sections = documents[name].split(r"\begin{axis}")
        for index, section in enumerate(sections):
            if f"title={{{title}}}" in section:
                sections[index] = section.replace("ymin=0", f"ymode=log,log basis y=10,ymin={minimum * 0.75:.12g}", 1)
        documents[name] = r"\begin{axis}".join(sections)
    documents["figure-4-fors-tree"] = tree_tex()
    documents["figure-5-fors-tree-verification"] = tree_tex(verification=True)
    documents["figure-4-recursive-trees"] = recursive_tree_tex(recursive_rows)
    documents["figure-5-tree-verification"] = recursive_tree_tex(recursive_rows, verification=True)
    cache = output / ".tectonic-cache"
    if args.render:
        helper.prepare_tex_cache(cache)
    for name, document in documents.items():
        # Long, explicit backend names need a smaller shared legend.
        document = document.replace("legend style={font=\\small", "legend style={font=\\scriptsize")
        tex = output / f"{name}.tex"
        tex.write_text(document)
        if args.render:
            helper.render(tex, cache)
    for path in (Path(__file__), ROOT / "risc-v/scripts/figures.py", ROOT / "risc-v/tree-bench/src/main.rs",
                 ROOT / "risc-v/tree-bench/Cargo.lock", ROOT / "leanISA/scripts/article_figures.py",
                 ROOT / "leanISA/results/article/environment.json"):
        SOURCES[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    metadata = {
        "schema": 2, "backends": {"falcon": RV_PIN, "mldsa": RV_PIN, "fors": ISA_PIN},
        "riscv_baseline_guest_sha256": RV_GUESTS,
        "direct_measurements": len(rows), "tree_counts": list(COUNTS), "tree_samples_per_count": 3,
        "recursive_tree_measurements": len(recursive_rows), "recursive_tree_schemes": ["falcon", "mldsa", "fors"],
        "sample_policy": "Direct proof points: three fresh proofs after one warmup. Tree points: three complete fresh leaf-plus-merge runs. Medians and full min/max ranges, not extrapolations.",
        "thread_policy": {"falcon_and_mldsa": "Requests eight workers; the backend topology can add efficiency-core workers, so this is not a total process-thread count", "fors": "Automatic leanVM thread selection, threads_env=null on the 12-logical-CPU host"},
        "direct_verification": {"falcon_and_mldsa": "Proof decoding plus complete Program::verify, no program loading/public-claim derivation/file I/O", "fors": "Prepared-bytecode verifier::verify_execution, median of three verify_cached_s samples from independent pinned public-only receiver; excludes compilation/table setup/public-claim derivation/file I/O"},
        "tree_scope": "RISC-V Falcon: ten signatures per real leaf; RISC-V ML-DSA: two; both first-level arity two and node arity two, rate one. Archived leanISA FORS: five signatures per leaf, fan-in four, rate one. Separate five-signature ML-DSA pilots are not timing-curve points.",
        "tree_backend_pin_source": "RISC-V producer, public receiver and trusted statement pin RV_PIN. Archived FORS reports have no revision field; ISA_PIN is checked against leanISA/results/article/environment.json upstream.leanVM.rev.",
        "tree_padding": "RISC-V uses max(2,next_power_of_two(real_leaves)) leaf slots, reusing the final real leaf proof in canonical padding slots. Padding is not counted as new signatures. Every merge is freshly proved and charged; each distinct real leaf is freshly proved once per pipeline. Counts, slots and padding are retained in CSV.",
        "tree_proving": "Sum of fresh leaf prove_s and every merge node prove_s; excludes compilation, fixture generation and serialization, not elapsed parallel latency.",
        "tree_size": "RISC-V: serialized TreeProof including its reduced claim statement. FORS: root STARK plus auxiliary deferred edge points and aggregate serialization metadata. Neither includes child proof files or signature witnesses; public claims and shared programs are additional.",
        "tree_verification_cold": {"riscv": "program_load_s + tree_setup_s + first_complete_verify_s (decode plus Tree::verify)", "fors": "compile_plan_s + deferred_bytecode_prepare_s + median(deferred_evaluation_s) + median(root_core_verify_cold_s)"},
        "tree_verification_prepared": {"riscv": "median of three decode plus Tree::verify samples after one warmup; Tree::verify settles all reduced dense-polynomial and Flock matrix claims", "fors": "median(deferred_evaluation_s) + median(root_core_verify_cached_s); every deferred edge and root STARK still checked"},
        "tree_verification_excludes": "Public-claim derivation and file I/O. Public-claim derivation is retained as claim_ms in CSV, not added to plotted verifier time.",
        "timing_comparison": "Backend acceleration, worker policy, tree arity, signatures per leaf, padding and verification timer boundaries differ. These are implementation measurements, not controlled signature-only speedup ratios.",
        "axis_scales": "Figure1 proving time, Figure3 per-signature proving time and the new recursive tree timing panels use log10 y axes. Proof size, capacity, direct verification and RSS remain linear. Direct batch counts use log2 x axes; tree counts remain linear. Earlier FORS-only Figures4/5 are retained with their original linear axes.",
        "capacity": "Same numerical 2^28 bound, different witness representations. Percentages are backend-specific budget occupancy, not interchangeable witness units.",
        "rendering": "LaTeX/PGFPlots through cached Tectonic, PNG from the same PDF through pdftoppm at 180dpi",
        "source_sha256": SOURCES,
    }
    (output / "provenance.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps({"direct_measurements": len(rows), "tree_counts": list(COUNTS),
                      "rendered": args.render, "output": str(output)}))


if __name__ == "__main__":
    main()
