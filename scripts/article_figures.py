#!/usr/bin/env python3
"""Render article figures from actual reports, preserving sampling and failures.

No proving, interpolation, extrapolation, or synthetic measurements occurs here.
Run after article_bench.py. --allow-incomplete makes missing cases visible while
an experiment is still running; the default requires all primary configurations.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import statistics

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("MPLCONFIGDIR", str(ROOT / ".cache/matplotlib"))

SCHEMES = ("ethfalcon", "falcon", "ethdilithium", "mldsa", "fors")
VERIFICATION_SCHEMES = ("falcon", "mldsa", "fors")
COUNTS = (10, 30, 70, 100)
LABEL = {"ethfalcon": "ethFalcon-512", "falcon": "Falcon-512 (SHAKE)",
         "ethdilithium": "ethDilithium (expanded key)", "mldsa": "ML-DSA-44 (expanded key)",
         "fors": "Research FORS"}
COLOR = {"ethfalcon": "#0072B2", "falcon": "#56B4E9", "ethdilithium": "#D55E00",
         "mldsa": "#E69F00", "fors": "#009E73"}
STYLE = {"ethfalcon": "--", "falcon": "-", "ethdilithium": "--", "mldsa": "-", "fors": "-"}


def median(values):
    values = [float(value) for value in values if value is not None]
    return statistics.median(values) if values else None


def numbers(value):
    if value is None:
        return []
    return [float(v) for v in value] if isinstance(value, list) else [float(value)]


class Measurements:
    def __init__(self, directory: Path, records: Path, incomplete: bool):
        self.directory, self.records, self.incomplete = directory, records, incomplete
        self.sources, self.warnings = {}, []
        self.direct, self.trees, self.failures, self.native = [], [], [], []
        self.read_direct()
        self.read_trees()
        self.read_native()

    def read(self, path):
        try:
            raw = path.read_bytes()
            data = json.loads(raw)
        except (OSError, ValueError) as error:
            if not self.incomplete:
                raise
            self.warnings.append(f"Skipped {path}: {error}")
            return None
        self.sources[str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)] = hashlib.sha256(raw).hexdigest()
        return data

    def read_direct(self):
        for path in sorted((self.directory / "direct").glob("*.json")):
            match = re.fullmatch(r"(ethfalcon|falcon|ethdilithium|mldsa|fors)-(\d+)(\.failed)?\.json", path.name)
            if not match:
                continue
            report = self.read(path)
            if report is None:
                continue
            scheme, count = match[1], int(match[2])
            if match[3] or report.get("status") == "failed":
                self.failures.append({"study": "direct", "scheme": scheme, "count": count,
                                      "error": report.get("error", ""), "report": str(path)})
                continue
            if not report.get("verified"):
                self.warnings.append(f"Ignored direct proof without successful verification: {path}")
                continue
            meta = report.get("metadata", {})
            if int(meta.get("count", count)) != count:
                raise ValueError(f"filename/count mismatch in {path}")
            samples = numbers(report.get("prove_s"))
            self.direct.append({"scheme": scheme, "count": count, "proof_bytes": int(report["proof_bytes"]),
                                "prove_s_median": median(samples), "prove_s_min": min(samples) if samples else None,
                                "prove_s_max": max(samples) if samples else None, "prove_samples": samples,
                                "raw_signature_bytes": meta.get("raw_signature_bytes", meta.get("signature_bytes")),
                                "peak_rss_bytes": report.get("process_peak_rss_bytes"), "guest_hash": report.get("guest_hash"),
                                "report": str(path)})

    def raw_signature_bytes(self, scheme, count):
        path = self.records / scheme / "records.json"
        if not path.exists():
            return None
        saved = self.read(path)
        if saved is None or len(saved) < count:
            return None
        if scheme == "fors":
            # Actual opening lengths from the records, including secret and path.
            return sum(sum(len(bytes.fromhex(opening["secret"])) +
                           sum(len(bytes.fromhex(node)) for node in opening["auth"])
                           for opening in record["signature"]) for record in saved[:count])
        if scheme in ("falcon", "ethfalcon"):
            return sum(len(bytes.fromhex(record["signed_message_hex"])) -
                       len(bytes.fromhex(record["message_hex"])) - 2 for record in saved[:count])
        return sum(len(bytes.fromhex(record["compact_signature_hex"])) for record in saved[:count])

    def read_trees(self):
        for directory in sorted((self.directory / "trees").glob("*")):
            match = re.fullmatch(r"(ethfalcon|falcon|ethdilithium|mldsa|fors)-(\d+)-b([248])(?:-leaf(\d+)|-(merge-only))?", directory.name)
            if not match:
                continue
            scheme, count, fan = match[1], int(match[2]), int(match[3])
            sensitivity = match[4] is not None
            merge_only = match[5] is not None
            for path in sorted(directory.glob("*.json")):
                sample_match = re.fullmatch(r"(?:sample-(\d+)|(warmup))(\.failed)?\.json", path.name)
                if not sample_match:
                    continue
                if sample_match[2] and not sample_match[3]:
                    continue
                report = self.read(path)
                if report is None:
                    continue
                if sample_match[3] or report.get("status") == "failed":
                    self.failures.append({"study": "tree", "scheme": scheme, "count": count,
                                          "fan_in": fan, "leaf_sensitivity": sensitivity,
                                          "merge_only": merge_only,
                                          "leaf_capacity": int(match[4]) if sensitivity else report.get("leaf_capacity"),
                                          "stage": "warmup" if sample_match[2] else "sample",
                                          "error": report.get("error", ""), "report": str(path)})
                    continue
                verification = report.get("verification", {})
                fresh_path = path.with_name(path.stem + ".fresh-verification.json")
                if fresh_path.exists():
                    fresh = self.read(fresh_path)
                    if fresh is not None:
                        verification = fresh
                if not verification.get("verified"):
                    self.warnings.append(f"Ignored unverified tree {path}")
                    continue
                if (report.get("signatures") != count or report.get("fan_in") != fan or
                        report.get("scheme") != scheme):
                    raise ValueError(f"tree filename/configuration mismatch: {path}")
                leaf_reports = report.get("leaf_reports", [])
                leaf_times = []
                for leaf in leaf_reports:
                    measured = leaf.get("original_report", {}) if leaf.get("reused") else leaf
                    if measured and "prove_s" in measured:
                        leaf_times.append(float(measured["prove_s"]))
                leaf_work = sum(leaf_times) if len(leaf_times) == len(leaf_reports) else None
                eval_s = median(numbers(verification.get("deferred_evaluation_s")))
                core_cold = median(numbers(verification.get("root_core_verify_cold_s")))
                core_cached = median(numbers(verification.get("root_core_verify_cached_s")))
                cold_parts = [verification.get("compile_plan_s"), verification.get("deferred_bytecode_prepare_s"), eval_s, core_cold]
                verify_cold = sum(cold_parts) if all(v is not None for v in cold_parts) else None
                verify_cached = eval_s + core_cached if eval_s is not None and core_cached is not None else None
                envelope = int(verification["aggregate_wire_bytes"])
                core = int(verification["root_core_proof_bytes"])
                raw = report.get("raw_signature_bytes") or self.raw_signature_bytes(scheme, count)
                passes = report.get("merge_passes", [])
                if not passes:
                    self.warnings.append(f"No measured merge pass: {path}")
                    continue
                for merge_pass in passes:
                    merge_work = sum(float(node["prove_s"]) for node in merge_pass["nodes"])
                    fresh_leaves = int(report.get("leaf_reuse_count", 0)) == 0
                    fresh_pipeline = fresh_leaves and fan == 4 and not merge_only and len(passes) == 1
                    total_work = leaf_work + merge_work if fresh_pipeline and leaf_work is not None else None
                    self.trees.append({"scheme": scheme, "count": count, "fan_in": fan,
                        "leaf_capacity": int(report["leaf_capacity"]), "leaf_sensitivity": sensitivity,
                        "merge_only": merge_only,
                        "sample": int(sample_match[1]), "merge_pass": int(merge_pass.get("pass", 0)),
                        "fresh_leaves": fresh_leaves, "leaf_reuse_count": int(report.get("leaf_reuse_count", 0)),
                        "fresh_pipeline": fresh_pipeline,
                        "leaf_count": int(report["leaf_count"]), "merge_count": int(report["merge_count"]),
                        "edge_count": int(report["edge_count"]), "depth": int(report["depth"]),
                        "leaf_prove_s": leaf_work if fresh_leaves else None, "merge_prove_s": merge_work,
                        "reference_leaf_prove_s": leaf_work if not fresh_leaves else None,
                        "reference_component_total_s": leaf_work + merge_work if not fresh_pipeline and leaf_work is not None else None,
                        "total_prove_s": total_work,
                        "pipeline_elapsed_s": report.get("pipeline_elapsed_s"),
                        "experiment_process_elapsed_s": report.get("experiment_process_elapsed_s"),
                        "envelope_bytes": envelope, "core_bytes": core, "auxiliary_bytes": envelope - core,
                        "raw_signature_bytes": raw, "verify_cold_s": verify_cold,
                        "verify_cached_s": verify_cached, "deferred_evaluation_s": eval_s,
                        "public_claim_derivation_s": verification.get("public_claim_derivation_s"),
                        "public_receiver_process_s": verification.get("public_receiver_process_s"),
                        "peak_rss_bytes": report.get("process_peak_rss_bytes"),
                        "prover_s_per_signature": total_work / count if total_work is not None else None,
                        "wire_bytes_per_signature": envelope / count,
                        "root_guest_hash": report.get("root_guest_hash"), "plan_hash": report.get("plan_hash"),
                        "report": str(path), "verification_report": str(fresh_path) if fresh_path.exists() else str(path)})

    def read_native(self):
        path = self.directory / "native.json"
        if not path.exists():
            return
        data = self.read(path)
        if data:
            for scheme in SCHEMES:
                if scheme in data:
                    self.native.append({"scheme": scheme, **data[scheme]})

    def validate(self):
        missing = []

        def tree_case(scheme, count, fan, *, merge_only=False, capacity=None):
            sensitivity = capacity is not None
            rows = [row for row in self.trees if row["scheme"] == scheme and row["count"] == count and
                    row["fan_in"] == fan and row["leaf_sensitivity"] == sensitivity and
                    row["merge_only"] == merge_only and (capacity is None or row["leaf_capacity"] == capacity)]
            failed = [row for row in self.failures if row["study"] == "tree" and row["scheme"] == scheme and
                      row["count"] == count and row["fan_in"] == fan and
                      row["leaf_sensitivity"] == sensitivity and row["merge_only"] == merge_only and
                      (capacity is None or row["leaf_capacity"] == capacity)]
            label = f"{scheme} N={count} b={fan}"
            if capacity is not None:
                label += f" leaf={capacity}"
            if merge_only:
                label += " merge-only"
            if failed:
                return
            if fan == 4 and not merge_only:
                samples = {row["sample"] for row in rows if row["fresh_pipeline"]}
                if not {0, 1, 2}.issubset(samples):
                    missing.append("three fresh prepared-input proof runs: " + label)
            else:
                passes = {row["merge_pass"] for row in rows if row["sample"] == 0 and
                          row["leaf_reuse_count"] == row["leaf_count"]}
                if not {0, 1, 2}.issubset(passes):
                    missing.append("three merge passes with all verified leaves reused: " + label)

        for scheme in SCHEMES:
            points = {row["count"]: row for row in self.direct if row["scheme"] == scheme}
            failures = {row["count"] for row in self.failures if row["study"] == "direct" and row["scheme"] == scheme}
            if scheme == "fors":
                expected_direct = [*range(1, 31), 70, 100]
            else:
                first_failure = min(failures) if failures else 31
                expected_direct = range(1, min(first_failure, 30) + 1)
            for count in expected_direct:
                if count in failures:
                    continue
                if count not in points or len(points[count]["prove_samples"]) < 3:
                    missing.append(f"three direct proof timings: {scheme} N={count}")
            for count in COUNTS:
                tree_case(scheme, count, 4)
                tree_case(scheme, count, 4, merge_only=True)
                tree_case(scheme, count, 2)
                tree_case(scheme, count, 8)
            native = next((row for row in self.native if row["scheme"] == scheme), None)
            if not native or len(numbers(native.get("verify_ns_samples"))) < 3 or native.get("repeats_per_sample", 0) < 1000:
                missing.append(f"native/reference verification, three groups of 1000 calls: {scheme}")
            if scheme != "fors" and (not native or len(numbers(native.get("sign_ns_samples"))) < 30):
                missing.append(f"30 fresh native signing samples: {scheme}")
        for capacity in (1, 2, 4):
            tree_case("ethfalcon", 100, 4, capacity=capacity)
        for count in COUNTS:
            tree_case("fors", count, 4, capacity=16)
        if missing and not self.incomplete:
            raise ValueError("Incomplete measurements. Use --allow-incomplete for a labelled partial preview:\n" + "\n".join(missing))
        self.warnings += ["Missing " + item for item in missing]


def write_csv(path, rows):
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(value) if isinstance(value, (list, dict)) else value for key, value in row.items()})


def verification_phase_summary(data, count=100, schemes=SCHEMES):
    """Keep claim preparation paired with verification from the same process."""
    summary = []
    for scheme in schemes:
        runs = []
        for row in data.trees:
            if (row["scheme"] != scheme or row["count"] != count or row["fan_in"] != 4 or
                    row["leaf_sensitivity"] or row["merge_only"] or not row["fresh_leaves"] or
                    row.get("public_claim_derivation_s") is None or row.get("verify_cold_s") is None):
                continue
            claims = float(row["public_claim_derivation_s"])
            proof = float(row["verify_cold_s"])
            report = Path(row["verification_report"])
            runs.append({"sample": row["sample"], "commitment_derivation_s": claims,
                         "proof_verification_s": proof, "total_s": claims + proof,
                         "verification_report": str(report.relative_to(ROOT)) if report.is_relative_to(ROOT) else str(report)})
        if not runs:
            continue
        runs.sort(key=lambda row: (row["total_s"], row["sample"]))
        middle = len(runs) // 2
        selected = runs[middle:middle + 1] if len(runs) % 2 else runs[middle - 1:middle + 1]
        claims = statistics.mean(row["commitment_derivation_s"] for row in selected)
        proof = statistics.mean(row["proof_verification_s"] for row in selected)
        summary.append({"scheme": scheme, "count": count, "paired_samples": len(runs),
                        "commitment_derivation_s": claims, "proof_verification_s": proof,
                        "total_s": claims + proof, "total_min_s": runs[0]["total_s"],
                        "total_max_s": runs[-1]["total_s"],
                        "component_samples": [row["sample"] for row in selected], "sample_timings": runs})
    return summary


def summaries(data):
    """Compact article tables, keeping incomplete samples explicitly pending."""
    native = {row["scheme"]: row for row in data.native}
    wallet, main = [], []
    table = ["| Relation | Native C verify, µs | Maximum measured direct batch | N=100 aggregated proof, KiB | N=100 prover work, s |",
             "|---|---:|---:|---:|---:|"]
    for scheme in SCHEMES:
        n = native.get(scheme, {})
        direct = [row for row in data.direct if row["scheme"] == scheme]
        one = next((row for row in direct if row["count"] == 1), {})
        sign_ns, keygen_ns = numbers(n.get("sign_ns_samples")), numbers(n.get("keygen_ns_samples"))
        raw, proof = one.get("raw_signature_bytes"), one.get("proof_bytes")
        wallet.append({"scheme": scheme, "native_implementation": n.get("implementation"),
                       "native_sign_samples": len(sign_ns), "native_sign_s_median": median(sign_ns) / 1e9 if sign_ns else None,
                       "native_keygen_s_median": median(keygen_ns) / 1e9 if keygen_ns else None,
                       "native_verify_s_median": n.get("verify_ns_median", 0) / 1e9 if n else None,
                       "direct_one_prove_s_median": one.get("prove_s_median"),
                       "direct_one_process_peak_rss_bytes": one.get("peak_rss_bytes"),
                       "raw_signature_upload_bytes": raw, "individual_proof_upload_bytes": proof,
                       "individual_proof_to_signature_byte_ratio": proof / raw if proof and raw else None,
                       "scope": "desktop host; signer memory, device performance, MPC and battery not measured"})
        for count in COUNTS:
            rows = [row for row in data.trees if row["scheme"] == scheme and row["count"] == count and
                    row["fan_in"] == 4 and not row["leaf_sensitivity"] and not row["merge_only"] and row["fresh_pipeline"]]
            summary = {"scheme": scheme, "count": count, "fresh_pipeline_samples": len(rows)}
            for field in ("total_prove_s", "envelope_bytes", "core_bytes", "auxiliary_bytes", "verify_cold_s",
                          "verify_cached_s", "public_claim_derivation_s", "peak_rss_bytes", "edge_count",
                          "raw_signature_bytes", "prover_s_per_signature", "wire_bytes_per_signature"):
                summary[field + "_median"] = median([row.get(field) for row in rows])
            main.append(summary)
            if count == 100:
                complete = len(rows) >= 3
                v = n.get("verify_ns_median")
                native_text = f"{v / 1000:.2f}" if v and scheme != "fors" else "Python reference only"
                cap = str(max(row["count"] for row in direct)) if direct else "Pending"
                if scheme == "fors" and cap != "Pending":
                    cap = "At least " + cap
                envelope = f"{summary['envelope_bytes_median'] / 1024:.2f}" if complete else "Pending"
                work = f"{summary['total_prove_s_median']:.3f}" if complete else "Pending"
                table.append(f"| {LABEL[scheme]} | {native_text} | {cap} | {envelope} | {work} |")
    return wallet, main, "\n".join(table) + "\n"


def axis_style(axis, ylabel, xlabel="Signatures"):
    axis.set_xlabel(xlabel)
    axis.set_ylabel(ylabel)
    axis.spines[["top", "right"]].set_visible(False)
    axis.grid(axis="y", color="#dddddd", linewidth=.5)
    axis.set_axisbelow(True)


def error_curve(axis, rows, xkey, ykey, scheme, scale=1, style=None, label=None,
                marker="o", markersize=4.5, linewidth=1.6, **kwargs):
    grouped = {}
    for row in rows:
        if row.get(ykey) is not None:
            grouped.setdefault(row[xkey], []).append(float(row[ykey]) / scale)
    xs = sorted(grouped)
    ys = [median(grouped[x]) for x in xs]
    if not xs:
        return
    axis.errorbar(xs, ys, yerr=[[v - min(grouped[x]) for x, v in zip(xs, ys)],
                              [max(grouped[x]) - v for x, v in zip(xs, ys)]],
                  color=COLOR[scheme], linestyle=STYLE[scheme] if style is None else style,
                  marker=marker, markersize=markersize, linewidth=linewidth, capsize=2.5,
                  label=label or LABEL[scheme], **kwargs)


def save_figure(figure, directory, name):
    figure.savefig(directory / (name + ".png"), dpi=220, facecolor="white")
    figure.savefig(directory / (name + ".svg"), facecolor="white")


def render(data, directory):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D
    # Ten-inch figures with 11-13 pt text retain readable labels when a forum
    # scales the exported image to its roughly 736-pixel article column.
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 12, "axes.titlesize": 13,
                         "axes.labelsize": 12, "xtick.labelsize": 11, "ytick.labelsize": 11,
                         "legend.fontsize": 11, "svg.fonttype": "none", "savefig.bbox": "tight"})
    legend = [Line2D([0], [0], color=COLOR[s], linestyle=STYLE[s], label=LABEL[s]) for s in SCHEMES]
    def partial(figure):
        if data.warnings:
            figure.text(.99, .995, "PARTIAL DATA: see measurements.json", ha="right", va="top", fontsize=10, color="#777777")
    note = "M4 Pro; custom leanISA; rate=1. Python fixture/advice preparation excluded."
    fig, axes = plt.subplots(1, 2, figsize=(10, 6.4))
    fig.subplots_adjust(left=.09, right=.98, top=.87, bottom=.32, wspace=.28)
    for scheme in SCHEMES:
        rows = sorted([r for r in data.direct if r["scheme"] == scheme], key=lambda r: r["count"])
        error_curve(axes[0], rows, "count", "proof_bytes", scheme, scale=1024)
        if rows:
            axes[1].errorbar([r["count"] for r in rows], [r["prove_s_median"] for r in rows],
                            yerr=[[r["prove_s_median"] - r["prove_s_min"] for r in rows],
                                  [r["prove_s_max"] - r["prove_s_median"] for r in rows]],
                            color=COLOR[scheme], linestyle=STYLE[scheme], marker="o", markersize=4.5,
                            capsize=2.5, linewidth=1.6)
        for failure in [r for r in data.failures if r["study"] == "direct" and r["scheme"] == scheme]:
            if "WitnessOutOfRange" not in failure["error"]:
                continue
            for axis in axes:
                axis.plot(failure["count"], .04 + SCHEMES.index(scheme) * .035, "x", color=COLOR[scheme],
                          transform=axis.get_xaxis_transform(), clip_on=False, markersize=6)
    axis_style(axes[0], "Serialized proof (KiB)")
    axis_style(axes[1], "Prover work (seconds)")
    axes[0].set_title("A  Direct batch proof size")
    axes[1].set_title("B  Proving time\nmedian and observed range")
    axes[1].set_yscale("log")
    from matplotlib.ticker import ScalarFormatter
    for axis in axes:
        axis.set_xscale("log")
        axis.set_xlim(.5, 101)
        # Leave the measured N=70 point on the curve, but omit its crowded
        # tick label next to 100 when rendered in a 736-pixel article column.
        axis.set_xticks([1, 2, 5, 10, 30, 100])
        axis.xaxis.set_major_formatter(ScalarFormatter())
    fig.legend(handles=legend, loc="center", ncol=3, bbox_to_anchor=(.52, .17), frameon=False)
    fig.text(.08, .075, "× marks measured capacity failure; later counts remain gaps.", fontsize=11)
    fig.text(.08, .04, "Expanded-key relations and research FORS are not security-equivalent.", fontsize=11)
    fig.text(.08, .005, note, fontsize=11)
    partial(fig)
    save_figure(fig, directory, "figure-1-direct-batches")
    plt.close(fig)

    main = [row for row in data.trees if row["fan_in"] == 4 and not row["leaf_sensitivity"] and
            not row["merge_only"] and row["fresh_leaves"]]
    direct_fors = sorted([row for row in data.direct if row["scheme"] == "fors" and row["count"] in COUNTS],
                         key=lambda row: row["count"])
    from matplotlib.legend_handler import HandlerTuple

    def primary_style():
        return tuple(Line2D([0], [0], color="#444444", linestyle=style)
                     for style in ("-", "--"))

    direct_style = Line2D([0], [0], color=COLOR["fors"], linestyle=":",
                         marker="^", markerfacecolor="white")
    tree_panels = (
        ("figure-2a-tree-proving", "Figure 2A  Leaf and merge proving work",
         "Total prover work (seconds)",
         [primary_style(), direct_style], ["Leaves plus all merges", "Direct FORS (no tree)"],
         "Prepared inputs; Python fixture/advice preparation excluded."),
        ("figure-2b-aggregated-proof-comparison", "Figure 2B  Aggregated STARK proofs versus original signatures",
         "Proof or signature bytes (KiB)",
         [Line2D([0], [0], color="#444444", linestyle="-", marker="s", linewidth=2.6),
          Line2D([0], [0], color="#444444", linestyle="-."), direct_style],
         ["Aggregated STARK proof", "Original signatures", "Direct FORS batch"],
         "Public keys/messages and trusted code are additional inputs. Research FORS parameters."),
        ("figure-2c-verification", "Figure 2C  Verification",
         "Verification time (seconds)", [], [],
         "Includes program/table preparation, auxiliary checks and final STARK verification."),
    )
    for panel, (name, title, ylabel, style_handles, style_labels, footer) in enumerate(tree_panels):
        fig, axis = plt.subplots(figsize=(10.8, 8) if panel == 1 else (10, 6.5) if panel == 2 else (10, 7.5))
        if panel == 1:
            fig.subplots_adjust(left=.09, right=.98, top=.89, bottom=.34)
        elif panel == 2:
            fig.subplots_adjust(left=.10, right=.97, top=.89, bottom=.32)
        else:
            fig.subplots_adjust(left=.10, right=.97, top=.91, bottom=.40)
        # Draw the ETH variants last within each pair so their dashed curves
        # remain visible when the envelope sizes nearly coincide.
        schemes = ("falcon", "ethfalcon", "mldsa", "ethdilithium", "fors") if panel == 1 else SCHEMES
        for scheme in schemes:
            rows = [r for r in main if r["scheme"] == scheme]
            if panel == 0:
                error_curve(axis, rows, "count", "total_prove_s", scheme)
            elif panel == 1:
                error_curve(axis, rows, "count", "envelope_bytes", scheme, scale=1024,
                            marker="s", markersize=7 if scheme.startswith("eth") else 4.5,
                            markerfacecolor="none" if scheme.startswith("eth") else COLOR[scheme],
                            linewidth=2.7, zorder=5)
                error_curve(axis, rows, "count", "raw_signature_bytes", scheme, scale=1024,
                            style="-.", marker="", linewidth=1.9, alpha=.75, zorder=2)
            else:
                error_curve(axis, rows, "count", "verify_cold_s", scheme, linewidth=2, markersize=5)
        if direct_fors and panel in (0, 1):
            values = ([r["prove_s_median"] for r in direct_fors] if panel == 0 else
                      [r["proof_bytes"] / 1024 for r in direct_fors])
            axis.plot([r["count"] for r in direct_fors], values, color=COLOR["fors"],
                      linestyle=":", marker="^", markerfacecolor="white",
                      markersize=7 if panel == 1 else 6, linewidth=2.3 if panel == 1 else 1.3)
        axis.set_xticks(COUNTS)
        axis_style(axis, ylabel)
        axis.set_title(title)
        if panel == 0:
            axis.set_yscale("log")
        elif panel == 2:
            axis.set_ylim(bottom=0)
            axis.set_xlabel("Number of signatures")
        if panel == 1:
            axis.set_xlim(5, 148)
            axis.set_ylim(0, 485)
            axis.set_xlabel("Number of signatures")

            def endpoint(scheme, field):
                return median([r[field] / 1024 for r in main
                               if r["scheme"] == scheme and r["count"] == 100 and r.get(field) is not None])

            def endpoint_label(value, text, color, offset=0):
                if value is not None:
                    axis.annotate(text, xy=(100, value), xytext=(104, value + offset),
                                  color=color, fontsize=11, va="center",
                                  bbox={"facecolor": "white", "edgecolor": "none", "pad": 1},
                                  arrowprops={"arrowstyle": "-", "color": color, "linewidth": .9},
                                  annotation_clip=False, zorder=8)

            pairs = (("ethdilithium", "mldsa", "Dilithium", 0),
                     ("ethfalcon", "falcon", "Falcon", 23))
            for eth, standard, family, offset in pairs:
                values = [endpoint(s, "envelope_bytes") for s in (eth, standard)]
                if all(value is not None for value in values):
                    rounded = sorted({round(value) for value in values})
                    size = str(rounded[0]) if len(rounded) == 1 else f"{rounded[0]}–{rounded[-1]}"
                    endpoint_label(values[0], f"{family} proofs: {size} KiB", COLOR[eth], offset)
                raw = endpoint(standard, "raw_signature_bytes")
                if raw is not None:
                    endpoint_label(raw, f"{family} signatures: {raw:.0f} KiB", COLOR[standard])
            envelope = endpoint("fors", "envelope_bytes")
            raw = endpoint("fors", "raw_signature_bytes")
            if envelope is not None:
                endpoint_label(envelope, f"FORS proof: {envelope:.0f} KiB", COLOR["fors"], -10)
            if raw is not None:
                endpoint_label(raw, f"FORS signatures: {raw:.0f} KiB", COLOR["fors"])
            direct_end = [r["proof_bytes"] / 1024 for r in direct_fors if r["count"] == 100]
            if direct_end:
                endpoint_label(direct_end[0], f"Direct FORS: {direct_end[0]:.0f} KiB", COLOR["fors"], -14)

        panel_legend = ([Line2D([0], [0], color=COLOR[s], linestyle=STYLE[s], marker="s",
                                label={"ethdilithium": "ethDilithium", "mldsa": "ML-DSA-44"}.get(s, LABEL[s]))
                         for s in SCHEMES] if panel == 1 else legend)
        fig.legend(handles=panel_legend, loc="center", ncol=3,
                   bbox_to_anchor=(.52, .225 if panel == 1 else .20 if panel == 2 else .285), frameon=False)
        if style_handles:
            fig.legend(handles=style_handles, labels=style_labels,
                       handler_map={tuple: HandlerTuple(ndivide=None)},
                       title=None if panel == 1 else "Line styles and markers",
                       loc="center", ncol=3 if panel == 1 else 2,
                       bbox_to_anchor=(.52, .12 if panel == 1 else .17), frameon=False,
                       fontsize=11, handlelength=3.5, columnspacing=2)
        fig.text(.08, .06 if panel == 1 else .10 if panel == 2 else .07,
                 "Fan-in 4; three-run medians. ETH and standard proof sizes nearly overlap."
                 if panel == 1 else "Fan-in 4; medians and observed ranges from three fresh proof runs.", fontsize=11)
        fig.text(.08, .025 if panel == 1 else .055 if panel == 2 else .035, footer, fontsize=11)
        if panel == 2:
            fig.text(.08, .01, "Expected public-claim derivation and file I/O are excluded.", fontsize=11)
        partial(fig)
        save_figure(fig, directory, name)
        plt.close(fig)

    phase_rows = [row for count in COUNTS
                  for row in verification_phase_summary(data, count, schemes=VERIFICATION_SCHEMES)]
    if phase_rows:
        fig, axis = plt.subplots(figsize=(11.5, 8))
        fig.subplots_adjust(left=.085, right=.985, top=.87, bottom=.32)
        centers = {count: index * 1.65 for index, count in enumerate(COUNTS)}
        offsets = {scheme: (index - 1) * .4 for index, scheme in enumerate(VERIFICATION_SCHEMES)}
        positions = [centers[row["count"]] + offsets[row["scheme"]] for row in phase_rows]
        claims = [row["commitment_derivation_s"] for row in phase_rows]
        proofs = [row["proof_verification_s"] for row in phase_rows]
        totals = [row["total_s"] for row in phase_rows]
        claim_color, proof_color = "#8064A2", "#0072B2"
        claim_bars = axis.bar(positions, claims, width=.3, color=claim_color)
        proof_bars = axis.bar(positions, proofs, bottom=claims, width=.3, color=proof_color)
        axis.errorbar(positions, totals,
                      yerr=[[row["total_s"] - row["total_min_s"] for row in phase_rows],
                            [row["total_max_s"] - row["total_s"] for row in phase_rows]],
                      fmt="none", ecolor="#333333", elinewidth=1, capsize=2.5, zorder=5)
        for position, row in zip(positions, phase_rows):
            claim, proof = row["commitment_derivation_s"], row["proof_verification_s"]
            if claim >= .35:
                axis.text(position, claim / 2, f"{claim:.3f}", ha="center", va="center",
                          color="white", fontsize=9.5)
            if proof >= .35:
                axis.text(position, claim + proof / 2, f"{proof:.3f}", ha="center", va="center",
                          color="white", fontsize=9.5)
            axis.text(position, row["total_max_s"] + .08, f"{row['total_s']:.3f}",
                      ha="center", va="bottom", fontweight="bold", fontsize=10.5)
        short_labels = {"falcon": "Falcon", "mldsa": "ML-DSA\n44", "fors": "FORS"}
        for position, row in zip(positions, phase_rows):
            axis.text(position, -.025, short_labels[row["scheme"]],
                      transform=axis.get_xaxis_transform(), ha="center", va="top", fontsize=10.5)
            if row["commitment_derivation_s"] < .35:
                axis.text(position, -.088, f"{row['commitment_derivation_s'] * 1000:.1f} ms",
                          transform=axis.get_xaxis_transform(), ha="center", va="top",
                          color=claim_color, fontsize=10.2)
        axis.set_xticks(list(centers.values()), [f"{count} signatures" for count in COUNTS])
        axis.tick_params(axis="x", pad=42, length=0, labelsize=12)
        axis.set_xlim(-.8, centers[COUNTS[-1]] + .8)
        axis.set_ylim(0, max(row["total_max_s"] for row in phase_rows) + .65)
        axis_style(axis, "Time (seconds)", xlabel="")
        for left, right in zip(list(centers.values()), list(centers.values())[1:]):
            axis.axvline((left + right) / 2, color="#eeeeee", linewidth=.8, zorder=0)
        fig.suptitle("Figure 2D  Verification time breakdown", y=.97, fontsize=16)
        fig.text(.085, .915, "Falcon-512, ML-DSA-44 and research FORS; tree fan-in 4", fontsize=12)
        fig.legend(handles=[claim_bars[0], proof_bars[0]],
                   labels=["Commitment derivation", "Aggregated-proof verification"],
                   loc="center", ncol=2, bbox_to_anchor=(.53, .17), frameon=False, fontsize=12)
        fig.text(.08, .115, "Measured elapsed times: three paired runs per bar. Black labels show combined seconds; whiskers show the range.", fontsize=10.5)
        fig.text(.08, .082, "Purple labels below Falcon/FORS show commitment derivation in milliseconds.", fontsize=10.5)
        fig.text(.08, .049, "Commitment derivation uses the current Python frontend, including ML-DSA-44 expanded-key conversion.", fontsize=10.5)
        fig.text(.08, .016, "Totals exclude additional frontend inspection, process startup and proof loading.", fontsize=10.5)
        partial(fig)
        save_figure(fig, directory, "figure-2d-verification-clusters-labelled")
        plt.close(fig)

    fig = plt.figure(figsize=(10, 10))
    grid = fig.add_gridspec(2, 2, left=.10, right=.90, top=.94, bottom=.27,
                           height_ratios=[1, .9], hspace=.5, wspace=.4)
    axes = [fig.add_subplot(grid[0, 0]), fig.add_subplot(grid[0, 1]), fig.add_subplot(grid[1, :])]
    fan_rows = [row for row in data.trees if row["count"] == 100 and not row["leaf_sensitivity"] and
                (row["fan_in"] != 4 or row["merge_only"])]
    for scheme in SCHEMES:
        rows = [r for r in fan_rows if r["scheme"] == scheme]
        error_curve(axes[0], rows, "fan_in", "merge_prove_s", scheme)
        # A process contributes one RSS value even when it contains three merge passes.
        unique = list({r["report"]: r for r in rows}.values())
        error_curve(axes[1], unique, "fan_in", "peak_rss_bytes", scheme, scale=2**30)
    for axis in axes[:2]:
        axis.set_xticks([2, 4, 8])
    axis_style(axes[0], "All merge proving work (seconds)", "Fan-in, N=100")
    axis_style(axes[1], "Whole-process peak RSS (GiB)", "Fan-in, N=100")
    axis_style(axes[2], "Prover seconds per signature", "Signatures per leaf, N=100, fan-in 4")
    bytes_axis = axes[2].twinx()
    bytes_axis.set_ylabel("Aggregated proof size\n(KiB per signature)")
    bytes_axis.spines["top"].set_visible(False)
    leaf_rows = [r for r in data.trees if r["count"] == 100 and r["fan_in"] == 4 and
                 r["scheme"] in ("ethfalcon", "fors") and not r["merge_only"] and r["fresh_leaves"]]
    for scheme in ("ethfalcon", "fors"):
        rows = [r for r in leaf_rows if r["scheme"] == scheme]
        error_curve(axes[2], rows, "leaf_capacity", "prover_s_per_signature", scheme)
        error_curve(bytes_axis, rows, "leaf_capacity", "wire_bytes_per_signature", scheme, scale=1024, style=":", alpha=.7)
    axes[2].set_xticks([1, 2, 4, 5, 16])
    for i, title in enumerate(("A  Fan-in and merge work", "B  Memory of the measured process", "C  Leaf-size sensitivity")):
        axes[i].set_title(title)
    fig.legend(handles=legend, loc="center", ncol=3, bbox_to_anchor=(.52, .16), frameon=False)
    fig.text(.08, .095, "A/B: matched merge-only runs reuse verified leaves; RSS is whole-process.", fontsize=11)
    fig.text(.08, .065, "C: seconds solid/dashed; bytes dotted. Exact tails and padding are charged.", fontsize=11)
    fig.text(.08, .035, "Proving starts from prepared streams; Python fixture/advice preparation excluded.", fontsize=11)
    partial(fig)
    save_figure(fig, directory, "figure-3-efficiency-aggregated-proof")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=ROOT / "results/article")
    parser.add_argument("--records", type=Path, default=ROOT / "artifacts/article")
    parser.add_argument("--out", type=Path, default=ROOT / "results/article/figures")
    parser.add_argument("--allow-incomplete", action="store_true")
    args = parser.parse_args()
    data = Measurements(args.results, args.records, args.allow_incomplete)
    data.validate()
    args.out.mkdir(parents=True, exist_ok=True)
    write_csv(args.out / "direct-batches.csv", data.direct)
    write_csv(args.out / "recursive-trees.csv", data.trees)
    write_csv(args.out / "efficiency.csv", [row for row in data.trees if row["count"] == 100])
    write_csv(args.out / "native.csv", data.native)
    write_csv(args.out / "failures.csv", data.failures)
    wallet, main, table = summaries(data)
    write_csv(args.out / "wallet-costs.csv", wallet)
    write_csv(args.out / "main-tree-summary.csv", main)
    write_csv(args.out / "verification-phases.csv", [row for count in COUNTS
              for row in verification_phase_summary(data, count, schemes=VERIFICATION_SCHEMES)])
    (args.out / "article-table.md").write_text(table)
    (args.out / "measurements.json").write_text(json.dumps({"schema_version": 1,
        "direct": data.direct, "trees": data.trees, "native": data.native, "failures": data.failures,
        "warnings": data.warnings, "source_sha256": data.sources,
        "sampling": "main b4: fresh leaf/merge proofs from prepared inputs; b2/b8: repeated merges with checked reusable leaves",
        "proving_excludes": "Python fixture preparation, compact decoding, key expansion and Recorder arithmetic-advice generation before benchmark runs",
        "verification_cold_definition": "compile_plan + deferred table prepare + median edge evaluation + median cold root core",
        "verification_cached_definition": "median edge evaluation + median cached root core",
        "verification_excludes": "Python public-claim derivation, frontend compilation, CLI loading/deserialization",
        "capacity_policy": "only measured failures; unsupported ranges are gaps, never estimated successes"}, indent=2) + "\n")
    render(data, args.out)
    print(json.dumps({"direct_points": len(data.direct), "tree_samples": len(data.trees),
                      "failures": len(data.failures), "warnings": data.warnings, "output": str(args.out)}, indent=2))


if __name__ == "__main__":
    main()
