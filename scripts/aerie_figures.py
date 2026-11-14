#!/usr/bin/env python3
"""Plot measured native Aerie costs; never label these as leanVM proofs."""
from __future__ import annotations

import csv
import hashlib
import json
import os
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("MPLCONFIGDIR", str(ROOT / ".cache/matplotlib"))
COUNTS = (1, 10, 30, 70, 100, 1024, 8192, 32768)


def main():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import ScalarFormatter

    base = ROOT / "results/aerie"
    output = base / "figures"
    output.mkdir(parents=True, exist_ok=True)
    data, sources = {}, {}
    for threads in (1, 12):
        for count in COUNTS:
            path = base / "native" / f"falcon512-n{count}-t{threads}.json"
            encoded = path.read_bytes()
            report = json.loads(encoded)
            assert report["all_roundtrips_passed"]
            assert report["actual_records"] == count
            assert report["worker_threads"] == threads
            assert len(report["samples"]) == 3
            sources[str(path.relative_to(ROOT))] = hashlib.sha256(encoded).hexdigest()
            data[count, threads] = report

    rows = []
    for count in COUNTS:
        serial, parallel = data[count, 1], data[count, 12]
        samples = parallel["samples"]
        wire = statistics.median(s["envelope_bytes"] for s in samples)
        salts = 40 * count
        rows.append({"records": count, "padded_records": parallel["padded_records"],
            "native_prove_1_ms": serial["summary_ms"]["prove_ms"]["median"],
            "native_prove_12_ms": parallel["summary_ms"]["prove_ms"]["median"],
            "native_verify_1_ms": serial["summary_ms"]["verify_single_thread_ms"]["median"],
            "native_verify_12_ms": parallel["summary_ms"]["verify_parallel_ms"]["median"],
            "wire_bytes": wire, "salt_bytes": salts, "non_salt_wire_bytes": wire - salts,
            "raw_padded_signature_bytes": 666 * count,
            "process_peak_rss_12_bytes": parallel["process_peak_rss_bytes"],
            "native_setup_12_ms": parallel["summary_ms"]["setup_ms"]["median"]})
    with (output / "native-summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (output / "measurements.json").write_text(json.dumps({"schema_version": 1,
        "kind": "native Aerie; not leanVM or Aerie-to-leanSTARK measurements",
        "relation": "Falcon v1.2 padded, fn-dsa0.3.0 key-prefixed SHAKE, per-record salts",
        "summary": rows, "source_sha256": sources}, indent=2) + "\n")

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 12,
        "axes.labelsize": 12, "axes.titlesize": 13, "legend.fontsize": 11,
        "xtick.labelsize": 10, "ytick.labelsize": 11, "svg.fonttype": "none"})
    fig, axes = plt.subplots(1, 2, figsize=(10, 8.1))
    fig.subplots_adjust(left=.09, right=.98, top=.90, bottom=.40, wspace=.34)
    xs = [r["records"] for r in rows]
    for field, color, style, label in (
        ("raw_padded_signature_bytes", "#777777", "-.", "Original padded signatures"),
        ("wire_bytes", "#0072b2", "-", "Aerie: full wire aggregate"),
        ("non_salt_wire_bytes", "#d55e00", "--", "Aerie: wire excluding salts"),
        ("salt_bytes", "#009e73", ":", "40-byte salts")):
        axes[0].plot(xs, [r[field] / 1024 for r in rows], color=color,
                     linestyle=style, marker="o", markersize=4, label=label)
    axes[0].set_ylabel("Transport (KiB)")
    axes[0].set_title("A  Native Aerie transport")

    for threads, field, color, style, label in (
        (1, "prove_ms", "#0072b2", "--", "Prove, 1 thread"),
        (12, "prove_ms", "#0072b2", "-", "Prove, 12 threads"),
        (1, "verify_single_thread_ms", "#d55e00", "--", "Verify, 1 thread"),
        (12, "verify_parallel_ms", "#d55e00", "-", "Verify, 12 threads")):
        stats = [data[n, threads]["summary_ms"][field] for n in COUNTS]
        axes[1].errorbar(xs, [s["median"] for s in stats],
            yerr=[[s["median"] - s["min"] for s in stats],
                  [s["max"] - s["median"] for s in stats]],
            color=color, linestyle=style, marker="o", markersize=4,
            capsize=2, label=label)
    axes[1].set_ylabel("Native elapsed time (ms)")
    axes[1].set_title("B  Median and observed range")
    for axis in axes:
        axis.set_xscale("log")
        axis.set_yscale("log")
        axis.set_xlabel("Live signatures")
        axis.set_xticks([1, 10, 100, 1024, 32768])
        axis.xaxis.set_major_formatter(ScalarFormatter())
        axis.grid(axis="y", alpha=.25)
        axis.spines[["top", "right"]].set_visible(False)
        axis.legend(loc="upper left", bbox_to_anchor=(-.02, -.23), frameon=False, fontsize=10)
    fig.text(.08, .10, "M4 Pro, 24 GiB; one warmup and three native proof runs per point.", fontsize=11)
    fig.text(.08, .065, "Falcon v1.2 framing. Setup and signing excluded; keys/messages add transport.", fontsize=11)
    fig.text(.08, .03, "These are native Aerie results. No full Aerie verifier has been proved in leanVM.", fontsize=11)
    for extension in ("png", "svg"):
        fig.savefig(output / f"figure-4-aerie-native.{extension}", dpi=180, bbox_inches="tight")
    plt.close(fig)
    print(json.dumps({"native_cases": len(data), "summary_rows": len(rows), "output": str(output)}))


if __name__ == "__main__":
    main()
