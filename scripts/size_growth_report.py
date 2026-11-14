#!/usr/bin/env python3
"""Build a size-only study from verified proofs; never interpolate missing proofs."""
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results/size-growth"
STUDIES = [
    ("ethfalcon", "ethFalcon-512", "size-growth-falcon", ROOT / "results/size-growth-falcon/ethfalcon-6.failed.json"),
    ("ethdilithium", "ethDilithium2", "size-growth-dilithium", ROOT / "results/2026-11-03-dilithium/ethdilithium-2.failed.json"),
    ("fors", "FORS research", "size-growth-fors", None),
]


def collect():
    rows = []
    for scheme, label, folder, failure_path in STUDIES:
        failure = json.loads(failure_path.read_text()) if failure_path else None
        failed_at = failure["count"] if failure else None
        for count in range(1, 31):
            report = ROOT / "results" / folder / f"{scheme}-{count}.json"
            row = {"scheme": scheme, "label": label, "signatures": count,
                   "status": "not_run", "proof_bytes": None, "proof_kib": None,
                   "guest_hash": None, "source_report": None, "reason": None}
            if report.exists():
                data = json.loads(report.read_text())
                assert data["verified"] and data["metadata"]["count"] == count
                artifact = ROOT / "artifacts" / folder / f"{scheme}-{count}.proof"
                assert artifact.stat().st_size == data["proof_bytes"]
                checked = json.loads(report.with_suffix(".verify.json").read_text())
                for field in ("guest_hash", "public_input_hex", "proof_bytes"):
                    assert checked[field] == data[field]
                row.update(status="verified", proof_bytes=data["proof_bytes"],
                           proof_kib=data["proof_bytes"] / 1024, guest_hash=data["guest_hash"],
                           source_report=str(report.relative_to(ROOT)))
            elif count == failed_at:
                row.update(status="capacity_failure", source_report=str(failure_path.relative_to(ROOT)), reason=failure["error"])
            elif failed_at is not None and count > failed_at:
                row["reason"] = f"Not run after the witness-size cap was observed at N={failed_at}; no proof-size estimate."
            else:
                raise ValueError(f"unexplained missing measurement: {scheme} N={count}")
            rows.append(row)
    return rows


def write_outputs(rows):
    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / "proof-sizes.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (OUT / "proof-sizes.json").write_text(json.dumps({"kind": "measured_single_proof_sizes", "inverse_rate_log": 1,
                                                     "bytes_exclude": ["statements", "keys", "shared_bytecode", "dependency_frames"],
                                                     "rows": rows}, indent=2) + "\n")
    by_key = {(r["scheme"], r["signatures"]): r for r in rows}
    lines = ["# Single-proof sizes for 1 through 30 signatures", "",
             "These are actual serialized proof payloads, each verified in a fresh process. They are not recursively aggregated proofs or sums of leaf files. One proof was generated per count at inverse-rate logarithm 1. Size may vary with the input, transcript and pruned Merkle paths. Falcon uses the corrected verifier, without the erroneous 625-byte payload policy. Dilithium replays the saved input from the earlier study.", "",
             "![Measured proof sizes](proof-size-growth.png)", "",
             "| Signatures | ethFalcon KiB | ethDilithium KiB | Research FORS KiB |",
             "|---:|---:|---:|---:|"]
    for count in range(1, 31):
        cells = []
        for scheme, _, _, _ in STUDIES:
            r = by_key[(scheme, count)]
            cells.append(f"{r['proof_kib']:.1f}" if r["status"] == "verified" else
                         "capacity failure" if r["status"] == "capacity_failure" else "not run after cap")
        lines.append(f"| {count} | " + " | ".join(cells) + " |")
    lines += ["", "Falcon N=6 and Dilithium N=2 require log committed size 29; the pinned backend accepts at most 28. Counts after the first failed size were not attempted. Those blank ranges are not claims of measured failure at every individual count. A later [recursive experiment](../recursive-30/REPORT.md) now covers 30 ETHFALCON signatures using six leaves and one root; it is a different topology from these direct-batch curves.", "",
              "FORS size is not monotonic. Power-of-two stacking changes the fraction of committed lanes carrying real data. The backend omits zero tail lanes from Merkle openings; query/path structure also varies. For example, going from N=4 to N=5 reduces opened first-phase field words from 13,380 to 8,028, while the scalar stream grows from 47,696 to 47,840 bytes. The total proof shrinks from 270,584 to 237,904 bytes. This is a measured transport/layout effect, not skipped signature verification.", "",
              "Exact byte counts, statuses and program hashes are in [CSV](proof-sizes.csv) and [JSON](proof-sizes.json). The sibling size-growth directories contain every successful proof report, cached-verification report, failed-capacity log and proof-encoding breakdown. The full proof files and witness-free statements are under `artifacts/size-growth-*`. Use `scripts/verify_saved.py` to recheck them.", "",
              "The relations use different encodings and are not security-equivalent. In particular, standalone deterministic FORS is a few-time research component with a chosen-message birthday limitation, and Dilithium authenticates a registered expanded key rather than proving expansion from the compact key. See [the encoding review](../../docs/encoding-review.md).", ""]
    (OUT / "REPORT.md").write_text("\n".join(lines))


def plot(rows):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    measured = [row["proof_kib"] for row in rows if row["status"] == "verified"]
    low, high = min(measured), max(measured)
    margin = (high - low) * 0.16
    fig, axes = plt.subplots(3, 1, figsize=(8.5, 7.4), sharex=True, sharey=True)
    colors = ["#b75818", "#7554a3", "#27649b"]
    for ax, (scheme, label, _, _), color in zip(axes, STUDIES, colors):
        points = [row for row in rows if row["scheme"] == scheme and row["status"] == "verified"]
        failures = [row for row in rows if row["scheme"] == scheme and row["status"] == "capacity_failure"]
        ax.plot([p["signatures"] for p in points], [p["proof_kib"] for p in points], color=color,
                marker="o", markersize=4, linewidth=1.5)
        ax.set_title(label, loc="left", fontsize=11, fontweight="medium", pad=6)
        ax.set_ylabel("Proof size (KiB)", fontsize=10)
        ax.set_ylim(low - margin, high + margin)
        ax.set_xlim(0.3, 30.7)
        ax.grid(axis="y", color="#e2e5e9", linewidth=0.6)
        ax.spines[["top", "right"]].set_visible(False)
        ax.spines[["left", "bottom"]].set_color("#999999")
        ax.tick_params(labelsize=9, labelbottom=True)
        if failures:
            first = failures[0]["signatures"]
            ax.axvspan(first - 0.45, 30.7, color="#f0f1f3", zorder=0)
            ax.axvline(first - 0.45, color="#9d9d9d", linestyle="--", linewidth=0.9)
            ax.text((first + 30) / 2, (low + high) / 2,
                    f"Witness cap reached at N={first}\nLater counts not run", ha="center", va="center",
                    color="#4c5058", fontsize=10)
        for p in (points[:1] if len(points) == 1 else [points[0], points[-1]]):
            last = p is points[-1] and len(points) > 1
            dx = -7 if p["signatures"] > 25 else 8
            dy = -17 if not last else 9
            ax.annotate(f"{p['proof_kib']:.1f} KiB", (p["signatures"], p["proof_kib"]),
                        xytext=(dx, dy), textcoords="offset points", fontsize=9,
                        ha="right" if dx < 0 else "left", color=color)
    axes[-1].set_xlabel("Signatures in one proof (N)", fontsize=11)
    axes[-1].set_xticks([1, 5, 10, 15, 20, 25, 30])
    fig.suptitle("Direct-batch proof size from 1 to 30 signatures", fontsize=14, x=0.11, ha="left")
    fig.text(0.11, 0.024, "Direct batches · 1 KiB = 1,024 bytes · rate 1 · recursive result reported separately", fontsize=9, color="#555555")
    fig.subplots_adjust(left=0.11, right=0.97, top=0.91, bottom=0.10, hspace=0.46)
    fig.savefig(OUT / "proof-size-growth.png", dpi=180, facecolor="white")
    fig.savefig(OUT / "proof-size-growth.svg", facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    data = collect()
    write_outputs(data)
    plot(data)
    print(OUT / "REPORT.md")
