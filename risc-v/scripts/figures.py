#!/usr/bin/env python3
"""Generate PGFPlots figures from actual accepted, verified RISC-V proof reports.

Only completed `prove` reports are plotted. There is no interpolation of missing
measurements or projection beyond the measured signature counts. Lines connect
measured points for readability. LaTeX/PGFPlots produces PDFs; pdftoppm produces
PNG previews of those same PDFs.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SCHEMES = {
    "falcon": ("Falcon-512", "falconblue", "*"),
    "mldsa": ("ML-DSA-44", "mldsaorange", "square*"),
    "fors": ("FORS", "forsgreen", "triangle*"),
}
CAP = 2**28


def median(values):
    return statistics.median(float(value) for value in values)


def read_reports(directory):
    rows = []
    sources = []
    for scheme in SCHEMES:
        for path in sorted(directory.glob(f"{scheme}-*.json")):
            try:
                raw = path.read_bytes()
                data = json.loads(raw)
            except json.JSONDecodeError:
                print(f"Skipping incomplete report: {path}", file=sys.stderr)
                continue
            if (data.get("action") != "prove" or data.get("status") != "accepted"
                    or data.get("verified") is not True):
                continue
            if data.get("scheme") != scheme:
                raise ValueError(f"Scheme mismatch: {path}")
            times, verifies = data.get("prove_s", []), data.get("verify_s", [])
            if not times or not verifies:
                raise ValueError(f"Accepted proof has no timing samples: {path}")
            count = int(data["count"])
            if count < 1:
                raise ValueError(f"Invalid count: {path}")
            sizes = data.get("proof_bytes_samples", [data["proof_bytes"]])
            committed = int(data["execution"]["committed_words"])
            row = {
                "scheme": scheme,
                "count": count,
                "proof_kib": median(sizes) / 1024,
                "prove_s": median(times),
                "prove_min_s": min(times),
                "prove_max_s": max(times),
                "prove_error_minus_s": median(times) - min(times),
                "prove_error_plus_s": max(times) - median(times),
                "verify_ms": 1000 * median(verifies),
                "verify_min_ms": 1000 * min(verifies),
                "verify_max_ms": 1000 * max(verifies),
                "verify_error_minus_ms": 1000 * (median(verifies) - min(verifies)),
                "verify_error_plus_ms": 1000 * (max(verifies) - median(verifies)),
                "rss_gib": int(data["peak_rss_bytes"]) / 2**30,
                "committed_words": committed,
                "capacity_percent": 100 * committed / CAP,
                "prove_per_signature_ms": 1000 * median(times) / count,
                "prove_per_signature_error_minus_ms": 1000 * (median(times) - min(times)) / count,
                "prove_per_signature_error_plus_ms": 1000 * (max(times) - median(times)) / count,
                "cycles": int(data["execution"]["cycles"]),
            }
            rows.append(row)
            sources.append({
                "path": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "backend_revision": data["leanvm_revision"],
                "threads": data["threads"],
                "log_inverse_rate": data["log_inverse_rate"],
                "samples": len(times),
                "warmup": data["warmup"],
                "elf_sha256": data["elf_sha256"],
            })
    rows.sort(key=lambda row: (list(SCHEMES).index(row["scheme"]), row["count"]))
    if not rows:
        raise ValueError("No completed accepted and verified prove reports")
    if len({(row["scheme"], row["count"]) for row in rows}) != len(rows):
        raise ValueError("Duplicate scheme/count measurements")
    for key in ("backend_revision", "threads", "log_inverse_rate"):
        if len({source[key] for source in sources}) != 1:
            raise ValueError(f"Mixed experiment configuration: {key}")
    for scheme in SCHEMES:
        selected = [source["elf_sha256"] for source in sources if Path(source["path"]).name.startswith(scheme + "-")]
        if len(set(selected)) > 1:
            raise ValueError(f"Mixed guest ELF identities for {scheme}; rerun on one build")
    return rows, sources


def write_csv(path, rows):
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def tex_document(left, right, rows, output_dir):
    maximum = max(row["count"] for row in rows)
    ticks = [2**i for i in range(math.ceil(math.log2(maximum)) + 1)]
    if maximum == 1:
        ticks = [1, 2]
    tick_string = ",".join(map(str, ticks))
    plots = []
    for panel, (field, ylabel, title) in enumerate((left, right)):
        options = [f"ylabel={{{ylabel}}}", f"title={{{title}}}"]
        if field == "capacity_percent":
            options += ["ymin=0", "ymax=107", "ytick={0,25,50,75,100}"]
        elif field == "proof_kib":
            options += [f"ymin={min(row[field] for row in rows) * 0.90:.5f}"]
        else:
            options += ["ymin=0"]
        plots.append("\\begin{axis}[paperaxis,name=panel" + str(panel) + ",at={(" + str(panel * 8.6) + "cm,0cm)}," + ",".join(options) + "]")
        for scheme, (label, color, mark) in SCHEMES.items():
            if not any(row["scheme"] == scheme for row in rows):
                continue
            error_columns = {
                "prove_s": ("prove_error_minus_s", "prove_error_plus_s"),
                "verify_ms": ("verify_error_minus_ms", "verify_error_plus_ms"),
                "prove_per_signature_ms": ("prove_per_signature_error_minus_ms", "prove_per_signature_error_plus_ms"),
            }
            plot_options = f"color={color},mark={mark},mark size=2.1pt"
            table_options = f"x=count,y={field},col sep=comma"
            if field in error_columns:
                minus, plus = error_columns[field]
                plot_options += ",error bars/.cd,y dir=both,y explicit,error bar style={line width=0.65pt},error mark options={rotate=90,mark size=2pt}"
                table_options += f",y error minus={minus},y error plus={plus}"
            plots.append(
                f"\\addplot+[{plot_options}] "
                f"table[{table_options}] {{{scheme}.csv}};"
            )
            if panel == 0:
                plots.append(f"\\addlegendentry{{{label}}}")
        if field == "capacity_percent":
            xmax = max(2, 2 ** math.ceil(math.log2(maximum)) * 1.05)
            plots.append(
                "\\addplot[color=gray,dashed,no marks,forget plot] "
                f"coordinates {{(1,100) ({xmax:.8g},100)}};"
            )
            plots.append("\\node[anchor=north east,font=\\scriptsize,text=gray] at (rel axis cs:0.98,0.94) {$2^{28}$ words};")
        plots.append("\\end{axis}")
    document = r"""\documentclass[tikz,border=5pt]{standalone}
\usepackage{pgfplots}
\pgfplotsset{compat=1.18}
\definecolor{falconblue}{HTML}{0072B2}
\definecolor{mldsaorange}{HTML}{D55E00}
\definecolor{forsgreen}{HTML}{009E73}
\begin{document}
\begin{tikzpicture}
\pgfplotsset{paperaxis/.style={
  width=7.1cm,height=5.3cm,
  xlabel={Signatures per batch},
  xmode=log,log basis x=2,
  xtick={TICKS},xticklabels={TICKS},
  xmin=0.9,xmax=XMAX,
  grid=major,grid style={gray!15},
  axis line style={gray!65},tick style={gray!65},
  line width=0.9pt,
  tick label style={font=\small},
  label style={font=\small},title style={font=\small},
  scaled y ticks=false,
  legend style={font=\small,draw=none,fill=none,at={(1.15,1.2)},anchor=south,legend columns=-1},
  legend cell align=left,
  unbounded coords=discard,
}}
PLOTS
\end{tikzpicture}
\end{document}
""".replace("TICKS", tick_string).replace("XMAX", f"{max(2, 2 ** math.ceil(math.log2(maximum)) * 1.05):.8g}").replace("PLOTS", "\n".join(plots))

    # Axis options are kept explicit. Applying a user style during TikZ's own
    # option pass resolves unqualified keys under /tikz instead of /pgfplots.
    prefix = "\\pgfplotsset{paperaxis/.style={"
    start = document.index(prefix)
    end = document.index("}}\n", start) + 3
    options = document[start + len(prefix):end - 3]
    document = document[:start] + document[end:]
    return document.replace("[paperaxis,", "[" + options + ",")


def prepare_tex_cache(destination):
    original = Path.home() / "Library/Caches/Tectonic"
    if not destination.exists():
        if original.exists():
            shutil.copytree(original, destination)
        else:
            destination.mkdir(parents=True)
    bundle = destination / "offline-bundle.zip"
    if not bundle.exists():
        resources = next((path for path in (destination / "bundles/data").iterdir() if path.is_dir()), None)
        if resources is None:
            raise RuntimeError("No cached Tectonic resources available")
        with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in resources.rglob("*"):
                if path.is_file():
                    archive.write(path, path.relative_to(resources))
            archive.writestr("SHA256SUM", resources.name + "\n")


def render(tex, cache):
    env = os.environ.copy()
    env["TECTONIC_CACHE_DIR"] = str(cache)
    command = ["tectonic", "--bundle", str(cache / "offline-bundle.zip"), "--only-cached", "--keep-logs", "--outdir", str(tex.parent), str(tex)]
    completed = subprocess.run(command, cwd=tex.parent, env=env, text=True, capture_output=True)
    (tex.with_suffix(".render.log")).write_text(completed.stdout + completed.stderr)
    if completed.returncode:
        raise RuntimeError(f"LaTeX failed; see {tex.with_suffix('.render.log')}")
    subprocess.run([
        "pdftoppm", "-png", "-singlefile", "-r", "180", str(tex.with_suffix(".pdf")), str(tex.with_suffix(""))
    ], check=True, capture_output=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=ROOT / "risc-v/results/direct")
    parser.add_argument("--output", type=Path, default=ROOT / "risc-v/figures")
    parser.add_argument("--render", action="store_true", help="Compile the generated LaTeX and rasterize its PDFs")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    rows, sources = read_reports(args.results.resolve())
    write_csv(output / "measurements.csv", rows)
    for scheme in SCHEMES:
        selected = [row for row in rows if row["scheme"] == scheme]
        if selected:
            write_csv(output / f"{scheme}.csv", selected)
    figures = {
        "figure-1-batching": (("proof_kib", "Proof size (KiB)", "Proof size"), ("prove_s", "Proving time (s)", "Proving time")),
        "figure-2-verification-memory": (("verify_ms", "Verification time (ms)", "Verification"), ("rss_gib", "Peak process RSS (GiB)", "Prover memory")),
        "figure-3-capacity-efficiency": (("capacity_percent", "Commitment budget used (\\%)", "Capacity"), ("prove_per_signature_ms", "Proving time per signature (ms)", "Amortized proving time")),
    }
    for name, (left, right) in figures.items():
        tex = output / f"{name}.tex"
        tex.write_text(tex_document(left, right, rows, output))
        if args.render:
            cache = output / ".tectonic-cache"
            prepare_tex_cache(cache)
            render(tex, cache)
    metadata = {
        "source_reports": sources,
        "plotted_measurements": len(rows),
        "schemes_present": [scheme for scheme in SCHEMES if any(row["scheme"] == scheme for row in rows)],
        "statistics": "Points are medians; vertical error bars span the recorded minimum to maximum proof/verification times. One process RSS high-water per report.",
        "capacity_words": CAP,
        "missing_or_rejected_measurements": "Not plotted; no extrapolation.",
        "curve_lines": "Straight line segments connect measured points only.",
        "rendering": "LaTeX/PGFPlots via Tectonic; PNG previews rasterized from the same PDFs by pdftoppm at180dpi.",
    }
    (output / "provenance.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps({"measurements": len(rows), "schemes": metadata["schemes_present"], "output": str(output), "rendered": args.render}))


if __name__ == "__main__":
    main()
