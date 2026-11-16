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




