#!/usr/bin/env python3
"""Plot actual full-wrapper samples and explicit measured capacity failures."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import statistics

ROOT=Path(__file__).resolve().parents[1]
os.environ.setdefault("MPLCONFIGDIR",str(ROOT/".cache/matplotlib"))
COLORS={"non-zk":"#0072b2","zk":"#d55e00"}
LABELS={"non-zk":"Outer leanSTARK, non-ZK","zk":"Outer leanSTARK, ZK"}


def stat(values):
    return {"median":statistics.median(values),"min":min(values),"max":max(values)} if values else None


def read_points(args,cohort="trusted-q64-cache",result_root=None):
    rows=[];sources={};missing=[]
    result_root=args.results if result_root is None else result_root
    for mode in args.modes:
        for count in args.counts:
            path=result_root/mode/f"n{count}"/"summary.json"
            if not path.exists():
                missing.append(f"{mode}/n{count}");continue
            encoded=path.read_bytes();a=json.loads(encoded)
            sources[str(path.resolve())]=hashlib.sha256(encoded).hexdigest()
            if a.get("records")!=count or a.get("requested_zero_knowledge")!=(mode=="zk"):
                raise ValueError(f"point identity differs from directory: {path}")
            complete=a.get("status")=="complete"
            capacity=a.get("status")=="measured_capacity_failure"
            if not complete and not capacity:
                raise ValueError(f"not a complete sample or measured capacity failure: {path}: {a.get('status')}")
            samples=a.get("samples",[]) if complete else a.get("native_samples",[])
            if complete and (len(samples)!=a.get("repeat") or not samples):
                raise ValueError(f"missing measured full-wrapper samples: {path}")
            inner=stat([s["inner_prove_s"] for s in samples])
            if inner is None and a.get("inner_prove_median_s") is not None:
                inner={"median":a["inner_prove_median_s"],"min":a["inner_prove_median_s"],"max":a["inner_prove_median_s"]}
            outer=stat([s["outer_prove_s"] for s in samples]) if complete else None
            total=stat([s["sum_prover_stage_work_s"] for s in samples]) if complete else None
            inner_bytes=stat([s["inner_proof_bytes"] for s in samples])
            outer_bytes=stat([s["outer_proof_bytes"] for s in samples]) if complete else None
            cycles=stat([s["cycles"] for s in samples]) if complete else None
            rss=stat([s["peak_rss_bytes"] for s in samples]) if complete else None
            interpreted=a.get("complete_guest_interpretation",{})
            interpretations=a.get("complete_guest_interpretations",[interpreted] if interpreted else [])
            valid_interpretations=[x for x in interpretations if x.get("status")=="ok" and x.get("public_output_checked") is True]
            if capacity and (len(valid_interpretations)!=a.get("repeat") or not valid_interpretations):
                raise ValueError(f"missing completed, output-checked interpreter samples: {path}")
            execution=stat([x["interpret_samples_s"][0] for x in valid_interpretations])
            lower=stat([x["interpreter_counts"]["packed_witness_lower_bound_words"] for x in valid_interpretations])
            limits={1<<x["max_commitment_log_words"] for x in valid_interpretations}
            if len(limits)>1:raise ValueError(f"inconsistent commitment limits: {path}")
            failure=a.get("failure",{})
            row={"cohort":cohort,"mode":mode,"records":count,"padded_records":a.get("padded_records"),
                "status":a["status"],"measured_samples":len(samples) if complete else 0,
                "measured_native_samples":len(samples),
                "measured_guest_samples":len(valid_interpretations),
                "elf_sha256":a.get("elf_sha256"),"inner_setup_s":a.get("inner_setup_s"),
                "native_inputs_integrity_sha256":a.get("native_inputs_integrity_sha256"),
                "canonical_statement_bytes":a.get("canonical_statement_bytes"),
                "inner_prove_s":inner,"outer_prove_s":outer,"sum_prover_stage_work_s":total,
                "inner_proof_bytes":inner_bytes,"outer_proof_bytes":outer_bytes,
                "cycles":cycles,"peak_rss_bytes":rss,
                "guest_interpretation_s":execution,"packed_witness_lower_bound_words":lower,
                "one_commitment_limit_words":next(iter(limits)) if limits else None,
                "capacity_error_kind":failure.get("error_kind") if capacity else None,
                "capacity_error":failure.get("error") if capacity else None,
                "complete_interpreter_output_checked":bool(valid_interpretations) and len(valid_interpretations)==len(interpretations),
                "interpreter_instructions":interpreted.get("interpreter_instructions"),
                "outer_proof_available":complete,"source_report":str(path.resolve()),
                "source_report_sha256":hashlib.sha256(encoded).hexdigest()}
            rows.append(row)
    if missing and not args.allow_incomplete:
        raise ValueError("missing requested points: "+", ".join(missing))
    if not rows:
        raise ValueError("no actual measurements to plot")
    return rows,sources,missing


def flattened(row):
    flat={}
    for key,value in row.items():
        if isinstance(value,dict):
            flat.update({key+"_"+part:number for part,number in value.items()})
        elif value is None and key in ("inner_prove_s","outer_prove_s","sum_prover_stage_work_s","inner_proof_bytes","outer_proof_bytes","cycles","peak_rss_bytes","guest_interpretation_s","packed_witness_lower_bound_words"):
            flat.update({key+"_"+part:None for part in ("median","min","max")})
        else:flat[key]=value
    return flat


def draw_curve(axis,counts,points,field,color,label,style="-",scale=1):
    values=[points.get(n,{}).get(field) for n in counts]
    if not any(v is not None for v in values):return False
    # NaNs break lines at unsupported/missing counts; no interpolation across failures.
    median=[v["median"]/scale if v is not None else math.nan for v in values]
    lower=[(v["median"]-v["min"])/scale if v is not None else math.nan for v in values]
    upper=[(v["max"]-v["median"])/scale if v is not None else math.nan for v in values]
    axis.errorbar(counts,median,yerr=[lower,upper],color=color,linestyle=style,
        marker="o",markersize=4.5,capsize=2.5,linewidth=1.7,label=label)
    return True


def render(args,rows,baseline_rows,missing):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D
    from matplotlib.ticker import NullLocator, ScalarFormatter, StrMethodFormatter

    plt.rcParams.update({"font.family":"DejaVu Sans","font.size":12,
        "axes.titlesize":13,"axes.labelsize":12,"xtick.labelsize":10,"ytick.labelsize":11,
        "legend.fontsize":10,"svg.fonttype":"none"})
    counts=args.counts
    all_unavailable=not any(row["outer_proof_available"] for row in rows)
    inner_groups={mode:{r["records"]:r for r in rows if r["mode"]==mode} for mode in args.modes}
    baseline_groups={mode:{r["records"]:r for r in baseline_rows if r["mode"]==mode} for mode in args.modes}

    def count_axis(axis):
        axis.set_xscale("log")
        axis.set_xlabel("Live signatures")
        axis.set_xticks(counts)
        axis.xaxis.set_major_formatter(ScalarFormatter())
        axis.xaxis.set_minor_locator(NullLocator())
        if len(counts)>1:axis.set_xlim(min(counts)*.8,max(counts)*1.25)
        axis.grid(axis="y",alpha=.25)
        axis.spines[["top","right"]].set_visible(False)

    # Native inputs are one shared immutable cohort in both proof modes.
    # Keep separate native lines only when measured cohorts actually differ.
    native_equal=True
    present_modes=[m for m,p in inner_groups.items() if p]
    if len(present_modes)>1:
        first=inner_groups[present_modes[0]]
        for mode in present_modes[1:]:
            for n,row in inner_groups[mode].items():
                other=first.get(n)
                if other and (row["inner_prove_s"]!=other["inner_prove_s"] or row["inner_proof_bytes"]!=other["inner_proof_bytes"]):
                    native_equal=False
    native_modes=present_modes[:1] if native_equal else present_modes
    if native_equal and present_modes:
        union={}
        for mode in present_modes:
            for count,row in inner_groups[mode].items():
                if count not in union or union[count]["inner_prove_s"] is None:union[count]=row
        native_points={present_modes[0]:union}
    else:native_points=inner_groups

    fig,axes=plt.subplots(1,2,figsize=(10,6.3 if all_unavailable else 8.5))
    fig.subplots_adjust(left=.09,right=.98,top=.90,bottom=.31 if all_unavailable else .42,wspace=.34)
    for index,mode in enumerate(native_modes):
        label="Native Aerie" if native_equal else f"Native Aerie ({mode} cohort)"
        color="#666666" if index==0 else "#999999"
        draw_curve(axes[0],counts,native_points[mode],"inner_prove_s",color,label,
            style="-",scale=.001 if all_unavailable else 1)
        draw_curve(axes[1],counts,native_points[mode],"inner_proof_bytes",color,label+" aggregate",style="-",scale=1024)
    for mode in args.modes:
        points=inner_groups[mode];color=COLORS[mode]
        draw_curve(axes[0],counts,points,"outer_prove_s",color,LABELS[mode])
        draw_curve(axes[0],counts,points,"sum_prover_stage_work_s",color,"Native + outer ("+mode+")",style=":")
        draw_curve(axes[1],counts,points,"outer_proof_bytes",color,LABELS[mode],scale=1024)
        failed=[r for r in points.values() if not r["outer_proof_available"]]
        # For mixed results, status markers use axis coordinates, never a
        # fabricated numeric value. When every outer proof failed, use a box.
        if failed and not all_unavailable:
            for axis in axes:
                for row in failed:
                    axis.plot(row["records"],.035+.045*args.modes.index(mode),marker="x",color=color,
                        transform=axis.get_xaxis_transform(),clip_on=False,markersize=7,markeredgewidth=1.6)
                axis.add_line(Line2D([],[],marker="x",linestyle="none",color=color,label="Unavailable outer ("+mode+")"))
    for axis in axes:
        count_axis(axis)
        if all_unavailable:
            axis.set_ylim(bottom=0)
            axis.yaxis.set_major_formatter(StrMethodFormatter("{x:g}"))
            axis.legend(loc="lower right",frameon=False,fontsize=10)
        else:
            axis.set_yscale("log")
            axis.yaxis.set_major_formatter(ScalarFormatter())
            axis.legend(loc="upper left",bbox_to_anchor=(-.02,-.23),frameon=False,fontsize=9.5)
    axes[0].set_title("A  Native Aerie proving" if all_unavailable else "A  Full-wrapper proving stages")
    axes[0].set_ylabel("Proving time (milliseconds)" if all_unavailable else "Measured proving work (seconds)")
    axes[1].set_title("B  Native aggregate proof size" if all_unavailable else "B  Actual inner and outer proof sizes")
    axes[1].set_ylabel("Proof payload (KiB)")
    if missing:fig.text(.99,.99,"PARTIAL: missing requested points",ha="right",va="top",fontsize=11,color="#777777")
    if all_unavailable:
        count_label=str(len(set(row["records"] for row in rows)))
        fig.text(.535,.145,"Outer leanSTARK unavailable at all "+count_label+" tested counts.\n"
            "All batches exceed leanVM's one-proof capacity. Outer time and size are not plotted.",
            ha="center",va="center",fontsize=10.5,color="#334455",
            bbox={"boxstyle":"round,pad=.7","facecolor":"#f0f3f5","edgecolor":"#cbd3d9"})
        fig.text(.08,.035,"M4 Pro. Medians and sample ranges. Setup excluded; inner proofs include salts.",fontsize=10.5)
    else:
        fig.text(.08,.105,"M4 Pro; pinned full Aerie verifier guest. Medians and observed sample ranges.",fontsize=11)
        fig.text(.08,.070,"× means a measured unavailable outer proof. Gaps are not zero or estimates.",fontsize=11)
        fig.text(.08,.035,"Inner includes salts; outer excludes trusted ELF and public statement. Setup is separate.",fontsize=11)
    for extension in ("png","svg"):
        fig.savefig(args.out/("figure-5-aerie-wrapper."+extension),dpi=180,bbox_inches="tight")
    plt.close(fig)

    # The exact interpreter can finish a full verification even when the
    # witness exceeds the commitment cap. This is execution, not proving.
    fig,axes=plt.subplots(1,2,figsize=(10,6.5))
    fig.subplots_adjust(left=.09,right=.98,top=.88,bottom=.28,wspace=.36)
    execution_max=0
    for mode in args.modes:
        suffix=" ("+mode+")" if len(args.modes)>1 else ""
        baseline=baseline_groups[mode]
        if baseline:
            draw_curve(axes[0],counts,baseline,"guest_interpretation_s","#777777","No terminal cache"+suffix,style="--")
            draw_curve(axes[1],counts,baseline,"packed_witness_lower_bound_words","#777777","No terminal cache"+suffix,style="--",scale=2**20)
        points=inner_groups[mode]
        draw_curve(axes[0],counts,points,"guest_interpretation_s",COLORS[mode],"Trusted Q64 cache"+suffix)
        draw_curve(axes[1],counts,points,"packed_witness_lower_bound_words",COLORS[mode],"Trusted Q64 cache"+suffix,scale=2**20)
        for row in list(points.values())+list(baseline.values()):
            value=row["guest_interpretation_s"]
            if value is not None:execution_max=max(execution_max,value["max"])
    limits={row["one_commitment_limit_words"] for row in rows+baseline_rows if row["one_commitment_limit_words"] is not None}
    if len(limits)>1:raise ValueError("cannot plot different one-proof commitment limits on one axis")
    if limits:axes[1].axhline(next(iter(limits))/2**20,color="#d55e00",linestyle=":",linewidth=1.7,label="One-proof limit")
    axes[0].set_title("A  Full verifier execution, without a proof")
    axes[0].set_ylabel("Reference interpreter (seconds)")
    axes[0].set_ylim(0,execution_max*1.1 if execution_max else 1)
    axes[0].yaxis.set_major_formatter(StrMethodFormatter("{x:g}"))
    axes[1].set_title("B  Measured witness capacity")
    axes[1].set_ylabel("Packed witness bound (2²⁰ words)")
    axes[1].set_yscale("log",base=2)
    axes[1].yaxis.set_major_formatter(StrMethodFormatter("{x:,.0f}"))
    axes[1].yaxis.set_minor_locator(NullLocator())
    for index,axis in enumerate(axes):
        count_axis(axis)
        axis.legend(loc="lower right" if index==0 else "center left",frameon=False,fontsize=9.5)
    fig.text(.08,.125,"Same native proofs and public claims; both guests check the complete verifier and output.",fontsize=10.5)
    fig.text(.08,.075,"Medians and sample ranges. Witness bound omits other columns and fill rows.",fontsize=10.5)
    fig.text(.08,.025,"VM execution time and witness words are neither proof size nor estimated proving time.",fontsize=10.5)
    for extension in ("png","svg"):
        fig.savefig(args.out/("figure-6-aerie-vm-capacity."+extension),dpi=180,bbox_inches="tight")
    plt.close(fig)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results",type=Path,default=ROOT/"results/aerie-wrapper")
    parser.add_argument("--out",type=Path,default=ROOT/"results/aerie-wrapper/figures")
    parser.add_argument("--counts",type=int,nargs="+",default=[1,10,30,70,100])
    parser.add_argument("--modes",nargs="+",choices=("non-zk","zk"),default=["non-zk","zk"])
    parser.add_argument("--allow-incomplete",action="store_true")
    args=parser.parse_args();args.counts=sorted(set(args.counts));args.modes=list(dict.fromkeys(args.modes))
    if not args.counts or any(n<1 for n in args.counts):parser.error("positive counts required")
    rows,sources,missing=read_points(args)
    baseline_rows=[];baseline_sources={}
    if (args.results/"baseline").is_dir():
        baseline_rows,baseline_sources,baseline_missing=read_points(args,
            cohort="baseline-no-terminal-cache",result_root=args.results/"baseline")
        missing.extend("baseline/"+item for item in baseline_missing)
        primary={(row["mode"],row["records"]):row for row in rows}
        for row in baseline_rows:
            other=primary.get((row["mode"],row["records"]))
            if other and row["native_inputs_integrity_sha256"]!=other["native_inputs_integrity_sha256"]:
                raise ValueError("baseline does not use the same native proof cohort: "+row["source_report"])
    sources.update(baseline_sources)
    args.out.mkdir(parents=True,exist_ok=True)
    all_rows=rows+baseline_rows
    flat=[flattened(row) for row in all_rows];columns=list(dict.fromkeys(key for row in flat for key in row))
    with(args.out/"wrapper-summary.csv").open("w",newline="")as stream:
        writer=csv.DictWriter(stream,fieldnames=columns);writer.writeheader();writer.writerows(flat)
    (args.out/"measurements.json").write_text(json.dumps({"schema_version":1,
        "scope":"Actual complete-verifier wrapper samples, with measured failures unavailable",
        "plotting_script_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "source_sha256":sources,"baseline_source_sha256":baseline_sources,
        "rows":all_rows,"missing_requested_points":missing,
        "null_semantics":"Unavailable outer proving time/size is null, never zero or inferred",
        "total_work_semantics":"Sum of measured native Aerie and outer proving intervals for matched samples, not distributed latency",
        "public_transport_excluded":"Trusted ELF/program deployment and intended keys/messages statement"},indent=2)+"\n")
    render(args,rows,baseline_rows,missing)
    print(json.dumps({"loaded_points":len(rows),"complete_outer_points":sum(r["outer_proof_available"] for r in rows),
        "measured_capacity_failures":sum(not r["outer_proof_available"] for r in rows),
        "matched_baseline_points":len(baseline_rows),"missing":missing,"output":str(args.out)}))


if __name__=="__main__":main()
