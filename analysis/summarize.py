"""Summaries of raw DFA runs.

    python3 analysis/summarize.py results/raw/<name>.jsonl [...]

For each file writes results/summary/<name>.json and prints one Markdown row.
All numbers are computed from the raw lines; nothing is estimated.
"""
import json
import math
import os
import statistics as st
import sys
from collections import Counter


def q(xs, p):
    xs = sorted(xs)
    if not xs:
        return None
    k = (len(xs) - 1) * p
    lo, hi = math.floor(k), math.ceil(k)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def dist(xs):
    return {"n": len(xs), "mean": st.mean(xs), "median": st.median(xs), "min": min(xs), "max": max(xs),
            "p90": q(xs, 0.9), "p99": q(xs, 0.99), "hist": sorted(Counter(xs).items())}


def survivors_curve(stages_list, idx, fmax=200):
    """log2 survivors after f faults in stage idx; only keys whose stage ran >= f faults.
    Values flagged 'capped' are lower bounds; their share is reported."""
    out = []
    for f in range(fmax):
        vals, capped = [], 0
        for stg in stages_list:
            if idx >= len(stg):
                continue
            s = stg[idx]
            if f < len(s["log2_surv"]):
                vals.append(s["log2_surv"][f])
                capped += s["capped"][f]
        if not vals:
            break
        out.append({"f": f + 1, "keys": len(vals), "mean_log2": st.mean(vals), "median_log2": st.median(vals),
                    "min_log2": min(vals), "max_log2": max(vals), "capped_share": capped / len(vals)})
    return out


def summarize(path):
    rows = [json.loads(l) for l in open(path)]
    name = os.path.basename(path).rsplit(".", 1)[0]
    r0 = rows[0]
    ok = [r for r in rows if r["ok"]]
    res = {
        "name": name, "variant": r0["variant"], "ks": r0["ks"], "opt": r0["opt"], "model": r0["model"],
        "mode": r0.get("mode", "near"), "seed": r0["seed"], "floor": r0["floor"], "theta": r0.get("theta"),
        "node_cap": r0["node_cap"], "keys": len(rows),
        "stage_rule_met": len(ok),
        "success": sum(r["success"] for r in rows),
        "true_tuple_kept": sum(r.get("true_tuple", 0) for r in rows),
        "total_faults": dist([r["total_faults"] for r in ok]) if ok else None,
        "masters_checked": dist([r["masters"] for r in ok]) if ok else None,
        "pc_match": dist([r["pc_match"] for r in ok]) if ok else None,
        "tuples_final": dist([r["tuples_final"] for r in ok]) if ok else None,
        "cpu_s": dist([round(r["cpu"], 3) for r in rows]),
        "stages": [],
    }
    nst = max(len(r["stages"]) for r in rows)
    stages_list = [r["stages"] for r in rows]
    for i in range(nst):
        ss = [r["stages"][i] for r in rows if i < len(r["stages"])]
        res["stages"].append({
            "target": ss[0]["target"], "fault_round": ss[0]["fault_round"], "keys": len(ss),
            "reached": sum(s["reached"] for s in ss), "true_kept": sum(s["true_kept"] for s in ss),
            "faults": dist([s["faults"] for s in ss if s["reached"]]) if any(s["reached"] for s in ss) else None,
            "prefixes_in": dist([s["prefixes_in"] for s in ss]),
            "live_end": dist([s["live_end"] for s in ss if s["reached"]]) if any(s["reached"] for s in ss) else None,
            "cands_out": dist([s["cands_out"] for s in ss if s["reached"]]) if any(s["reached"] for s in ss) else None,
            "nodes": dist([s["nodes"] for s in ss]),
            "level_max_max": max(s["level_max"] for s in ss),
            "cpu_s": dist([round(s["cpu"], 3) for s in ss]),
            "survivors": survivors_curve(stages_list, i),
        })
    os.makedirs("results/summary", exist_ok=True)
    for d in [res["total_faults"], res["cpu_s"]] + [s["faults"] for s in res["stages"]]:
        pass
    with open(f"results/summary/{name}.json", "w") as fh:
        json.dump(res, fh, indent=1)
    tf = res["total_faults"]
    stf = " / ".join(f"{s['faults']['mean']:.1f}" if s["faults"] else "-" for s in res["stages"])
    mc = res["masters_checked"]
    print(f"| {name} | {res['variant']} | {res['ks']}{res['opt'] if res['opt'] != '-' else ''} | M{res['model']} | {res['mode']} | "
          f"{res['theta'] if res['theta'] is not None and res['theta'] >= 0 else 'floor'} | {res['keys']} | "
          f"{res['success']}/{res['keys']} | "
          + (f"{tf['mean']:.1f} | {tf['median']:.0f} | {tf['max']} | {stf} | {mc['max']} | " if tf else "- | - | - | - | - | ")
          + f"{res['cpu_s']['mean']:.2f} |")


if __name__ == "__main__":
    print("| run | variant | key | model | mode | stop | keys | success | faults mean | median | max | per stage (mean) | max masters checked | CPU s/key |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for p in sys.argv[1:]:
        summarize(p)
