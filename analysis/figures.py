"""Figures from raw results (no numbers are typed in by hand).

    python analysis/figures.py

fig1_faults_ecdf.png  share of keys whose 64/96 master key is recovered after <= n faults
                      (strict stop rule), M1 and M2 panels, dipper vs the analysis-only variants
fig2_survivors.png    median log2(surviving rk27 candidates) vs number of faults, M1, stage 1
"""
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

RAW = "results/raw"
OUT = "figures"
# validated default categorical palette, slots 1-3 in fixed order (dataviz skill reference)
COL = {"dipper": "#2a78d6", "xor": "#eb6834", "none": "#1baf7a"}
LS = {"dipper": "-", "xor": "--", "none": ":"}
TEXT, MUTED, GRID = "#1f1f1e", "#5f5e5a", "#e4e3df"

plt.rcParams.update({
    "font.size": 9, "axes.edgecolor": MUTED, "axes.labelcolor": TEXT, "xtick.color": MUTED,
    "ytick.color": MUTED, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "savefig.dpi": 300,
})


def load(name):
    return [json.loads(l) for l in open(f"{RAW}/{name}.jsonl")]


def ecdf_panel(ax, runs, title):
    for v, name, label in runs:
        r = load(name)
        f = np.sort([x["total_faults"] for x in r if x["success"]])
        y = np.arange(1, len(f) + 1) / len(r)
        med = np.median(f)
        ax.step(f, y, where="post", color=COL[v], ls=LS[v], lw=2, label=f"{label}: median {med:.0f}")
    ax.set_title(title, color=TEXT, fontsize=9, loc="left")
    ax.legend(loc="lower right", fontsize=7, frameon=False, labelcolor=TEXT)
    ax.set_xlabel("faulty ciphertexts (total, both stages)")
    ax.set_ylim(0, 1.02)


def fig1():
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.9), sharey=True)
    ecdf_panel(axes[0], [("dipper", "d96_M1_strict", "dipper (fault at T-1)"),
                         ("xor", "xor96_M1_deep_strict", "xor (fault at T-2)"),
                         ("none", "none96_M1_deep_strict", "none (fault at T-2)")],
               "M1: one random nibble")
    ecdf_panel(axes[1], [("dipper", "dipper96_M2_near_strict", "dipper"),
                         ("xor", "xor96_M2_near_strict", "xor"),
                         ("none", "none96_M2_near_strict", "none")],
               "M2: one random bit (fault at T-1, all variants)")
    axes[0].set_ylabel("share of keys recovered")
    fig.text(0.01, 0.005, "64/96, 1000 random keys per curve, strict stop rule. xor and none are analysis-only variants.",
             color=MUTED, fontsize=7)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(f"{OUT}/fig1_faults_ecdf.png")
    plt.close(fig)


def fig2():
    fig, ax = plt.subplots(figsize=(4.6, 3.0))
    for v, name, label in [("dipper", "d96_M1_strict", "dipper, fault at round 26"),
                           ("xor", "xor96_M1_deep_strict", "xor, fault at round 25"),
                           ("none", "none96_M1_deep_strict", "none, fault at round 25")]:
        r = load(name)
        st = [x["stages"][0] for x in r]
        fmax = 120
        xs, med, exact = [], [], []
        for f in range(fmax):
            # a key that stopped earlier keeps its final count
            vals, cap = [], 0
            for s in st:
                k = min(f, len(s["log2_surv"]) - 1)
                vals.append(s["log2_surv"][k]); cap += s["capped"][k]
            xs.append(f + 1); med.append(np.median(vals)); exact.append(cap / len(st) <= 0.5)
        xs, med, exact = np.array(xs), np.array(med), np.array(exact)
        ax.plot(xs, np.where(exact, med, np.nan), color=COL[v], ls=LS[v], lw=2, label=label)
        ax.plot(xs, np.where(~exact, med, np.nan), color=COL[v], ls=LS[v], lw=1, alpha=0.5)
    ax.legend(loc="upper right", fontsize=7, frameon=False, labelcolor=TEXT)
    ax.set_xlabel("faults used for rk27")
    ax.set_ylabel("median log2(rk27 candidates)")
    ax.set_title("Surviving candidates for rk27, M1, 64/96", color=TEXT, fontsize=9, loc="left")
    fig.text(0.01, 0.005, "Thin part: >50% of keys hit the node cap; there the median is a lower bound.",
             color=MUTED, fontsize=7)
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(f"{OUT}/fig2_survivors.png")
    plt.close(fig)


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    fig1()
    fig2()
    print("wrote", sorted(os.listdir(OUT)))
