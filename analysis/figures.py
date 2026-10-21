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


# ---------------------------------------------------------------- extra figures for the long paper
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch


def _box(ax, x, y, w, h, text, fc="#ffffff", ec=MUTED, fs=8, bold=False):
    ax.add_patch(FancyBboxPatch((x - w / 2, y - h / 2), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
                                fc=fc, ec=ec, lw=1))
    ax.text(x, y, text, ha="center", va="center", fontsize=fs, color=TEXT, weight="bold" if bold else "normal")


def _arrow(ax, x0, y0, x1, y1, color=MUTED, lw=1.0):
    ax.add_patch(FancyArrowPatch((x0, y0), (x1, y1), arrowstyle="-|>", mutation_scale=9, color=color, lw=lw,
                                 shrinkA=0, shrinkB=0))


def fig_round():
    """Dipper round function with the fault point (diagram, no data)."""
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    ax.set_xlim(0, 10); ax.set_ylim(0, 10); ax.axis("off")
    ax.grid(False)
    _box(ax, 5, 9.4, 4.2, 0.6, r"$x_i$ (64 bits)")
    _arrow(ax, 5, 9.1, 5, 8.55)
    ax.text(5.15, 8.85, r"$\oplus\ rk_i$", fontsize=8, color=TEXT, va="center")
    _box(ax, 5, 8.25, 4.2, 0.55, r"$y_i = x_i \oplus rk_i$")
    ax.annotate("fault injected here\n(M1 nibble / M2 bit / M3 byte)", xy=(7.15, 8.25), xytext=(7.6, 8.9),
                fontsize=7, color=COL["xor"], arrowprops=dict(arrowstyle="-|>", color=COL["xor"], lw=1))
    _arrow(ax, 5, 7.97, 5, 7.45)
    _box(ax, 5, 7.15, 8.6, 0.55, "S-layer: GIFT S-box on all 16 nibbles", fc="#eef4fc")
    xs = [1.6, 3.85, 6.15, 8.4]
    names = ["A (63..48)", "B (47..32)", "C (31..16)", "D (15..0)"]
    rots = [1, 4, 7, 11]
    for x, nm, r in zip(xs, names, rots):
        _arrow(ax, x, 6.87, x, 6.35)
        _box(ax, x, 6.05, 1.9, 0.55, nm, fs=7)
        _arrow(ax, x, 5.77, x, 5.25)
        _box(ax, x, 4.95, 1.4, 0.55, rf"$\lll {r}$", fs=8)
    # modular additions
    for xa, xb, lab in [(xs[0], xs[1], r"$A_2=A_1\boxplus B_1$"), (xs[2], xs[3], r"$C_2=C_1\boxplus D_1$")]:
        _arrow(ax, xa, 4.67, xa, 3.9)                                   # A1 / C1 into the adder
        _arrow(ax, xb, 4.67, xb, 2.35)                                  # B1 / D1 straight to P
        _arrow(ax, xb, 4.2, xa + 0.32, 3.68, color=COL["dipper"])      # B1 / D1 branch into the adder
        ax.add_patch(plt.Circle((xa, 3.6), 0.3, fc="#ffffff", ec=COL["dipper"], lw=1.4))
        ax.text(xa, 3.6, r"$\boxplus$", ha="center", va="center", fontsize=10, color=COL["dipper"])
        ax.text(xa - 0.4, 2.95, lab, ha="right", fontsize=7, color=TEXT)
        _arrow(ax, xa, 3.3, xa, 2.35)
    _box(ax, 5, 2.05, 8.6, 0.55, "P: GIFT-64 bit permutation", fc="#eef4fc")
    _arrow(ax, 5, 1.77, 5, 1.2)
    _box(ax, 5, 0.9, 4.2, 0.55, r"$x_{i+1} = F(y_i)$,  $F = P\circ\mathrm{ARX}\circ S$")
    ax.text(0.05, 0.1, "xor variant: replace each addition by XOR;  none variant: drop the addition (analysis only)",
            fontsize=6.5, color=MUTED)
    fig.tight_layout()
    fig.savefig(f"{OUT}/fig3_round.png")
    plt.close(fig)


def _q(xs, p):
    xs = sorted(xs); k = (len(xs) - 1) * p; lo = int(k); hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def fig_tradeoff():
    """Median total faults (p10-p90 bars) vs log2 of the candidate tuples allowed per stage."""
    fig, ax = plt.subplots(figsize=(4.8, 3.1))
    series = [("dipper", "-", "o", "Dipper 64/96 (fault at T-1)", ["d96_M1_strict", "d96_M1_th8", "d96_M1_th12"]),
              ("dipper", "--", "s", "Dipper 64/128 A (fault at T-1)", ["d128A_M1_strict", "d128A_M1_th8", "d128A_M1_th12"]),
              ("xor", ":", "^", "xor 64/96 (fault at T-2)", ["xor96_M1_deep_strict", "xor96_M1_deep_th8", "xor96_M1_deep_th12"]),
              ("none", "-.", "D", "none 64/96 (fault at T-2)", ["none96_M1_deep_strict", "none96_M1_deep_th8", "none96_M1_deep_th12"])]
    for v, ls, mk, label, names in series:
        xs, med, lo, hi = [], [], [], []
        for n in names:
            r = load(n)
            f = [x["total_faults"] for x in r]
            th = r[0]["theta"]
            xs.append(th if th >= 0 else (4 if r[0]["variant"] == "dipper" else 0))
            med.append(np.median(f)); lo.append(_q(f, 0.1)); hi.append(_q(f, 0.9))
        med, lo, hi = np.array(med), np.array(lo), np.array(hi)
        ax.errorbar(xs, med, yerr=[med - lo, hi - med], color=COL[v], ls=ls, marker=mk, ms=5, lw=1.6, capsize=3,
                    label=label)
    ax.set_xlabel("log2 of candidates allowed per stage")
    fig.text(0.01, 0.005, "Floor rule plotted at 4 for Dipper (16 tuples) and 0 for the variants (1 tuple).",
             color=MUTED, fontsize=6.5)
    ax.set_ylabel("total faults (median, p10-p90)")
    ax.set_xticks([0, 4, 8, 12])
    ax.legend(fontsize=6.5, frameon=False, labelcolor=TEXT)
    ax.set_title("Faults vs. size of the final search, M1", color=TEXT, fontsize=9, loc="left")
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(f"{OUT}/fig4_tradeoff.png")
    plt.close(fig)


def fig_stage_hist():
    """Distribution of faults per stage, Dipper 64/96, M1, floor rule."""
    r = load("d96_M1_strict")
    fig, ax = plt.subplots(figsize=(4.8, 2.8))
    bins = np.arange(0, 480, 10)
    for i, (lab, ls, c) in enumerate([("stage 1: rk27 (faults in round 26)", "-", COL["dipper"]),
                                      ("stage 2: rk26 (faults in round 25)", "--", COL["xor"])]):
        f = [x["stages"][i]["faults"] for x in r]
        ax.hist(f, bins=bins, histtype="step", lw=1.8, ls=ls, color=c,
                label=f"{lab}: median {np.median(f):.0f}, max {max(f)}")
    ax.set_xlabel("faults used in the stage")
    ax.set_ylabel("keys (of 1000)")
    ax.legend(fontsize=6.5, frameon=False, labelcolor=TEXT)
    ax.set_title("Faults per stage, Dipper 64/96, M1, floor rule", color=TEXT, fontsize=9, loc="left")
    fig.tight_layout()
    fig.savefig(f"{OUT}/fig5_stage_hist.png")
    plt.close(fig)


if __name__ == "__main__":
    fig_round()
    fig_tradeoff()
    fig_stage_hist()
    print("wrote", sorted(os.listdir(OUT)))
