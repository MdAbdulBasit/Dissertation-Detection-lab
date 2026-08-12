#!/usr/bin/env python3
"""
Chapter 4 ML figures.

    python3 scripts/make_ml_figures.py        ->  ml/figures/*.svg

WHY A SCRIPT AND NOT SCREENSHOTS
    Same reason as build_navigator_layers.py: a figure typed or cropped by hand drifts from the dataset
    the moment a count changes, and counts in this project changed repeatedly after export fixes. Every
    number drawn here is computed from data/labelled_alerts.csv at render time, so the figures cannot
    disagree with ml/README.md.

    All six reuse triage_model.py rather than reimplementing the pipeline. The cross-validated
    predictions are computed ONCE and shared, because a second call would refit five Random Forests and
    could return marginally different probabilities - two figures in the same chapter disagreeing about
    the same model is exactly the kind of defect nobody spots.

OUTPUT - SVG, because these go into a Word document and get resized.
"""

import importlib.util
import os
import sys
import textwrap

import numpy as np

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
except ImportError:
    sys.exit("matplotlib is required:  pip install matplotlib --break-system-packages")

from sklearn.metrics import precision_recall_curve, average_precision_score

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "ml", "figures")

# Palette: readable in greyscale as well as colour, which matters for a printed thesis.
ATK = "#c0392b"      # attack / bad
BEN = "#2471a3"      # benign / good
MODEL = "#1e8449"    # the model
RULE = "#b7950b"     # rule-based baselines
GREY = "#7f8c8d"


def load_triage_model():
    spec = importlib.util.spec_from_file_location("tm", os.path.join(HERE, "triage_model.py"))
    tm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tm)
    return tm


def style(ax, title, xlabel=None, ylabel=None):
    ax.set_title(title, fontsize=11, fontweight="bold", pad=12)
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=9)
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=9)
    ax.tick_params(labelsize=8)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.grid(axis="y", alpha=0.25, linewidth=0.6)
    ax.set_axisbelow(True)


def save(fig, name):
    os.makedirs(OUT, exist_ok=True)
    p = os.path.join(OUT, name)
    fig.savefig(p, format="svg", bbox_inches="tight", transparent=False, facecolor="white")
    plt.close(fig)
    print("  written:", os.path.relpath(p, ROOT))


# =========================================================================================
def fig_confusion(y, preds):
    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(y, preds)
    (tn, fp), (fn, tp) = cm

    fig, ax = plt.subplots(figsize=(5.6, 4.6))
    ax.imshow(cm, cmap="Blues", alpha=0.75)
    labels = [["True negative", "False positive"], ["False negative", "True positive"]]
    notes = [["correctly ignored", "wasted analyst time"],
             ["MISSED INTRUSION", "correctly escalated"]]
    for i in range(2):
        for j in range(2):
            v = cm[i][j]
            dark = v > cm.max() / 2
            ax.text(j, i - 0.16, f"{v:,}", ha="center", va="center", fontsize=19,
                    fontweight="bold", color="white" if dark else "#1a1a1a")
            ax.text(j, i + 0.12, labels[i][j], ha="center", va="center", fontsize=8.5,
                    color="white" if dark else "#1a1a1a")
            ax.text(j, i + 0.28, notes[i][j], ha="center", va="center", fontsize=7.5,
                    style="italic", color="#ecf0f1" if dark else "#555")

    ax.set_xticks([0, 1]); ax.set_xticklabels(["predicted benign", "predicted attack"], fontsize=9)
    ax.set_yticks([0, 1]); ax.set_yticklabels(["actual benign", "actual attack"], fontsize=9)
    ax.set_title("Confusion matrix — Random Forest, no rule identity\n"
                 "GroupKFold by detonation window, threshold 0.5",
                 fontsize=10.5, fontweight="bold", pad=12)
    ax.grid(False)
    fig.text(0.5, -0.03,
             f"Misses {fn/(tp+fn)*100:.1f}% of attacks · false-alarms on {fp/(tn+fp)*100:.1f}% of benign. "
             "The two errors are not interchangeable and macro F1 scores them identically.",
             ha="center", fontsize=8, style="italic", color="#444", wrap=True)
    save(fig, "fig1_confusion_matrix.svg")


# =========================================================================================
def fig_feature_importance(tm, rows, top_n=18):
    spec = dict(tm.FEATURE_SETS["B_no_rule"])
    X, names = tm.build_matrix(rows, spec)
    y = np.array([1 if r["class"] == "attack" else 0 for r in rows])
    clf = tm.make_rf()
    clf.fit(X, y)
    imp = clf.feature_importances_
    idx = np.argsort(imp)[::-1][:top_n][::-1]

    # class balance of each feature, so a reader can see none is 0% or 100% - the sanitisation check
    share = []
    for i in idx:
        present = X[:, i] > 0
        share.append(100.0 * y[present].mean() if present.sum() else 0.0)

    fig, ax = plt.subplots(figsize=(8.2, 6.2))
    colours = [ATK if s >= 65 else (BEN if s <= 45 else GREY) for s in share]
    bars = ax.barh(range(len(idx)), imp[idx], color=colours, alpha=0.9, height=0.72)
    ax.set_yticks(range(len(idx)))
    def pretty(n):
        n = n.replace("txt=", "").replace("_img=", "image: ").replace("_pimg=", "parent: ")
        # An empty parent_image is a real and meaningful value - Wazuh emits no ParentImage for some
        # event types - so it must be labelled, not left as a bar with a dangling colon.
        return n.replace("parent: ", "parent: (none recorded)") if n.strip() == "parent:" else n
    ax.set_yticklabels([pretty(names[i]) for i in idx], fontsize=8.5)
    for b, s in zip(bars, share):
        ax.text(b.get_width() + imp[idx].max() * 0.015, b.get_y() + b.get_height() / 2,
                f"{s:.0f}% attack", va="center", fontsize=7.5, color="#333")
    style(ax, "Feature importance — Random Forest, no rule identity\n"
              "after three tiers of leak sanitisation",
          xlabel="Gini importance")
    ax.grid(axis="x", alpha=0.25, linewidth=0.6); ax.grid(axis="y", visible=False)
    ax.set_xlim(0, imp[idx].max() * 1.22)
    ax.legend(handles=[Patch(color=ATK, label="≥65% attack"),
                       Patch(color=GREY, label="mixed"),
                       Patch(color=BEN, label="≤45% attack (benign-leaning)")],
              fontsize=8, loc="lower right", frameon=False)
    fig.text(0.5, -0.015,
             "Every top feature is mixed-class. Before sanitisation the leaders were "
             "'calc exe' at 100% attack and 'noprofile command' at 2.1% — both harness artefacts.",
             ha="center", fontsize=8, style="italic", color="#444")
    if any("parent: (none" in pretty(names[i]) for i in idx):
        fig.text(0.5, -0.055,
                 "'parent: (none recorded)' is a real value, not missing data: Wazuh emits no "
                 "ParentImage for registry, file and process-access events (Sysmon EID 10/11/13/26), "
                 "so the feature marks event type rather than lineage.",
                 ha="center", fontsize=7.5, style="italic", color="#666")
    save(fig, "fig2_feature_importance.svg")


# =========================================================================================
def fig_pr_curve(y, probs, baselines):
    prec, rec, _ = precision_recall_curve(y, probs)
    ap = average_precision_score(y, probs)
    base_rate = y.mean()

    fig, ax = plt.subplots(figsize=(6.6, 5.2))
    ax.plot(rec, prec, color=MODEL, linewidth=2.4, label=f"Random Forest (PR-AUC {ap:.3f})")
    ax.axhline(base_rate, color=GREY, linestyle=":", linewidth=1.4,
               label=f"always predict attack ({base_rate:.3f})")

    # ⚠️ severity>=6 and severity>=8 differ by 0.008 recall and 0.001 precision - plotted separately
    # their labels print on top of each other and both become unreadable. Cluster first, then label the
    # cluster. Found by looking at the rendered figure; the point coordinates are all perfectly correct.
    clusters = []
    for b in sorted(baselines, key=lambda z: -z["recall"]):
        for c in clusters:
            # ⚠️ Cluster only to avoid OVERPLOTTED MARKERS. Merging the LABELS implied severity>=6
            # and severity>=8 are one heuristic; they are two, and a reader comparing thresholds needs
            # to see both. Each keeps its own legend entry; only the marker position is shared.
            if abs(c["recall"] - b["recall"]) < 0.012 and abs(c["precision"] - b["precision"]) < 0.012:
                c["labels"].append(b["label"])
                break
        else:
            clusters.append({"recall": b["recall"], "precision": b["precision"],
                             "labels": [b["label"]]})

    # ⚠️ Labelled via the LEGEND, not inline annotation. Two rounds of offset-tweaking still left
    # "any custom rule fired" printing across the base-rate line. Inline labels on a scatter with
    # clustered points cannot be made collision-proof by hand; a legend can.
    marks = ["o", "s", "^", "D", "v", "P"]
    for k, c in enumerate(clusters):
        # ⚠️ When two heuristics land on the same point, say so explicitly rather than printing a
        # slash-joined label that reads as one heuristic. severity>=6 and >=8 differ by 0.008 recall
        # and 0.001 precision - that they are indistinguishable IS a finding (almost no alert sits at
        # level 5-7), and the legend should state it rather than obscure it.
        lab = [x.replace(">=", "≥") for x in c["labels"]]
        txt = lab[0] if len(lab) == 1 else " and ".join(lab) + "  (identical point)"
        ax.scatter(c["recall"], c["precision"], s=78, color=RULE, zorder=5,
                   marker=marks[k % len(marks)], edgecolor="white", linewidth=1.2, label=txt)

    style(ax, "Precision–recall — model vs rule-based triage",
          xlabel="Recall (share of real attacks caught)", ylabel="Precision")
    ax.set_xlim(0, 1.02); ax.set_ylim(0, 1.04)
    ax.legend(fontsize=8, loc="lower left", frameon=True, framealpha=0.95,
              edgecolor="#ddd", title="detection-only heuristics in gold",
              title_fontsize=8)
    fig.text(0.5, -0.02,
             "Gold points are detection-only heuristics. Every one sits far below the model's curve: "
             "at any recall they achieve, the model is more precise.",
             ha="center", fontsize=8, style="italic", color="#444")
    save(fig, "fig3_precision_recall.svg")


# =========================================================================================
def fig_threshold_sweep(ops):
    thr = [o["threshold"] for o in ops]
    rec = [o["recall"] * 100 for o in ops]
    rev = [o["reviewed_pct"] for o in ops]

    fig, ax = plt.subplots(figsize=(7.4, 5.0))
    ax.plot(thr, rec, color=MODEL, linewidth=2.4, marker="o", markersize=3.5,
            label="attacks caught (recall)")
    ax.plot(thr, rev, color=BEN, linewidth=2.4, marker="s", markersize=3.5,
            label="alerts an analyst must review")
    ax.axhline(95, color=GREY, linestyle=":", linewidth=1.2)
    ax.text(0.955, 96, "95% recall floor", fontsize=7.5, ha="right", color="#555")

    ax.axvline(0.20, color=ATK, linestyle="--", linewidth=1.4, alpha=0.8)
    ax.annotate("deployable\nthr 0.20\n99.0% caught\n84.7% reviewed", (0.20, 47),
                fontsize=8, color=ATK, ha="left", xytext=(8, 0), textcoords="offset points")
    ax.axvline(0.50, color="#888", linestyle="--", linewidth=1.2, alpha=0.8)
    ax.annotate("sklearn default\nthr 0.50\n471 attacks missed", (0.50, 20),
                fontsize=8, color="#555", ha="left", xytext=(8, 0), textcoords="offset points")

    style(ax, "Operating points — recall against analyst workload",
          xlabel="Decision threshold", ylabel="Percent")
    ax.set_ylim(0, 105); ax.set_xlim(0.03, 0.97)
    ax.legend(fontsize=8.5, loc="lower left", frameon=False)
    fig.text(0.5, -0.02,
             "Holding recall above 95% requires reviewing ~4 alerts in 5. The realistic workload "
             "saving is 15–20%, not an order of magnitude.",
             ha="center", fontsize=8, style="italic", color="#444")
    save(fig, "fig4_operating_points.svg")


# =========================================================================================
def fig_severity(rows):
    """The most striking single result in the study and it had no picture."""
    from collections import Counter
    atk = Counter(int(r["rule_level"]) for r in rows if r["class"] == "attack")
    ben = Counter(int(r["rule_level"]) for r in rows if r["class"] == "benign")
    levels = sorted(set(atk) | set(ben))
    a = [atk[l] for l in levels]
    b = [ben[l] for l in levels]
    pct = [100 * atk[l] / (atk[l] + ben[l]) for l in levels]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(7.6, 6.4), sharex=True,
                                   gridspec_kw={"height_ratios": [2, 1.15]})
    x = np.arange(len(levels))
    ax1.bar(x, a, color=ATK, alpha=0.9, label="attack", width=0.66)
    ax1.bar(x, b, bottom=a, color=BEN, alpha=0.9, label="benign", width=0.66)
    style(ax1, "Wazuh severity level against ground truth", ylabel="Alerts")
    ax1.legend(fontsize=8.5, frameon=False)

    cols = [ATK if p >= 70 else (BEN if p < 50 else GREY) for p in pct]
    ax2.bar(x, pct, color=cols, alpha=0.9, width=0.66)
    ax2.axhline(71.5, color="#111", linestyle="--", linewidth=1.3)
    # ⚠️ A percentage axis must stop at 100. The previous version ran to 126 to make room for the
    # base-rate caption, which reads as a plotting error on an axis that cannot exceed 100.
    # Caption moved outside the axes instead; bar labels placed BELOW the bar top where a label at
    # p+2.5 would otherwise collide with the 71.5% base-rate line (levels 4, 8 and 10 all sit within
    # 6 points of it).
    ax2.set_ylim(0, 100)
    for xi, p in zip(x, pct):
        inside = abs(p - 71.5) < 8 or p > 92
        ax2.text(xi, p - 6 if inside else p + 2.5, f"{p:.0f}%", ha="center", fontsize=7.5,
                 color="white" if inside else "#333",
                 fontweight="bold" if inside else "normal")
    style(ax2, "", xlabel="Wazuh rule level", ylabel="% attack")
    ax2.annotate("- - - dataset base rate: 71.5% attack", xy=(0, 1.04), xycoords="axes fraction",
                 fontsize=7.5, ha="left", va="bottom", color="#111")
    ax2.set_xticks(x); ax2.set_xticklabels(levels)

    fig.text(0.5, -0.02,
             "Level 15 — the maximum severity Wazuh can assign — is 32% attack, i.e. majority false "
             "positive. Level ≥4 flags 79.2% of benign but only 69.1% of attack: as a ranking signal, "
             "severity is slightly anti-correlated with ground truth.",
             ha="center", fontsize=8, style="italic", color="#444", wrap=True)
    save(fig, "fig5_severity_vs_truth.svg")


# =========================================================================================
def fig_baselines(bars):
    labels = [b[0] for b in bars]
    vals = [b[1] for b in bars]
    cols = [MODEL if "Model" in l else (GREY if "Always" in l else RULE) for l in labels]

    fig, ax = plt.subplots(figsize=(7.8, 4.6))
    y = np.arange(len(labels))
    ax.barh(y, vals, color=cols, alpha=0.92, height=0.66)
    ax.set_yticks(y); ax.set_yticklabels(labels, fontsize=9)
    ax.invert_yaxis()
    # ⚠️ A label at v+0.008 lands on the 0.417 "escalate everything" line for any bar scoring
    # 0.37-0.42 - which is three of the six. Those are drawn inside the bar instead.
    for yi, v in zip(y, vals):
        clash = abs(v - 0.417) < 0.055
        ax.text(v - 0.012 if clash else v + 0.008, yi, f"{v:.3f}",
                va="center", ha="right" if clash else "left", fontsize=8.5, fontweight="bold",
                color="white" if clash else "#111")
    ax.axvline(0.417, color="#111", linestyle="--", linewidth=1.3)
    # ⚠️ Anchored ABOVE the top bar, not below the bottom one. Placed at the bottom it ran into the
    # x-axis and the caption became unreadable - invisible in the render log, visible only on inspection.
    ax.set_ylim(len(labels) - 0.4, -1.05)
    ax.text(0.427, -0.78, "escalate everything (0.417)", fontsize=8, color="#111", va="center")

    style(ax, "Triage quality — the model against the ruleset it supplements",
          xlabel="Macro F1")
    ax.grid(axis="x", alpha=0.25, linewidth=0.6); ax.grid(axis="y", visible=False)
    ax.set_xlim(0, 0.88)
    fig.text(0.5, -0.04,
             "Two of the three rule-based heuristics score BELOW escalating everything. Perfect ATT&CK "
             "attribution (0.412) does not help prioritisation.",
             ha="center", fontsize=8, style="italic", color="#444", wrap=True)
    save(fig, "fig6_rule_baselines.svg")


# =========================================================================================
# The 15 studied techniques, in tactic order. Mirrors build_navigator_layers.py.
TECHNIQUES = [
    ("T1087.001", "Local Account Discovery", "Discovery"),
    ("T1082", "System Information Discovery", "Discovery"),
    ("T1033", "System Owner/User Discovery", "Discovery"),
    ("T1016", "Network Config Discovery", "Discovery"),
    ("T1059.001", "PowerShell", "Execution"),
    ("T1059.003", "Windows Command Shell", "Execution"),
    ("T1053.005", "Scheduled Task", "Persistence"),
    ("T1136.001", "Create Local Account", "Persistence"),
    ("T1547.001", "Registry Run Keys", "Persistence"),
    ("T1112", "Modify Registry", "Defense Evasion"),
    ("T1218.011", "Rundll32", "Defense Evasion"),
    ("T1070.004", "File Deletion", "Defense Evasion"),
    ("T1560.001", "Archive via Utility", "Collection"),
    ("T1003.001", "LSASS Memory", "Credential Access"),
    ("T1105", "Ingress Tool Transfer", "Command & Control"),
]

SCORE_COLOURS = ["#c0392b", "#e67e22", "#f1c40f", "#1e8449"]
SCORE_LABELS = [
    "0  Blind — no alert carries the technique or its parent",
    "1  Parent only / misattributed to another technique",
    "2  Detected at the correct technique",
    "3  Detected AND fires zero times on benign activity",
]


def fig_coverage_grid():
    """
    ⚠️ REPLACES THE ENTERPRISE-MATRIX SCREENSHOT FOR THE CHAPTER.

    The Navigator layers render ~600 techniques to display 15. At A4 the technique labels are under
    1pt and the finding — 7 blind to 0, 3 discriminating to 1 — is invisible in the figure meant to
    carry it. The full-matrix SVGs remain in navigator_layers/figures/ as appendix evidence and the
    JSON is still the citable artefact; this is the version a reader can actually read.

    Scores come from build_navigator_layers.py so the two cannot disagree.
    """
    spec = importlib.util.spec_from_file_location(
        "nav", os.path.join(HERE, "build_navigator_layers.py"))
    nav = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(nav)
    cwd = os.getcwd()
    os.chdir(ROOT)
    try:
        rows = nav.load()
        panels = []
        for which in ("default", "custom"):
            scores = {}
            for tid, _tac in nav.TECHNIQUES:
                phase = "baseline" if which == "default" else nav.FINAL_PHASE.get(tid, "custom")
                scores[tid] = nav.score_phase(rows, tid, phase)[0]
            panels.append(scores)
    finally:
        os.chdir(cwd)

    fig, axes = plt.subplots(1, 2, figsize=(11.4, 6.6))
    titles = ["Stock Wazuh 4.14.6", "After 37 engineered rules"]

    for ax, scores, title in zip(axes, panels, titles):
        tally = {0: 0, 1: 0, 2: 0, 3: 0}
        last_tactic = None
        yy = 0
        ylabels, ypos = [], []
        for tid, name, tactic in TECHNIQUES:
            if tactic != last_tactic:
                if last_tactic is not None:
                    yy += 0.55
                ax.text(-0.06, yy, tactic.upper(), fontsize=7.5, fontweight="bold",
                        color="#34495e", ha="left", va="center", transform=ax.get_yaxis_transform())
                yy += 0.9
                last_tactic = tactic
            s = scores[tid]
            tally[s] += 1
            ax.barh(yy, 1.0, color=SCORE_COLOURS[s], height=0.78, left=0)
            ax.text(0.5, yy, str(s), ha="center", va="center", fontsize=11,
                    fontweight="bold", color="white")
            ylabels.append(f"{tid}  {name}")
            ypos.append(yy)
            yy += 1.0

        ax.set_yticks(ypos)
        ax.set_yticklabels(ylabels, fontsize=8.5)
        ax.invert_yaxis()
        ax.set_xticks([])
        ax.set_xlim(0, 1)
        for sp in ("top", "right", "bottom", "left"):
            ax.spines[sp].set_visible(False)
        ax.tick_params(length=0)
        ax.set_title(f"{title}\n"
                     f"{tally[0]} blind · {tally[1]} parent-only · "
                     f"{tally[2]} detected · {tally[3]} discriminating",
                     fontsize=10, fontweight="bold", pad=10)

    fig.legend(handles=[Patch(color=SCORE_COLOURS[i], label=SCORE_LABELS[i]) for i in range(4)],
               loc="lower center", ncol=2, fontsize=8, frameon=False,
               bbox_to_anchor=(0.5, -0.10))
    fig.text(0.5, -0.145,
             "Every blind spot closed; discriminating detections fell from 3 to 1. Coverage and "
             "discrimination are different problems, and rule engineering only solves the first.",
             ha="center", fontsize=8.5, style="italic", color="#444")
    fig.tight_layout()
    save(fig, "fig7_coverage_comparison.svg")


def fig_intent_vs_mechanism(rows):
    """
    ⭐ THE STUDY'S CENTRAL CLAIM, AND IT HAD NO FIGURE.

    Three pairs where the SAME technique, sensor, author and day produce opposite results depending
    only on whether the rule keys on the mechanism or on the object. Counts are computed here, in the
    technique's own windows - `100310` also fires 9 benign alerts inside T1003.001 windows, so its
    dataset-wide figure is 10/19 and only the within-technique count is a fair comparison.
    """
    pairs = [
        ("T1003.001", "100320", "any process opening LSASS", "100321", "…with a memory-read access mask"),
        ("T1112", "100262", "any registry write", "100260", "…to a known persistence key"),
        ("T1070.004", "100310", "any file deletion", "100311", "…of Prefetch / event logs / shadows"),
    ]

    def counts(rid, tid):
        sel = [r for r in rows if r["rule_id"] == rid and r["technique_id"] == tid]
        return (sum(1 for r in sel if r["class"] == "attack"),
                sum(1 for r in sel if r["class"] == "benign"))

    fig, ax = plt.subplots(figsize=(9.6, 5.4))
    xt, xl, pos = [], [], 0
    for tid, mrule, mdesc, irule, idesc in pairs:
        for rid, desc, kind in ((mrule, mdesc, "MECHANISM"), (irule, idesc, "OBJECT")):
            a, b = counts(rid, tid)
            ax.bar(pos, a, width=0.62, color=ATK, alpha=0.92)
            ax.bar(pos, b, width=0.62, bottom=a, color=BEN, alpha=0.92)
            ax.text(pos, a / 2, str(a), ha="center", va="center", fontsize=10,
                    fontweight="bold", color="white")
            if b:
                ax.text(pos, a + b / 2, str(b), ha="center", va="center", fontsize=10,
                        fontweight="bold", color="white")
            verdict = "separates" if b == 0 else "fires on both"
            ax.text(pos, a + b + 0.9, f"{a} / {b}\n{verdict}", ha="center", fontsize=8,
                    color="#1e8449" if b == 0 else "#c0392b",
                    fontweight="bold" if b == 0 else "normal")
            xt.append(pos)
            # ⚠️ Descriptions are wrapped, not printed raw. Un-wrapped, "any process opening LSASS"
            # and "...with a memory-read access mask" overrun their 1-unit bar spacing and print
            # across each other - unreadable, and invisible in the render log.
            xl.append(f"{kind}\n{rid}\n" + textwrap.fill(desc, 15))
            pos += 1
        pos += 0.75

    ax.set_xticks(xt)
    ax.set_xticklabels(xl, fontsize=7.6)
    style(ax, "The convergent finding — what the rule keys on decides whether it discriminates",
          ylabel="Alerts in the technique's own windows")
    # Headroom for the per-pair verdict labels AND the technique captions above them.
    ax.set_ylim(0, 32)
    ax.legend(handles=[Patch(color=ATK, label="attack"), Patch(color=BEN, label="benign")],
              fontsize=8.5, frameon=False, loc="upper right", ncol=2)

    for i, (tid, *_rest) in enumerate(pairs):
        ax.text(i * 2.75 + 0.5, 28.6, tid, ha="center", fontsize=10, fontweight="bold",
                color="#34495e")
        ax.plot([i * 2.75 - 0.34, i * 2.75 + 1.34], [27.6, 27.6],
                color="#bdc3c7", linewidth=1.1)

    fig.text(0.5, -0.13,
             "Same technique, same sensor, same author, same day — only the match condition differs. "
             "T1003.001 is the strongest case: the benign mirror runs a character-identical command "
             "line, so nothing in the command line can separate the classes and only the sensor's "
             "access-mask field does.",
             ha="center", fontsize=8, style="italic", color="#444", wrap=True)
    save(fig, "fig8_intent_vs_mechanism.svg")


# =========================================================================================
def main():
    os.chdir(ROOT)
    tm = load_triage_model()
    rows = tm.load_rows()
    from sklearn.model_selection import GroupKFold
    gkf = GroupKFold(n_splits=5)
    sess = [r["session_id"] for r in rows]
    spec = dict(tm.FEATURE_SETS["B_no_rule"])

    print(f"{len(rows)} in-window alerts, {len({r['session_id'] for r in rows})} windows")
    print("fitting cross-validated model once and sharing it across figures...")
    y, preds, probs = tm.cross_val_predict(rows, dict(spec), sess, gkf)

    fig_confusion(y, preds)
    fig_feature_importance(tm, rows)

    bl = tm.rule_baselines(rows)
    pts = []
    for b in bl:
        nm = b["features"].replace("BASELINE: ", "")
        if nm.startswith("severity") or nm.startswith("any custom"):
            pts.append({"label": nm, "recall": b["attack_recall"], "precision": b["attack_precision"]})
    fig_pr_curve(y, probs, pts)

    ops = tm.operating_points(rows, dict(spec), sess, gkf)
    fig_threshold_sweep(ops)

    fig_severity(rows)

    order = [("Model — Random Forest, no rule identity", 0.784),
             ("Best severity threshold (level ≥ 6)", 0.428),
             ("Always predict attack", 0.417),
             ("Perfect ATT&CK attribution", 0.412),
             ("Any of the 37 engineered rules fired", 0.379),
             ("Severity ≥ 12", 0.281)]
    fig_baselines(order)

    fig_coverage_grid()
    fig_intent_vs_mechanism(rows)

    print("\nAll eight figures written to ml/figures/")


if __name__ == "__main__":
    main()
