#!/usr/bin/env python3
"""
Alert-triage model: can a classifier separate attack from benign alerts when RULE LOGIC CANNOT?

WHY THIS EXISTS
    The Navigator result (scripts/build_navigator_layers.py) measured that 37 engineered rules closed
    every coverage gap and produced NO additional discriminating power: one genuinely discriminating
    detection before, one after. Rule engineering solves coverage; it does not solve discrimination.
    This script asks whether a model can, from the same telemetry.

    The interesting outcome is NOT a high score. A high score here is the FAILURE case, because the
    easiest way to get one is to learn the lab's own naming conventions.

------------------------------------------------------------------------------------------------------
THE LEAK PROBLEM - read this before trusting any number below
------------------------------------------------------------------------------------------------------
    Measured on the raw dataset, 18% of in-window alerts carry a token that gives the class away:

        "atomic"    127 attack /   0 benign        "lab..."      0 attack / 203 benign
        "deleteme"   64 attack /   0 benign        "benign"      0 attack / 138 benign
        "T1xxx"     231 attack /   5 benign

    The word "benign" is literally present in the benign class's command lines, because the mirror
    names its artefacts LabBenignSvc, labfetch, labstale.bat and so on. Those names exist to make the
    lab reproducible and auditable; they also make the classification task trivial and meaningless.
    A model trained on the raw text scores ~95% and has learned nothing about behaviour.

    SANITISE() below replaces every such token before any feature is built. This is the single most
    important function in the file. If it is weakened, every result becomes worthless in a way that
    LOOKS like success - which is the most dangerous kind of error in this whole project.

------------------------------------------------------------------------------------------------------
SPLITTING - grouped, never random
------------------------------------------------------------------------------------------------------
    2,683 in-window alerts come from only 259 detonation windows: median 8 alerts per window, max 58,
    and alerts within one window share command lines almost exactly. A random alert-level split puts
    near-duplicates on both sides and reports a fantasy score.

    Two splits are run:
      GroupKFold on session_id   - no window spans train and test. The realistic evaluation.
      LeaveOneGroupOut on technique_id - train on 14 techniques, test on the 15th. Much harder, and
                                  the honest test of whether anything generalises beyond memorising
                                  the specific commands each atomic runs.

USAGE
    pip install scikit-learn --break-system-packages
    python3 scripts/triage_model.py
"""

import csv
import os
import re
import sys
from collections import Counter, defaultdict

import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics import average_precision_score, classification_report, confusion_matrix
    from sklearn.model_selection import GroupKFold, LeaveOneGroupOut
    from sklearn.pipeline import FeatureUnion, Pipeline
    from sklearn.preprocessing import OneHotEncoder
    from sklearn.compose import ColumnTransformer
except ImportError:
    sys.exit("scikit-learn is required:  pip install scikit-learn --break-system-packages")

try:
    from xgboost import XGBClassifier
    HAVE_XGB = True
except ImportError:
    HAVE_XGB = False

DATA = os.path.join("data", "labelled_alerts.csv")


def make_rf(pos_weight=None):
    return RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                  min_samples_leaf=2, random_state=42, n_jobs=-1)


def make_xgb(pos_weight=None):
    # scale_pos_weight is XGBoost's equivalent of class_weight="balanced". Passed explicitly from the
    # TRAINING fold only - computing it on the full dataset would leak the test fold's class balance.
    return XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1,
                         subsample=0.9, colsample_bytree=0.9,
                         scale_pos_weight=(pos_weight or 1.0),
                         eval_metric="logloss", random_state=42, n_jobs=-1,
                         tree_method="hist")


CLASSIFIERS = {"RandomForest": make_rf}
if HAVE_XGB:
    CLASSIFIERS["XGBoost"] = make_xgb

# =====================================================================================================
# LEAK SANITISATION
# Order matters: technique IDs are stripped before the generic word patterns, because names like
# deleteme_T1551.004 contain both.
# =====================================================================================================
_SANITISERS = [
    (re.compile(r"T1\d{3}(?:\.\d{3})?", re.I), " "),   # T1136.001, T1551.004
    (re.compile(r"atomic\w*", re.I),           " "),   # AtomicRedTeam, atomictest
    (re.compile(r"\blab\w*", re.I),            " "),   # LabBenignSvc, labfetch, labarchive
    (re.compile(r"benign\w*", re.I),           " "),   # the class name, in the data
    (re.compile(r"deleteme\w*", re.I),         " "),
    (re.compile(r"smoke\w*", re.I),            " "),
    (re.compile(r"\bBasit\b", re.I),           " USERNAME "),      # the lab operator's account
    (re.compile(r"\b[0-9a-f]{8,}\b", re.I),    " HEX "),           # GUIDs, prefetch hashes
    (re.compile(r"\b\d{3,}\b"),                " NUM "),           # PIDs, sizes
    # -------------------------------------------------------------------------------------------
    # TIER 2, added after inspecting feature importances. The first sanitisation pass removed lab
    # NAMES and the model then keyed on lab HABITS instead. Measured top features before this tier:
    #
    #   "noprofile command"   n=94    2.1% attack   <- Invoke-ViaPowerShell passes -NoProfile -Command.
    #   "exe noprofile"       n=119  18.5% attack      ONLY the benign mirror does this. ART's executor
    #   "noprofile"           n=129  24.8% attack      does not.
    #   "command"             n=104  11.5% attack
    #   "calc exe"            n=111 100.0% attack   <- atomics launch calc.exe as their demo payload;
    #   "notepad"             n=93   33.3% attack      the mirror launches notepad.exe.
    #
    # None of that is a property of an attacker versus an administrator. It is my harness's invocation
    # style and Atomic Red Team's choice of harmless payload. Left in, the model scores well by
    # recognising who wrote the command rather than what it does - the same failure as the name leak,
    # one level further down, and far harder to spot because the tokens look like real telemetry.
    #
    # The scores BEFORE this tier, for comparison in the write-up:
    #   GroupKFold     A 0.832 / B 0.791 / C 0.768 macro F1
    #   LeaveOneTechOut A 0.571 / B 0.543 / C 0.557 macro F1
    # ⚠️ DELETED, not replaced. A placeholder does not sanitise a token that only ONE class emits - it
    # just renames the leak. Measured: substituting " HARNESSFLAG " left it as a top feature at 11%
    # attack, and the bigram "user XREDACTED" sat at 0.0% attack, because only the mirror writes
    # `net user <name>` with a name worth redacting. The presence of the marker was the signal.
    # Removing the tokens outright is the only honest option, even though it also destroys some genuine
    # information (an attacker really might use -EncodedCommand). That cost is accepted and reported:
    # it biases AGAINST the model, which is the safe direction for a claim about what ML adds.
    (re.compile(r"-?\bnoprofile\b", re.I),     " "),
    (re.compile(r"-?\bexecutionpolicy\b", re.I), " "),
    (re.compile(r"-?\bbypass\b", re.I),        " "),
    (re.compile(r"-?\bencodedcommand\b", re.I), " "),
    (re.compile(r"-\s*command\b", re.I),       " "),
    (re.compile(r"\b(calc|notepad|calculator|win32calc)(\.exe)?\b", re.I), " PAYLOADBIN "),
    # -------------------------------------------------------------------------------------------
    (re.compile(r"&amp;|&gt;|&lt;|&quot;"),    " "),               # XML entities from Wazuh
    (re.compile(r"[\\/]+"),                    " "),               # path separators -> tokens
    (re.compile(r"\s+"),                       " "),
]


def sanitise(text):
    t = text or ""
    for pat, rep in _SANITISERS:
        t = pat.sub(rep, t)
    return t.strip().lower()


def basename(p):
    return (p or "").replace("\\\\", "\\").split("\\")[-1].split("/")[-1].lower()


# =====================================================================================================
# FEATURE SETS - the comparison IS the experiment
# =====================================================================================================
FEATURE_SETS = {
    "A_full": dict(rule=True, proc=True, text=True,
                   note="Everything. Expected to score well and to mean little - rule identity alone "
                        "is close to a giveaway (92052 is 359 attack / 2 benign)."),
    "B_no_rule": dict(rule=False, proc=True, text=True,
                      note="Rule id, level and ATT&CK tags removed. Forces the model onto process and "
                           "command-line evidence rather than 'which rule fired'."),
    "C_text_only": dict(rule=False, proc=False, text=True,
                        note="Sanitised command line only. The hardest and most honest setting: can "
                             "the behaviour itself be classified?"),
}


def load_rows():
    with open(DATA, newline="", encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh) if r["label"] == "1" and r["class"] in ("attack", "benign")]
    for r in rows:
        r["_text"] = sanitise(r.get("command_line_normalised") or r.get("command_line") or "")
        r["_img"] = basename(r.get("image"))
        r["_pimg"] = basename(r.get("parent_image"))
        r["_tobj"] = sanitise(r.get("target_object") or "")
    return rows


def build_matrix(rows, spec, fit_on=None):
    """Return a dense feature matrix. fit_on lets test data reuse the training vocabulary."""
    blocks, names = [], []
    fitted = {}
    src = fit_on if fit_on is not None else rows

    if spec["rule"]:
        for col in ("rule_canonical", "rule_level"):
            vals = sorted({r[col] for r in src})
            idx = {v: i for i, v in enumerate(vals)}
            m = np.zeros((len(rows), len(vals)))
            for i, r in enumerate(rows):
                j = idx.get(r[col])
                if j is not None:
                    m[i, j] = 1
            blocks.append(m); names += [f"{col}={v}" for v in vals]
        tags = sorted({t for r in src for t in (r["rule_mitre"] or "").split(";") if t})
        m = np.zeros((len(rows), len(tags)))
        for i, r in enumerate(rows):
            for t in (r["rule_mitre"] or "").split(";"):
                if t in tags:
                    m[i, tags.index(t)] = 1
        blocks.append(m); names += [f"mitre={t}" for t in tags]

    if spec["proc"]:
        for col in ("_img", "_pimg"):
            vals = sorted({r[col] for r in src})
            idx = {v: i for i, v in enumerate(vals)}
            m = np.zeros((len(rows), len(vals)))
            for i, r in enumerate(rows):
                j = idx.get(r[col])
                if j is not None:
                    m[i, j] = 1
            blocks.append(m); names += [f"{col}={v}" for v in vals]

    if spec["text"]:
        vec = fitted.get("tfidf")
        if fit_on is None:
            vec = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=2, max_features=400)
            vec.fit([r["_text"] for r in rows])
            spec["_vec"] = vec
        else:
            vec = spec["_vec"]
        m = vec.transform([r["_text"] for r in rows]).toarray()
        blocks.append(m); names += [f"txt={t}" for t in vec.get_feature_names_out()]

    return (np.hstack(blocks) if blocks else np.zeros((len(rows), 1))), names


def cross_val_predict(rows, spec, groups, splitter, clf_name="RandomForest"):
    """Out-of-fold labels AND probabilities. Every alert is predicted by a model that never saw its
    window (or its technique, depending on the splitter)."""
    y = np.array([1 if r["class"] == "attack" else 0 for r in rows])
    g = np.array(groups)
    preds = np.zeros(len(rows), dtype=int)
    probs = np.zeros(len(rows), dtype=float)

    for tr, te in splitter.split(np.zeros(len(rows)), y, g):
        train = [rows[i] for i in tr]
        test = [rows[i] for i in te]
        s = dict(spec)
        Xtr, _ = build_matrix(train, s)
        Xte, _ = build_matrix(test, s, fit_on=train)
        if Xtr.shape[1] != Xte.shape[1]:
            k = min(Xtr.shape[1], Xte.shape[1]); Xtr, Xte = Xtr[:, :k], Xte[:, :k]
        n_pos = max(int((y[tr] == 1).sum()), 1)
        n_neg = max(int((y[tr] == 0).sum()), 1)
        clf = CLASSIFIERS[clf_name](pos_weight=n_neg / n_pos)
        clf.fit(Xtr, y[tr])
        preds[te] = clf.predict(Xte)
        probs[te] = clf.predict_proba(Xte)[:, 1]
    return y, preds, probs


def evaluate(rows, spec_name, spec, groups, split_name, splitter, clf_name="RandomForest"):
    y, preds, probs = cross_val_predict(rows, spec, groups, splitter, clf_name)
    rep = classification_report(y, preds, target_names=["benign", "attack"],
                                output_dict=True, zero_division=0)
    return {
        "features": spec_name, "split": split_name, "classifier": clf_name,
        "attack_precision": rep["attack"]["precision"], "attack_recall": rep["attack"]["recall"],
        "attack_f1": rep["attack"]["f1-score"],
        "benign_precision": rep["benign"]["precision"], "benign_recall": rep["benign"]["recall"],
        "benign_f1": rep["benign"]["f1-score"],
        "macro_f1": rep["macro avg"]["f1-score"], "pr_auc": average_precision_score(y, probs),
        "cm": confusion_matrix(y, preds).tolist(),
    }


def print_confusion(cm, title):
    """
    Confusion matrices, printed rather than buried in the CSV. `evaluate` has always computed one and
    nothing ever displayed it, so the error BALANCE - which of the two mistakes the model actually makes
    - was invisible behind a single macro-F1 number. For a triage tool the two errors are not
    interchangeable: a false negative is a missed intrusion, a false positive is wasted analyst time.
    """
    (tn, fp), (fn, tp) = cm
    print(f"\n   {title}")
    print(f"      {'':16}{'pred benign':>13}{'pred attack':>13}")
    print(f"      {'actual benign':16}{tn:>13}{fp:>13}   <- {fp} false alarms")
    print(f"      {'actual attack':16}{fn:>13}{tp:>13}   <- {fn} MISSED attacks")
    total = tn + fp + fn + tp
    print(f"      {tp+fn} attacks, {tn+fp} benign, {total} alerts. "
          f"Missed {fn/(tp+fn)*100:.1f}% of attacks, false-alarmed on {fp/(tn+fp)*100:.1f}% of benign.")


def operating_points(rows, spec, groups, splitter, clf_name="RandomForest"):
    """
    ⚠️ THE QUESTION A SOC ACTUALLY ASKS, which macro F1 does not answer.

    A triage model is not deployed at its argmax-F1 threshold. It is deployed at whatever cut-off
    matches the team's tolerance for missed intrusions, and the operational question is: "if we only
    review the top N% of alerts, what fraction of real attacks do we still catch?" Reporting a single
    threshold-0.5 score hides the fact that the same model supports very different trade-offs.

    Reported as WORKLOAD REDUCTION, because that is the claim the dissertation makes: alert
    prioritisation is worth having only if an analyst can look at meaningfully fewer alerts without
    meaningfully more misses.
    """
    y, _, probs = cross_val_predict(rows, spec, groups, splitter, clf_name)
    n = len(y)
    n_atk = int(y.sum())
    out = []
    for thr in [round(t, 2) for t in np.arange(0.05, 1.00, 0.05)]:
        flagged = probs >= thr
        n_flag = int(flagged.sum())
        if n_flag == 0:
            continue
        tp = int((flagged & (y == 1)).sum())
        fp = int((flagged & (y == 0)).sum())
        fn = n_atk - tp
        prec = tp / n_flag
        rec = tp / n_atk
        f1 = 0.0 if prec + rec == 0 else 2 * prec * rec / (prec + rec)
        out.append({"threshold": thr, "reviewed": n_flag, "reviewed_pct": 100 * n_flag / n,
                    "tp": tp, "fp": fp, "missed": fn,
                    "precision": prec, "recall": rec, "f1": f1})
    return out


def rule_baselines(rows):
    """
    ⚠️ THE COMPARISON THE THESIS ACTUALLY NEEDS, and it was missing from the first version of this
    script. Reporting "the model reaches macro F1 0.784 against a 0.42 majority baseline" compares the
    model against predicting the most common class - not against the RULESET it is meant to supplement.
    An examiner asks that immediately, and the honest answer has to be a measured number.

    Three heuristics an analyst could actually apply to this alert stream with no model at all:

      severity>=N   escalate anything at Wazuh level N or above. This is what alert triage looks like
                    in practice when there is no model: a severity threshold.
      any-custom    escalate if one of the 37 engineered rules fired. Tests whether the rules built in
                    this project function as a triage signal, which is the strongest form of the
                    "do we even need a model" question.
      technique-tagged  escalate if the alert carries the ATT&CK ID of the technique under test, i.e.
                    perfect attribution. An upper bound on what correct labelling alone can do.
    """
    y = np.array([1 if r["class"] == "attack" else 0 for r in rows])
    out = []

    for lvl in (6, 8, 10, 12):
        pred = np.array([1 if int(r["rule_level"] or 0) >= lvl else 0 for r in rows])
        out.append((f"severity >= {lvl}", pred))

    pred = np.array([1 if r["rule_id"].startswith(("1002", "1003")) else 0 for r in rows])
    out.append(("any custom rule fired", pred))

    pred = np.array([1 if r["technique_id"] in (r["rule_mitre"] or "").split(";") else 0 for r in rows])
    out.append(("alert tagged with the technique", pred))

    print("\n" + "=" * 100)
    print("RULE-BASED BASELINES - what an analyst gets with no model at all")
    print("=" * 100)
    print(f"{'heuristic':34} {'atk P':>7} {'atk R':>7} {'atk F1':>7} {'ben F1':>7} {'macroF1':>8}")
    results = []
    for name, pred in out:
        rep = classification_report(y, pred, target_names=["benign", "attack"],
                                    output_dict=True, zero_division=0)
        results.append({"features": f"BASELINE: {name}", "split": "n/a (no training)",
                        "attack_precision": rep["attack"]["precision"],
                        "attack_recall": rep["attack"]["recall"],
                        "attack_f1": rep["attack"]["f1-score"],
                        "benign_precision": rep["benign"]["precision"],
                        "benign_recall": rep["benign"]["recall"],
                        "benign_f1": rep["benign"]["f1-score"],
                        "macro_f1": rep["macro avg"]["f1-score"], "pr_auc": float("nan")})
        print(f"{name:34} {rep['attack']['precision']:7.3f} {rep['attack']['recall']:7.3f} "
              f"{rep['attack']['f1-score']:7.3f} {rep['benign']['f1-score']:7.3f} "
              f"{rep['macro avg']['f1-score']:8.3f}")
    maj = np.ones(len(y))
    rep = classification_report(y, maj, target_names=["benign", "attack"], output_dict=True,
                                zero_division=0)
    print(f"{'always predict attack':34} {rep['attack']['precision']:7.3f} "
          f"{rep['attack']['recall']:7.3f} {rep['attack']['f1-score']:7.3f} "
          f"{rep['benign']['f1-score']:7.3f} {rep['macro avg']['f1-score']:8.3f}")
    return results


def fp_reduction_vs_severity(rows, spec, groups, splitter, clf_name="RandomForest"):
    """
    ⭐ THE DISSERTATION'S STATED SUCCESS CRITERION (§3.4):
       "a measurable false-positive reduction against a detection-only baseline, WITHOUT LOSS OF RECALL"

    Every other comparison in this file comparees the two approaches at THEIR OWN operating points, which
    is not what §3.4 asks. The criterion is a matched-recall comparison: hold recall at whatever the
    detection-only baseline achieves, and count how many fewer false positives the model produces.

    DETECTION-ONLY BASELINE = rank by Wazuh rule level alone, no model. That is precisely what a SOC does
    today with an out-of-the-box SIEM, and it is the comparison the write-up promised.

    Rule level is a coarse integer, so the baseline offers only a handful of operating points. For each
    one we take its recall as the floor, find the LOWEST-cost model threshold that still meets or beats
    that recall, and compare false-positive counts. Choosing the model point by "cheapest that matches
    recall" rather than "best F1" is deliberate - it is the honest way to answer "same detection, less
    noise?".
    """
    y, _, probs = cross_val_predict(rows, spec, groups, splitter, clf_name)
    levels = np.array([int(r["rule_level"]) for r in rows])
    n_atk = int(y.sum())
    n_ben = int((y == 0).sum())

    out = []
    for lvl in sorted(set(levels.tolist())):
        flag = levels >= lvl
        tp = int((flag & (y == 1)).sum())
        fp = int((flag & (y == 0)).sum())
        if tp == 0:
            continue
        base_rec = tp / n_atk

        # cheapest model threshold that does not lose recall
        best = None
        for thr in [round(t, 3) for t in np.arange(0.01, 1.0, 0.01)]:
            mflag = probs >= thr
            mtp = int((mflag & (y == 1)).sum())
            if mtp / n_atk >= base_rec:
                mfp = int((mflag & (y == 0)).sum())
                if best is None or mfp < best[1]:
                    best = (thr, mfp, mtp)
        if best is None:
            continue
        thr, mfp, mtp = best
        out.append({
            "baseline": f"rule level >= {lvl}",
            "base_recall": base_rec, "base_fp": fp,
            "model_threshold": thr, "model_recall": mtp / n_atk, "model_fp": mfp,
            "fp_reduction": fp - mfp,
            "fp_reduction_pct": (100.0 * (fp - mfp) / fp) if fp else 0.0,
            "n_benign": n_ben,
        })
    return out


def per_fold_variance(rows, spec, groups, splitter, seeds=(42, 7, 1337)):
    """Macro F1 per fold and across seeds. A single number from a single seed is not a result."""
    y = np.array([1 if r["class"] == "attack" else 0 for r in rows])
    g = np.array(groups)
    scores = []
    for seed in seeds:
        for tr, te in splitter.split(np.zeros(len(rows)), y, g):
            train = [rows[i] for i in tr]; test = [rows[i] for i in te]
            s = dict(spec)
            Xtr, _ = build_matrix(train, s)
            Xte, _ = build_matrix(test, s, fit_on=train)
            k = min(Xtr.shape[1], Xte.shape[1]); Xtr, Xte = Xtr[:, :k], Xte[:, :k]
            clf = RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                         min_samples_leaf=2, random_state=seed, n_jobs=-1)
            clf.fit(Xtr, y[tr])
            rep = classification_report(y[te], clf.predict(Xte), output_dict=True, zero_division=0)
            scores.append(rep["macro avg"]["f1-score"])
    return np.mean(scores), np.std(scores), min(scores), max(scores), len(scores)


def per_technique_breakdown(rows, spec):
    """Where does it fail? LeaveOneTechniqueOut, reported per held-out technique."""
    y = np.array([1 if r["class"] == "attack" else 0 for r in rows])
    g = np.array([r["technique_id"] for r in rows])
    print("\n" + "=" * 100)
    print("PER-TECHNIQUE - LeaveOneTechniqueOut, B_no_rule. Each row: model never saw this technique.")
    print("=" * 100)
    print(f"{'held-out technique':13} {'n':>5} {'atk':>5} {'ben':>5} {'atk F1':>7} {'ben F1':>7} {'macroF1':>8}")
    rowsout = []
    for tech in sorted(set(g)):
        te = np.where(g == tech)[0]; tr = np.where(g != tech)[0]
        train = [rows[i] for i in tr]; test = [rows[i] for i in te]
        s = dict(spec)
        Xtr, _ = build_matrix(train, s)
        Xte, _ = build_matrix(test, s, fit_on=train)
        k = min(Xtr.shape[1], Xte.shape[1]); Xtr, Xte = Xtr[:, :k], Xte[:, :k]
        clf = RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                     min_samples_leaf=2, random_state=42, n_jobs=-1)
        clf.fit(Xtr, y[tr])
        rep = classification_report(y[te], clf.predict(Xte), output_dict=True, zero_division=0,
                                    labels=[0, 1], target_names=["benign", "attack"])
        na = int((y[te] == 1).sum()); nb = int((y[te] == 0).sum())
        print(f"{tech:13} {len(te):5} {na:5} {nb:5} {rep['attack']['f1-score']:7.3f} "
              f"{rep['benign']['f1-score']:7.3f} {rep['macro avg']['f1-score']:8.3f}")
        rowsout.append((tech, len(te), na, nb, rep["macro avg"]["f1-score"]))
    return rowsout


def main():
    rows = load_rows()
    y = [r["class"] for r in rows]
    print(f"in-window alerts        : {len(rows)}")
    print(f"  attack / benign       : {y.count('attack')} / {y.count('benign')}")
    print(f"  windows (group unit)  : {len({r['session_id'] for r in rows})}")
    print(f"  techniques            : {len({r['technique_id'] for r in rows})}")
    maj = max(y.count('attack'), y.count('benign')) / len(y)
    print(f"  majority-class baseline accuracy: {maj:.3f}  <- any model must beat this to mean anything")

    # ⚠️ The placeholder must not contain any token this check looks for. The first version substituted
    # " LABARTEFACT ", which contains "lab" - so the leak check found 517 hits and they were all the
    # sanitiser matching its own replacement. A verification step that can be satisfied by the thing it
    # is verifying is worse than no verification, because it reports success. Placeholder is XREDACTED.
    print("\nLEAK CHECK after sanitisation (every count must be 0):")
    leaks = 0
    for tok in ("atomic", "benign", "lab", "deleteme", "smoke", "basit", "t1136", "t1551", "t1087"):
        n = sum(1 for r in rows if tok in r["_text"])
        leaks += n
        flag = "" if n == 0 else "   <== LEAK, results are invalid until fixed"
        print(f"   '{tok}': {n}{flag}")
    if leaks:
        print("\n   ⚠️ Sanitisation incomplete. Any score below reflects lab naming, not behaviour.")
    # Show what the model actually sees, so the sanitisation can be eyeballed rather than trusted.
    print("\n   sample sanitised text (attack / benign):")
    for cls in ("attack", "benign"):
        for r in rows:
            if r["class"] == cls and len(r["_text"]) > 40:
                print(f"     {cls:7} {r['_text'][:104]}")
                break

    results = []
    for split_name, splitter, groups in [
        ("GroupKFold(5) by window", GroupKFold(n_splits=5), [r["session_id"] for r in rows]),
        ("LeaveOneTechniqueOut", LeaveOneGroupOut(), [r["technique_id"] for r in rows]),
    ]:
        print(f"\n{'='*100}\nSPLIT: {split_name}\n{'='*100}")
        print(f"{'features':13} {'atk P':>7} {'atk R':>7} {'atk F1':>7} {'ben P':>7} {'ben R':>7} "
              f"{'ben F1':>7} {'macroF1':>8} {'PR-AUC':>7}")
        for sname, spec in FEATURE_SETS.items():
            r = evaluate(rows, sname, dict(spec), groups, split_name, splitter)
            results.append(r)
            print(f"{sname:13} {r['attack_precision']:7.3f} {r['attack_recall']:7.3f} "
                  f"{r['attack_f1']:7.3f} {r['benign_precision']:7.3f} {r['benign_recall']:7.3f} "
                  f"{r['benign_f1']:7.3f} {r['macro_f1']:8.3f} {r['pr_auc']:7.3f}")

    results += rule_baselines(rows)

    # -------------------------------------------------------------------------------------------
    gkf = GroupKFold(n_splits=5)
    sess = [r["session_id"] for r in rows]

    print("\n" + "=" * 100)
    print("CLASSIFIER COMPARISON - B_no_rule, both splits")
    print("=" * 100)
    if not HAVE_XGB:
        print("  xgboost not installed:  pip install xgboost --break-system-packages")
    print(f"{'classifier':14} {'split':26} {'atk F1':>7} {'ben F1':>7} {'macroF1':>8} {'PR-AUC':>7}")
    for clf_name in CLASSIFIERS:
        for split_name, splitter, groups in [
            ("GroupKFold(5) by window", gkf, sess),
            ("LeaveOneTechniqueOut", LeaveOneGroupOut(), [r["technique_id"] for r in rows]),
        ]:
            r = evaluate(rows, "B_no_rule", dict(FEATURE_SETS["B_no_rule"]),
                         groups, split_name, splitter, clf_name)
            r["features"] = f"B_no_rule [{clf_name}]"
            results.append(r)
            print(f"{clf_name:14} {split_name:26} {r['attack_f1']:7.3f} {r['benign_f1']:7.3f} "
                  f"{r['macro_f1']:8.3f} {r['pr_auc']:7.3f}")
            if split_name.startswith("GroupKFold"):
                print_confusion(r["cm"], f"Confusion matrix - {clf_name}, B_no_rule, GroupKFold")

    print("\n" + "=" * 100)
    print("OPERATING POINTS - B_no_rule, RandomForest, GroupKFold by window")
    print("What a SOC actually needs: review the top N% of alerts, catch what fraction of attacks?")
    print("=" * 100)
    ops = operating_points(rows, dict(FEATURE_SETS["B_no_rule"]), sess, gkf)
    print(f"{'thresh':>7} {'reviewed':>9} {'% of all':>9} {'caught':>7} {'missed':>7} "
          f"{'precision':>10} {'recall':>8} {'F1':>7}")
    for o in ops:
        print(f"{o['threshold']:7.2f} {o['reviewed']:9} {o['reviewed_pct']:8.1f}% {o['tp']:7} "
              f"{o['missed']:7} {o['precision']:10.3f} {o['recall']:8.3f} {o['f1']:7.3f}")

    # The two cut-offs a SOC would actually argue about, picked from the sweep rather than asserted.
    hi_rec = [o for o in ops if o["recall"] >= 0.95]
    hi_prec = [o for o in ops if o["precision"] >= 0.95]
    print("\n  Two defensible operating points:")
    if hi_rec:
        o = max(hi_rec, key=lambda o: o["threshold"])
        print(f"    MISS-AVERSE  thr {o['threshold']:.2f}: review {o['reviewed_pct']:.1f}% of alerts, "
              f"catch {o['recall']*100:.1f}% of attacks, miss {o['missed']}.")
    if hi_prec:
        o = min(hi_prec, key=lambda o: o["threshold"])
        print(f"    LOAD-AVERSE  thr {o['threshold']:.2f}: review {o['reviewed_pct']:.1f}% of alerts, "
              f"{o['precision']*100:.1f}% of what you open is real, miss {o['missed']}.")
    print("  ⚠️ Both are measured on THIS lab's 72/28 attack/benign mix. A real SOC queue is far more")
    print("     benign-heavy, so precision at any threshold would be substantially lower in production.")

    print("\n" + "=" * 100)
    print("SUCCESS CRITERION (§3.4) - FALSE POSITIVES AT MATCHED RECALL")
    print("Detection-only baseline = rank by Wazuh rule level alone. Recall held at the baseline's own.")
    print("=" * 100)
    fpr = fp_reduction_vs_severity(rows, dict(FEATURE_SETS["B_no_rule"]), sess, gkf)
    print(f"{'detection-only baseline':24} {'recall':>7} {'its FPs':>8} | "
          f"{'model thr':>9} {'recall':>7} {'its FPs':>8} {'FP saved':>9} {'reduction':>10}")
    for o in fpr:
        print(f"{o['baseline']:24} {o['base_recall']:7.3f} {o['base_fp']:8} | "
              f"{o['model_threshold']:9.2f} {o['model_recall']:7.3f} {o['model_fp']:8} "
              f"{o['fp_reduction']:9} {o['fp_reduction_pct']:9.1f}%")
    if fpr:
        head = max(fpr, key=lambda o: o["base_recall"])
        print(f"\n  ⭐ At the baseline's highest recall ({head['base_recall']*100:.1f}%, "
              f"'{head['baseline']}'), the model matches that recall with "
              f"{head['model_fp']} false positives instead of {head['base_fp']} "
              f"- a {head['fp_reduction_pct']:.1f}% reduction.")
        print("  Recall is held at or above the baseline's in every row, so no detection is traded away.")

    print("\n" + "=" * 100)
    print("FOLD AND SEED VARIANCE - B_no_rule, GroupKFold by window, 3 seeds x 5 folds")
    print("=" * 100)
    m, sd, lo, hi, n = per_fold_variance(rows, dict(FEATURE_SETS["B_no_rule"]),
                                         [r["session_id"] for r in rows], GroupKFold(n_splits=5))
    print(f"  macro F1 mean {m:.3f}  sd {sd:.3f}  range {lo:.3f}-{hi:.3f}  over {n} fits")
    print("  A single number from a single seed is not a result; this is the spread behind it.")

    per_technique_breakdown(rows, dict(FEATURE_SETS["B_no_rule"]))

    os.makedirs("ml", exist_ok=True)
    with open(os.path.join("ml", "triage_results.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=[k for k in results[0] if k != "cm"])
        w.writeheader()
        for r in results:
            w.writerow({k: v for k, v in r.items() if k != "cm"})
    print("\nwritten: ml/triage_results.csv")

    print("\nFEATURE-SET NOTES")
    for k, v in FEATURE_SETS.items():
        print(f"  {k:13} {v['note']}")

    # =================================================================================================
    # WHAT IS IT ACTUALLY KEYING ON?
    # Fitted on everything - not an evaluation, just an inspection of which signals carry weight in the
    # no-rule-identity setting. This is the part that connects to the study's convergent finding: rules
    # that separated the classes encoded WHAT WAS DONE TO WHAT, not HOW. If the model has found the same
    # thing, its top features should be objects and targets rather than binaries and verbs.
    # =================================================================================================
    print("\n" + "=" * 100)
    print("TOP FEATURES - B_no_rule, fitted on the full dataset (inspection, not evaluation)")
    print("=" * 100)
    spec = dict(FEATURE_SETS["B_no_rule"])
    X, names = build_matrix(rows, spec)
    yb = np.array([1 if r["class"] == "attack" else 0 for r in rows])
    clf = RandomForestClassifier(n_estimators=400, class_weight="balanced",
                                 min_samples_leaf=2, random_state=42, n_jobs=-1)
    clf.fit(X, yb)
    imp = sorted(zip(names, clf.feature_importances_), key=lambda t: -t[1])[:25]
    atk_rate = {}
    for nm, _ in imp:
        col = names.index(nm)
        present = X[:, col] > 0
        atk_rate[nm] = (yb[present].mean() if present.sum() else float("nan"), int(present.sum()))
    for nm, v in imp:
        rate, n = atk_rate[nm]
        lean = "attack" if rate > 0.72 else ("benign" if rate < 0.5 else "mixed")
        print(f"  {v:.4f}  {nm:52} n={n:<5} {rate*100:5.1f}% attack  [{lean}]")


if __name__ == "__main__":
    main()
