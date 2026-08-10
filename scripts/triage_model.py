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

DATA = os.path.join("data", "labelled_alerts.csv")

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


def evaluate(rows, spec_name, spec, groups, split_name, splitter):
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
        clf = RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                     min_samples_leaf=2, random_state=42, n_jobs=-1)
        clf.fit(Xtr, y[tr])
        preds[te] = clf.predict(Xte)
        probs[te] = clf.predict_proba(Xte)[:, 1]

    rep = classification_report(y, preds, target_names=["benign", "attack"],
                                output_dict=True, zero_division=0)
    return {
        "features": spec_name, "split": split_name,
        "attack_precision": rep["attack"]["precision"], "attack_recall": rep["attack"]["recall"],
        "attack_f1": rep["attack"]["f1-score"],
        "benign_precision": rep["benign"]["precision"], "benign_recall": rep["benign"]["recall"],
        "benign_f1": rep["benign"]["f1-score"],
        "macro_f1": rep["macro avg"]["f1-score"], "pr_auc": average_precision_score(y, probs),
        "cm": confusion_matrix(y, preds).tolist(),
    }


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
