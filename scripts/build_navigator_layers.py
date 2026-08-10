#!/usr/bin/env python3
"""
Build two MITRE ATT&CK Navigator layers from labelled_alerts.csv:

    navigator_layers/01_default_ruleset.json   what stock Wazuh detects
    navigator_layers/02_custom_ruleset.json    what the engineered ruleset detects

WHY THIS IS A SCRIPT AND NOT HAND-WRITTEN JSON
    The layers are a Chapter 4 figure. If they are typed by hand they drift from the dataset the moment
    a count changes - and in this project counts changed nine times in one afternoon after a filter fix.
    Everything here is derived from labelled_alerts.csv, so the figure cannot disagree with the data.

SCORING - derived, not asserted
    Each technique is scored 0-3 on DETECTION QUALITY, computed from the alerts actually observed in
    that technique's attack windows:

      0  BLIND        no alert carries the technique ID or its parent
      1  PARENT/WRONG alerts exist but carry only the PARENT technique (e.g. T1087 for T1087.001) or a
                      different technique entirely - the behaviour is visible, the attribution is not
      2  DETECTED     at least one alert carries the exact technique ID
      3  DISCRIMINATING  exact technique ID present AND the rules carrying it fired zero times in the
                      benign class - i.e. the detection also separates attacker from administrator

    Tier 3 is the one that matters for the dissertation's argument, and it is deliberately hard to
    reach: across 15 techniques the default ruleset reaches it once.

USAGE
    python3 scripts/build_navigator_layers.py
    (run from the repo root; reads data/labelled_alerts.csv)

    Load the JSON files at https://mitre-attack.github.io/attack-navigator/
"""

import csv
import json
import os
from collections import defaultdict

DATA = os.path.join("data", "labelled_alerts.csv")
OUTDIR = "navigator_layers"

# The 15 techniques in the study, with the tactic each is filed under. Order matches COVERAGE_TABLE.md.
TECHNIQUES = [
    ("T1087.001", "discovery"),
    ("T1082", "discovery"),
    ("T1033", "discovery"),
    ("T1016", "discovery"),
    ("T1059.001", "execution"),
    ("T1059.003", "execution"),
    ("T1053.005", "persistence"),
    ("T1136.001", "persistence"),
    ("T1547.001", "persistence"),
    ("T1112", "defense-evasion"),
    ("T1218.011", "defense-evasion"),
    ("T1070.004", "defense-evasion"),
    ("T1560.001", "collection"),
    ("T1003.001", "credential-access"),
    ("T1105", "command-and-control"),
]

# Phases that represent "the engineered setup" for each technique. Three techniques needed a sensor
# change as well as rules, and two deliberately have no custom phase because the default was adequate -
# for those the custom layer necessarily shows the baseline result, which is the honest representation.
FINAL_PHASE = {
    "T1112": "custom-sensor",
    "T1070.004": "custom-sensor",
    "T1003.001": "custom-sensor",
    "T1059.001": "baseline",   # no rule written - default already correct
    "T1059.003": "baseline",   # no rule written - default already correct
    "T1105": "baseline",       # no rule written - default already correct AND discriminating
}

NO_RULE_WRITTEN = {"T1059.001", "T1059.003", "T1105"}

# ⚠️ A score of 3 means "the exact technique ID was carried and those rules never fired on the benign
# mirror". It does NOT automatically mean the rule understands intent. Four scores are qualified, and the
# qualification is printed onto the layer itself so the figure cannot be read without it. Derived scores
# are only as honest as the caveats attached to them.
CAVEATS = {
    ("T1136.001", "default"):
        "⚠️ The 10/0 is ARGUMENT ORDER, not intent. 92040 (L12, T1136.001) requires the command line to "
        "match `add\\s`. The atomic runs `net user /add NAME PASS` (add + space) and fires it; the "
        "mirror runs `net user NAME PASS /add` (add is the last token, no trailing whitespace) and does "
        "NOT. The most natural way a human types the command evades a level-12 credential-creation "
        "rule and falls back to parent 92039, which calls it 'account discovery'.",
    ("T1033", "default"):
        "⚠️ PARTIAL COVERAGE. 92022 correctly maps qwinsta session enumeration to T1033, but whoami - "
        "the most common way anyone establishes identity - went to T1087+T1059.003 via 92032. The "
        "technique is detected for one variant and misattributed for the dominant one.",
    ("T1112", "default"):
        "⚠️ FALSE PRECISION. The exact-ID match comes from 92041, whose regex quantifies every group "
        "after /d with * or ?, so it matches ANY `reg add ... /d <anything>` - verified down to "
        "`add x /d `. It fired once per reg add issued and asserted T1027 obfuscation in 45 of 45 "
        "cases. It is a reg.exe execution counter wearing a base64 detector's description.",
    ("T1105", "default"):
        "⚠️ The 40/0 is specific to THIS mirror. 92074/92207/92227 key on the object (a .exe or .dll) "
        "and the destination (Users\\Public); the mirror fetches a .txt to Temp. An administrator "
        "downloading a legitimate installer with curl would trip 92074. Genuine intent-encoding, but "
        "not a general claim of zero false positives.",
}


def parent_of(technique_id):
    """T1087.001 -> T1087 ; T1112 -> None"""
    return technique_id.split(".")[0] if "." in technique_id else None


def load():
    with open(DATA, newline="", encoding="utf-8") as fh:
        return [r for r in csv.DictReader(fh) if r["label"] == "1" and r["technique_id"]]


def score_phase(rows, technique_id, phase):
    """Return (score, detail dict) for one technique in one phase."""
    sel = [r for r in rows if r["technique_id"] == technique_id and r["ruleset_phase"] == phase]
    atk = [r for r in sel if r["class"] == "attack"]
    ben = [r for r in sel if r["class"] == "benign"]
    parent = parent_of(technique_id)

    def tags(r):
        return {t for t in (r["rule_mitre"] or "").split(";") if t}

    exact_rules = {r["rule_id"] for r in atk if technique_id in tags(r)}
    parent_rules = {r["rule_id"] for r in atk if parent and parent in tags(r)}

    exact_atk = sum(1 for r in atk if technique_id in tags(r))
    # ⚠️ Count benign alerts CARRYING THE TECHNIQUE ID, not benign alerts from rules that happened to
    # fire in the attack class. The first version used `r["rule_id"] in exact_rules`, where exact_rules
    # was built only from attack-class alerts - so a rule that carries the technique ID and fires
    # ONLY on benign activity was invisible to the check. T1560.001 scored 3 ("never fires on benign")
    # while 100330 and 100331, both tagged T1560.001, fired 5 and 5 times in the benign class and
    # nowhere else. The question the tier is meant to answer is "does this detection also fire on the
    # administrator?", and that has to be asked of the tag, not of the rule set that won in attack.
    exact_ben = sum(1 for r in ben if technique_id in tags(r))

    # ⚠️ `elif parent_rules` NOT `elif parent_rules or atk`. The first version scored a technique 1
    # ("parent / misattributed") whenever ANY alert existed in its windows, which conflated two
    # completely different findings: T1003.001 produced alerts but not one carried T1003.001 or a
    # parent - it is BLIND - while T1087.001 produced alerts carrying the parent T1087 and nothing
    # else. Those are different results and the figure must not merge them.
    if exact_rules:
        score = 3 if exact_ben == 0 else 2
    elif parent_rules:
        score = 1
    else:
        score = 0

    return score, {
        "attack_total": len(atk),
        "benign_total": len(ben),
        "exact_attack": exact_atk,
        "exact_benign": exact_ben,
        "exact_rules": sorted(exact_rules),
        "parent_rules": sorted(parent_rules - exact_rules),
    }


LABEL = {0: "BLIND", 1: "PARENT / MISATTRIBUTED", 2: "DETECTED", 3: "DETECTED + DISCRIMINATING"}


def build_layer(rows, which):
    entries, tally = [], defaultdict(int)
    for tid, tactic in TECHNIQUES:
        phase = "baseline" if which == "default" else FINAL_PHASE.get(tid, "custom")
        score, d = score_phase(rows, tid, phase)
        tally[score] += 1

        note = [f"{LABEL[score]}  (phase: {phase})",
                f"attack alerts {d['attack_total']} / benign {d['benign_total']}",
                f"carrying {tid} exactly: {d['exact_attack']} attack, {d['exact_benign']} benign"]
        if d["exact_rules"]:
            note.append("rules with exact ID: " + ", ".join(d["exact_rules"]))
        if d["parent_rules"]:
            note.append("parent/other-technique rules only: " + ", ".join(d["parent_rules"]))
        if which == "custom" and tid in NO_RULE_WRITTEN:
            note.append("NO CUSTOM RULE WRITTEN - the default ruleset was already correct here, so "
                        "writing one would duplicate working detection and inflate the apparent "
                        "contribution of this project.")
        if which == "custom" and FINAL_PHASE.get(tid) == "custom-sensor":
            note.append("Required a SENSOR configuration change as well as rules - the default Sysmon "
                        "config emitted no usable telemetry for this technique.")
        caveat = CAVEATS.get((tid, which))
        if caveat:
            note.append(caveat)

        entries.append({
            "techniqueID": tid,
            "tactic": tactic,
            "score": score,
            "comment": "\n".join(note),
            "enabled": True,
            "showSubtechniques": True,
        })

    entries.extend(parent_container_rows(entries))
    return entries, tally


def parent_container_rows(entries):
    """
    ⚠️ WITHOUT THIS THE FIGURE RENDERS 5 TECHNIQUES INSTEAD OF 15.

    Ten of the fifteen studied techniques are SUB-techniques (T1087.001, T1059.001, T1059.003,
    T1053.005, T1136.001, T1547.001, T1218.011, T1070.004, T1560.001, T1003.001). In the Navigator a
    sub-technique is not a cell of its own - it is drawn inside its parent's expanded row. Two things
    therefore have to be true before it is visible at all:

        1. the PARENT technique must be present and enabled - otherwise `hideDisabled: true` removes
           the whole row, and the sub-technique inside it goes with it;
        2. the parent must carry `showSubtechniques: true`, or the row renders collapsed and the
           sub-technique stays hidden behind the expand arrow.

    Neither was true. The layers validated perfectly as DATA - 15 entries, correct scores, correct
    tactics - and would have displayed only the five top-level techniques (T1082, T1033, T1016, T1112,
    T1105). A figure can be right in every field it contains and still be wrong about what it shows,
    and that failure is invisible to every check that does not actually render it.

    The parent rows are deliberately emitted with NO `score` key. Scoring them 0 would paint nine extra
    red cells and turn a tally of seven blind techniques into sixteen; these rows are scaffolding for
    the matrix, not measurements. The tactic is inherited from the child so the parent lands in the
    same column.
    """
    by_parent = {}
    for e in entries:
        tid = e["techniqueID"]
        if "." not in tid:
            continue
        by_parent.setdefault(tid.split(".")[0], []).append((tid, e["tactic"]))

    present = {e["techniqueID"] for e in entries}
    rows = []
    for parent, children in sorted(by_parent.items()):
        if parent in present:          # already measured in its own right - leave it alone
            continue
        rows.append({
            "techniqueID": parent,
            "tactic": children[0][1],
            "comment": ("STRUCTURAL ROW - not a measurement.\n"
                        "Present only so the Navigator will draw its sub-technique(s): "
                        + ", ".join(c[0] for c in children) + ".\n"
                        "Deliberately unscored: the study measured the sub-technique, not the parent, "
                        "and colouring this cell would double-count it in the coverage tally."),
            "enabled": True,
            "showSubtechniques": True,
        })
    return rows


def strip_tactics(entries):
    """
    ⚠️ ATT&CK v19 (28 April 2026) DELETED the tactic these layers were built against.

    Defense Evasion was split into Stealth and Defense Impairment. Three of the fifteen studied
    techniques - T1112, T1218.011, T1070.004 - carry `"tactic": "defense-evasion"`, a shortname that no
    longer resolves. Loading the v14 layers on the live Navigator therefore triggers a migration wizard
    and renders those three unreliably.

    `tactic` is OPTIONAL in the layer format. Omitted, the Navigator resolves each technique's tactics
    from whichever ATT&CK dataset it has loaded, so the layer renders correctly on v19 and on whatever
    replaces it. The cost is that a technique belonging to several tactics is highlighted in each of
    them - T1053.005 appears under Execution, Persistence AND Privilege Escalation. The COUNT of
    coloured cells therefore exceeds fifteen in the v19 layers; the count of distinct techniques does
    not. The v14 pair, with tactics pinned, remains the citable figure for exactly this reason.

    Guessing the new shortnames was the obvious alternative and was rejected: a wrong guess fails
    silently by dropping the technique from the matrix, which is the same class of bug as the missing
    parent rows.
    """
    out = []
    for e in entries:
        e = dict(e)
        e.pop("tactic", None)
        out.append(e)
    return out


def layer_json(name, description, entries, attack_version="14"):
    return {
        "name": name,
        "versions": {"attack": attack_version, "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description,
        "techniques": entries,
        "gradient": {
            "colors": ["#c62828", "#ef6c00", "#f9a825", "#2e7d32"],
            "minValue": 0,
            "maxValue": 3,
        },
        "legendItems": [
            {"label": "0  Blind - no alert carries the technique or its parent", "color": "#c62828"},
            {"label": "1  Parent only / misattributed to another technique", "color": "#ef6c00"},
            {"label": "2  Detected at the correct technique", "color": "#f9a825"},
            {"label": "3  Detected AND fires zero times on benign activity", "color": "#2e7d32"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f",
        "selectTechniquesAcrossTactics": False,
        "hideDisabled": True,
    }


def main():
    rows = load()
    os.makedirs(OUTDIR, exist_ok=True)

    specs = [
        ("default", "01_default_ruleset.json",
         "Detection coverage - STOCK WAZUH 4.14.6",
         "MSc dissertation, Abdul Basit Mohammed (c5038891). Coverage of 15 ATT&CK techniques using the "
         "DEFAULT Wazuh ruleset with no customisation, measured over 5 attack and 5 benign detonation "
         "windows per technique. Scores are computed from labelled_alerts.csv, not assigned by hand."),
        ("custom", "02_custom_ruleset.json",
         "Detection coverage - ENGINEERED RULESET",
         "Same 15 techniques after deploying 37 custom Wazuh rules, and for T1112, T1070.004 and "
         "T1003.001 a widened Sysmon configuration. Three techniques were deliberately given NO custom "
         "rule because the default was already correct."),
    ]

    for which, fname, name, desc in specs:
        entries, tally = build_layer(rows, which)

        # v14 - tactics pinned. The citable figure: matches the Wazuh rule mappings, COVERAGE_TABLE.md
        # and the seven-tactic claim in the write-up. Reproduces the study as conducted.
        path = os.path.join(OUTDIR, fname)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(layer_json(name, desc, entries, "14"), fh, indent=2)

        # v19 - tactics omitted. Renders on the live Navigator without a migration wizard.
        v19_path = os.path.join(OUTDIR, fname.replace(".json", "_v19.json"))
        v19_desc = (desc + "  [ATT&CK v19 rendering. Tactic assignments are resolved by the Navigator "
                    "rather than pinned, because v19 split Defense Evasion into Stealth and Defense "
                    "Impairment after this study was conducted. Techniques belonging to several "
                    "tactics are highlighted in each, so the coloured-cell count exceeds 15; the "
                    "distinct-technique count does not. Cite the v14 layer.]")
        with open(v19_path, "w", encoding="utf-8") as fh:
            json.dump(layer_json(name + " (ATT&CK v19)", v19_desc,
                                 strip_tactics(entries), "19"), fh, indent=2)

        print(f"\n{name}")
        print(f"   v14 (cite this) -> {path}")
        print(f"   v19 (renders)   -> {v19_path}")
        for s in (0, 1, 2, 3):
            if tally[s]:
                names = [e["techniqueID"] for e in entries if e.get("score") == s]
                print(f"   {s}  {LABEL[s]:28} {tally[s]:2}   {', '.join(names)}")

    print("\nLoad at https://mitre-attack.github.io/attack-navigator/ (Open Existing Layer > Upload)")
    print("The live site serves ATT&CK v19 - use the _v19 files there. The v14 pair is the archived,")
    print("citable record and will trigger a version-migration wizard if opened on the live site.")


if __name__ == "__main__":
    main()
