#!/usr/bin/env python3
"""
Generate COVERAGE_SUMMARY.md - the compact, appendix-ready version of COVERAGE_TABLE.md.

    python3 scripts/build_coverage_summary.py

WHY THIS IS GENERATED AND NOT TYPED
    COVERAGE_TABLE.md is ~90,000 characters of per-technique prose. It is the working record and it is
    unreadable as an appendix. This produces the eight-column version that goes in the dissertation.

    It is generated for the same reason every other figure in this project is: a table typed by hand
    drifts from the dataset the moment a count changes, and counts in this project changed repeatedly
    after export fixes. COVERAGE_TABLE.md itself carried "258 usable windows / 4,636 alerts" and
    "92213 fires 551 times" long after both were wrong, and neither was caught by reading.

    Scores come from build_navigator_layers.py, so this table and the Navigator figures cannot disagree.
    Counts come from labelled_alerts.csv. Rule IDs come from local_rules.xml.

ALERT COUNTS ARE THE FINAL PHASE
    custom for most techniques, custom-sensor for T1112/T1070.004/T1003.001, and baseline for the three
    that were deliberately given no custom rule. The "default outcome" column is the BASELINE phase -
    that is what produces the 7 blind / 1 parent-only / 4 detected / 3 discriminating headline.
"""

import csv
import importlib.util
import os
import re
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

NAMES = {
    "T1087.001": "Local Account Discovery",
    "T1082": "System Information Discovery",
    "T1033": "System Owner/User Discovery",
    "T1016": "System Network Configuration Discovery",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1053.005": "Scheduled Task",
    "T1136.001": "Create Local Account",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1112": "Modify Registry",
    "T1218.011": "Rundll32",
    "T1070.004": "File Deletion",
    "T1560.001": "Archive via Utility",
    "T1003.001": "LSASS Memory",
    "T1105": "Ingress Tool Transfer",
}
TACTIC = {
    "discovery": "Discovery", "execution": "Execution", "persistence": "Persistence",
    "defense-evasion": "Defense Evasion", "collection": "Collection",
    "credential-access": "Credential Access", "command-and-control": "Command and Control",
}
OUTCOME = {0: "Blind", 1: "Parent only", 2: "Detected", 3: "Detected, discriminating"}

# Rule-ID block -> technique. Mirrors RULE_ID_REGISTER.md.
BLOCK = {
    "10020": "T1087.001", "10023": "T1082", "10024": "T1033", "10025": "T1016",
    "10026": "T1112", "10027": "T1053.005", "10028": "T1136.001", "10029": "T1547.001",
    "10030": "T1218.011", "10031": "T1070.004", "10032": "T1003.001", "10033": "T1560.001",
}


def load_nav():
    spec = importlib.util.spec_from_file_location(
        "nav", os.path.join("scripts", "build_navigator_layers.py"))
    nav = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(nav)
    return nav


def compress(ids):
    """100230,100231,100232,100233 -> 100230-100233"""
    if not ids:
        return "None"
    ids = sorted(ids)
    out, i = [], 0
    while i < len(ids):
        j = i
        while j + 1 < len(ids) and int(ids[j + 1]) == int(ids[j]) + 1:
            j += 1
        out.append(ids[i] if i == j else f"{ids[i]}-{ids[j]}")
        i = j + 1
    return ", ".join(out)


def main():
    nav = load_nav()
    navrows = nav.load()
    rows = [r for r in csv.DictReader(open("data/labelled_alerts.csv", encoding="utf-8"))
            if r["label"] == "1"]

    xml = open(os.path.join("wazuh_rules", "local_rules.xml"), encoding="utf-8").read()
    deployed = defaultdict(list)
    for rid in re.findall(r'rule id="(10\d{4})"', xml):
        t = BLOCK.get(rid[:5])
        if t:
            deployed[t].append(rid)

    lines, tally = [], defaultdict(int)
    for n, (tid, tac) in enumerate(nav.TECHNIQUES, 1):
        phase = nav.FINAL_PHASE.get(tid, "custom")
        score = nav.score_phase(navrows, tid, "baseline")[0]
        tally[score] += 1
        sel = [r for r in rows if r["technique_id"] == tid and r["ruleset_phase"] == phase]
        a = sum(1 for r in sel if r["class"] == "attack")
        b = sum(1 for r in sel if r["class"] == "benign")
        lines.append(f"| {n} | {tid} | {NAMES[tid]} | {TACTIC[tac]} | {OUTCOME[score]} | "
                     f"{compress(deployed.get(tid, []))} | {a} | {b} |")

    n_rules = sum(len(v) for v in deployed.values())
    total_a = sum(int(l.split("|")[7]) for l in lines)
    total_b = sum(int(l.split("|")[8]) for l in lines)

    doc = f"""# Coverage summary — appendix table

⚠️ **GENERATED FILE. Do not edit by hand.**
Regenerate with `python3 scripts/build_coverage_summary.py` after any re-export.

The compact, appendix-ready version of `COVERAGE_TABLE.md`, which is the ~90,000-character working
record and is not readable as an appendix. Scores are read from `scripts/build_navigator_layers.py`, so
this table cannot disagree with the Navigator figures. Counts come from `data/labelled_alerts.csv`.

| # | Technique ID | Technique | Tactic | Default outcome | Custom rules | Attack alerts | Benign alerts |
|---|---|---|---|---|---|---|---|
{chr(10).join(lines)}

**Totals:** {n_rules} custom rules deployed · {total_a} attack alerts · {total_b} benign alerts across
the final phase of all 15 techniques.

## Reading this table

**"Default outcome" is the BASELINE phase** — stock Wazuh 4.14.6 with no customisation. It gives the
headline coverage result:

| Outcome | Techniques |
|---|---|
| Blind — no alert carries the technique or its parent | **{tally[0]}** |
| Parent only — behaviour seen, sub-technique lost | **{tally[1]}** |
| Detected at the correct technique | **{tally[2]}** |
| Detected **and** never fires on benign activity | **{tally[3]}** |

After the 37 custom rules this becomes **0 / 0 / 14 / 1** — every blind spot closed, and the count of
detections that fire *only* on genuine attack activity falls from {tally[3]} to 1. **That is the
central finding: rule engineering solves coverage, not discrimination.**

**Alert counts are the FINAL phase** — `custom` for most techniques, `custom-sensor` for T1112,
T1070.004 and T1003.001 which required a widened Sysmon configuration, and `baseline` for the three
given no custom rule.

**Three techniques have no custom rules** — T1059.001, T1059.003 and T1105 — because the default
ruleset was already correct. T1105's default is also the only *discriminating* vendor detection in the
study. Writing rules there would have duplicated working detection and inflated the apparent
contribution of this project.

⚠️ **`100293` is absent from the T1547.001 range.** It was written, found unreachable, and retired;
the ID remains reserved so it cannot be reused.

## Word formatting

9 pt, left-aligned, bold header row, no hyphenation. Repeat Header Rows is not needed — 15 rows fit on
one page. Suggested column widths: 0.8 / 2.2 / 5 / 3 / 3.5 / 3.5 / 1.8 / 1.8 cm.
"""
    with open("COVERAGE_SUMMARY.md", "w", encoding="utf-8") as fh:
        fh.write(doc)

    print("written: COVERAGE_SUMMARY.md")
    print(f"  {len(lines)} technique rows")
    print(f"  baseline outcome tally: {tally[0]} blind / {tally[1]} parent-only / "
          f"{tally[2]} detected / {tally[3]} discriminating")
    print(f"  {n_rules} custom rules · {total_a} attack alerts · {total_b} benign alerts")


if __name__ == "__main__":
    main()
