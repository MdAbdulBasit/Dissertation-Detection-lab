#!/usr/bin/env python3
"""
Integrity check for the Chapter 4 evidence base.

    python3 scripts/check_docs.py        exit 0 = clean, 1 = something is wrong

WHY THIS EXISTS
    Two classes of defect have reached the repository unnoticed, and neither is visible when reading
    the file:

    1. STALE COUNTS. COVERAGE_TABLE.md carried "258 usable windows / 4,636 alerts" and "92213 fires 551
       times" long after the export changed. Both were found by accident. Numbers written by hand into
       prose do not update when the pipeline does.

    2. BROKEN TABLE ROWS. A note containing an un-escaped `|`, or a multi-line insertion, silently
       splits a row into extra columns or across several lines. GitHub renders the mess without
       complaint. Row 3 of COVERAGE_TABLE.md spent time split across twelve lines with its Notes cell
       orphaned below the table, and row 13 carried two extra columns from `0x1010|0x40`.

    Both are cheap to detect mechanically and expensive to find by eye in a 90,000-character table.

RUN THIS BEFORE EVERY COMMIT THAT TOUCHES A MARKDOWN FILE.
"""

import csv
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

FAIL = []
WARN = []


def ok(msg):
    print(f"  \033[32mok\033[0m    {msg}")


def bad(msg):
    FAIL.append(msg)
    print(f"  \033[31mFAIL\033[0m  {msg}")


def warn(msg):
    WARN.append(msg)
    print(f"  \033[33mwarn\033[0m  {msg}")


def split_cells(line):
    """Split a markdown table row on UNESCAPED pipes only - `\\|` is a literal pipe, not a separator."""
    return re.split(r"(?<!\\)\|", line)


# ---------------------------------------------------------------------------------------------
def check_table_integrity(path, row_re=r"\|\s*(\d{1,2})\s*\|", header_prefix="| #"):
    print(f"\n{path} — table structure")
    lines = open(path, encoding="utf-8").read().split("\n")
    headers = [l for l in lines if l.startswith(header_prefix)]
    if not headers:
        bad(f"{path}: no header row starting {header_prefix!r}")
        return
    expected = len(split_cells(headers[0]))
    rows = [(m.group(1), len(split_cells(l)))
            for l in lines if (m := re.match(row_re, l))]
    if not rows:
        bad(f"{path}: no numbered rows found")
        return
    broken = [(n, c - expected) for n, c in rows if c != expected]
    if broken:
        for n, delta in broken:
            bad(f"{path}: row {n} has {delta:+d} columns — un-escaped '|' or a multi-line cell")
    else:
        ok(f"{len(rows)} rows, all {expected - 2} columns wide")

    # a row whose Notes cell is empty is a hole in the evidence base
    for l in lines:
        m = re.match(row_re, l)
        if not m:
            continue
        c = [x.strip() for x in split_cells(l)]
        if len(c) == expected and not c[-2]:
            bad(f"{path}: row {m.group(1)} has an EMPTY Notes cell")


# ---------------------------------------------------------------------------------------------
def check_counts():
    print("\ndataset counts cited in prose")
    rows = list(csv.DictReader(open("data/labelled_alerts.csv", encoding="utf-8")))
    inw = [r for r in rows if r["label"] == "1"]
    det = list(csv.DictReader(open("data/detonation_log.csv", encoding="utf-8-sig")))
    sup = [r for r in det
           if any(str(v).upper().startswith(("SUPERSEDED", "ABORTED")) for v in r.values())]

    truth = {
        "total alerts retained": len(rows),
        "in-window alerts": len(inw),
        "attack alerts": sum(1 for r in inw if r["class"] == "attack"),
        "benign alerts": sum(1 for r in inw if r["class"] == "benign"),
        "usable windows": len(det) - len(sup),
        "92213 alerts": sum(1 for r in rows if r["rule_id"] == "92213"),
    }
    for k, v in truth.items():
        print(f"        {k:24} {v}")

    # figures known to be superseded. If one reappears outside a correction note, that is a regression.
    retired = {
        "4,636": "old retained-alert count (now 4,976)",
        "2,431": "old in-window count (now 2,683)",
        "258": "old usable-window count (now 278)",
        "3,217": "two-technique snapshot total",
        "3,365": "old dataset size",
        "551": "old 92213 count (now 115)",
    }
    # ⚠️ The exemption list must cover the language actually used in this repo's correction notes,
    # or the checker cries wolf on its own corrections and gets ignored - which is worse than no check.
    exempt = re.compile(r"SUPERSEDED|CORRECTED|not reproducible|cannot be reproduced|recomputed|"
                        r"previously read|Original|earlier|old |stale|decision needed|"
                        r"T1551|6010\d|→ \*\*4,976\*\*", re.I)
    md = [f for f in os.listdir(".") if f.endswith(".md")]
    md += [os.path.join(d, f) for d in ("ml", "navigator_layers", "evidence", "sigma_rules")
           if os.path.isdir(d) for f in os.listdir(d) if f.endswith(".md")]
    hits = 0
    for f in md:
        s = open(f, encoding="utf-8").read()
        for fig, why in retired.items():
            for m in re.finditer(re.escape(fig), s):
                ctx = re.sub(r"\s+", " ", s[max(0, m.start() - 200):m.start() + 120])
                if exempt.search(ctx):
                    continue
                hits += 1
                warn(f"{f}: retired figure {fig!r} ({why}) with no correction note nearby")
    if not hits:
        ok("no retired figure reappears outside a correction note")


# ---------------------------------------------------------------------------------------------
def check_rule_register():
    print("\nRULE_ID_REGISTER.md vs deployed rules")
    xml = open(os.path.join("wazuh_rules", "local_rules.xml"), encoding="utf-8").read()
    deployed = set(re.findall(r'rule id="(10\d{4})"', xml))
    reg = open("RULE_ID_REGISTER.md", encoding="utf-8").read()
    # Only a TABLE CELL saying "Not started" is a defect. The banner explaining that the file used to
    # say it must not trip the check that confirms it no longer does.
    stale_rows = [l for l in reg.split("\n")
                  if re.match(r"\|\s*100\d{3}", l) and "Not started" in l]
    if stale_rows:
        bad(f"RULE_ID_REGISTER.md: {len(stale_rows)} allocation row(s) still say 'Not started'")
    else:
        ok("no allocation row says 'Not started'")
    missing = sorted(r for r in deployed if r not in reg)
    if missing:
        bad(f"deployed but absent from the register: {', '.join(missing)}")
    else:
        ok(f"all {len(deployed)} deployed rule IDs appear in the register")


# ---------------------------------------------------------------------------------------------
if __name__ == "__main__":
    check_table_integrity("COVERAGE_TABLE.md")
    check_counts()
    check_rule_register()

    print()
    if FAIL:
        print(f"\033[31m{len(FAIL)} FAILURE(S)\033[0m, {len(WARN)} warning(s)")
        sys.exit(1)
    print(f"\033[32mclean\033[0m — {len(WARN)} warning(s)")
