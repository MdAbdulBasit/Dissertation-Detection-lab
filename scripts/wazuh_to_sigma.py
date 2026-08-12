#!/usr/bin/env python3
"""
Back-translate deployed Wazuh rules into Sigma.

    python3 scripts/wazuh_to_sigma.py            write missing sigma_rules/*.yml
    python3 scripts/wazuh_to_sigma.py --check    report coverage only, exit 1 if incomplete

⚠️ READ THIS BEFORE CITING THE OUTPUT.

    The methodology describes Sigma as authored FIRST and translated to Wazuh XML afterwards. That is
    true of three techniques - T1087.001, T1082 and T1136.001, written by hand with implementation
    notes. It is NOT true of the other nine, where the Wazuh rule was written directly under time
    pressure and the Sigma artefact did not exist.

    This script produces those nine by translating the DEPLOYED XML back into Sigma. Every file it
    writes carries a provenance banner saying so, with the date. Generating them silently and letting
    the directory imply Sigma-first authorship would be a false claim about process - the exact class
    of error this project has spent its corrections avoiding.

    What the back-translated files legitimately demonstrate: the deployed logic is expressible in a
    vendor-neutral form and is portable to another SIEM. What they do NOT demonstrate: that Sigma
    drove the engineering. Chapter 3 must say which is which.

MAPPING
    if_group / if_sid           -> logsource + a comment (Wazuh rule chaining has no Sigma equivalent)
    field name=... type=pcre2   -> <SigmaField>|re
    negate="yes"                -> moved into the condition as `and not`
    level                       -> Sigma level band
"""

import os
import re
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XML = os.path.join(ROOT, "wazuh_rules", "local_rules.xml")
OUT = os.path.join(ROOT, "sigma_rules")

# Sigma field names for the Wazuh/Sysmon eventdata fields actually used by the ruleset.
FIELD_MAP = {
    "win.eventdata.originalFileName": "OriginalFileName",
    "win.eventdata.commandLine": "CommandLine",
    "win.eventdata.targetObject": "TargetObject",
    "win.eventdata.details": "Details",
    "win.eventdata.targetFilename": "TargetFilename",
    "win.eventdata.image": "Image",
    "win.eventdata.targetImage": "TargetImage",
    "win.eventdata.grantedAccess": "GrantedAccess",
    "win.eventdata.sourceImage": "SourceImage",
}

# Which Sysmon event the chained group corresponds to, for the logsource block.
GROUP_EVENT = {
    "sysmon_eid1_detections": (1, "process_creation"),
    "sysmon_event1": (1, "process_creation"),
    "sysmon_event_10": (10, "process_access"),
    "sysmon_event3": (3, "network_connection"),
    "sysmon_event_11": (11, "file_event"),
    "sysmon_event_13": (13, "registry_set"),
    "sysmon_event_23": (23, "file_delete"),
    "sysmon_event_26": (26, "file_delete_detected"),
}

LEVEL_BAND = {range(0, 5): "low", range(5, 9): "medium", range(9, 12): "high", range(12, 16): "critical"}

# Techniques that already have a hand-authored, Sigma-first rule. Never overwrite these.
HAND_AUTHORED = {"T1087.001", "T1082", "T1136.001"}

# Rule-ID block -> the technique it was written for. Mirrors RULE_ID_REGISTER.md.
BLOCK_OWNER = {
    "10020": "T1087.001", "10023": "T1082", "10024": "T1033", "10025": "T1016",
    "10026": "T1112", "10027": "T1053.005", "10028": "T1136.001", "10029": "T1547.001",
    "10030": "T1218.011", "10031": "T1070.004", "10032": "T1003.001", "10033": "T1560.001",
}

TECH_NAMES = {
    "T1033": ("System Owner/User Discovery", "discovery"),
    "T1016": ("System Network Configuration Discovery", "discovery"),
    "T1053.005": ("Scheduled Task", "persistence"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "persistence"),
    "T1112": ("Modify Registry", "defense_evasion"),
    "T1218.011": ("Rundll32", "defense_evasion"),
    "T1070.004": ("File Deletion", "defense_evasion"),
    "T1003.001": ("LSASS Memory", "credential_access"),
    "T1560.001": ("Archive via Utility", "collection"),
    "T1087.001": ("Local Account Discovery", "discovery"),
    "T1082": ("System Information Discovery", "discovery"),
    "T1136.001": ("Create Local Account", "persistence"),
}

# Measured caveats, so the Sigma file cannot be read without the finding that qualifies it.
CAVEATS = {
    "T1033": "100241 fires only in the attack class here, and that is MIRROR SCOPE rather than "
             "discrimination - the benign mirror omits the mechanism it matches.",
    "T1016": "100251 and 100252 are attack-only because the benign mirror ran ipconfig/route/arp but "
             "not `netsh show` or `net config`. Excluded from any separability claim.",
    "T1112": "100262 fires 10 attack / 10 benign - registry writes are not adversarial. Only 100260, "
             "which keys on WHICH key is written, separates the classes (20/0).",
    "T1070.004": "100310 fires 10 attack / 10 benign in its own windows and 10/19 dataset-wide. Only "
                 "100311, which keys on WHAT is deleted, separates (5/0). Requires Sysmon "
                 "schemaversion 4.60+ for EID 26; 4.50 silently discards the events.",
    "T1003.001": "The strongest measured result in the study: the benign mirror runs a "
                 "character-identical command line, so nothing in the command line can separate the "
                 "classes. 100320 (any process opening LSASS) fires 5/5; 100321, which adds the "
                 "access-mask condition, fires 6/0.",
    "T1560.001": "100330 and 100331 fire 0 attack / 5 benign each - the first by DISPLACEMENT (100332 "
                 "at L12 outranks it), the second by MIRROR SCOPE (the atomic never uses PowerShell "
                 "compression). Mechanism-keyed archiving detection is 5/5; only object-keyed 100332 "
                 "separates (5/0).",
    "T1547.001": "Default rule 92300 is correctly mapped and SILENT - suppressed severity, not a "
                 "missing detection.",
    "T1218.011": "100300 initially failed to fire on comsvcs.dll MiniDump because rundll32's parent "
                 "was powershell.exe rather than cmd.exe: every rule chaining from "
                 "`sysmon_eid1_detections` inherits the vendor's blind spots.",
    "T1053.005": "100270 fires 15 attack / 4 benign. Creating a scheduled task looks the same whoever "
                 "does it, because it is the same action.",
}


def level_of(n):
    for rng, name in LEVEL_BAND.items():
        if n in rng:
            return name
    return "medium"


def parse_rules():
    raw = open(XML, encoding="utf-8").read()
    if "<group" not in raw.split("\n")[0]:
        raw = "<root>" + raw + "</root>"
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        root = ET.fromstring("<root>" + open(XML, encoding="utf-8").read() + "</root>")

    out = {}
    for rule in root.iter("rule"):
        rid = rule.get("id", "")
        if not rid.startswith("100"):
            continue
        mitre = [m.text.strip() for m in rule.findall("./mitre/id") if m.text]
        # ⚠️ Group by the RULE-ID BLOCK, not by the rule's first <mitre> tag. Several rules carry a
        # secondary technique — 100283 re-attributes group membership to T1098, and a T1112 rule is
        # tagged T1027 — so keying on mitre[0] invented two techniques that were never studied and
        # emitted Sigma files for them. The block allocation in RULE_ID_REGISTER.md is authoritative.
        tid = BLOCK_OWNER.get(rid[:5])
        if tid is None:
            continue
        fields = []
        for f in rule.findall("field"):
            fields.append({
                "wazuh": f.get("name", ""),
                "sigma": FIELD_MAP.get(f.get("name", ""), f.get("name", "").split(".")[-1]),
                "pattern": (f.text or "").strip(),
                "negate": f.get("negate") == "yes",
            })
        out.setdefault(tid, []).append({
            "id": rid,
            "level": int(rule.get("level", "0")),
            "chain": (rule.findtext("if_group") or rule.findtext("if_sid") or "").strip(),
            "desc": re.sub(r"\s+", " ", (rule.findtext("description") or "").strip()),
            "mitre": mitre,
            "fields": fields,
        })
    return out


def yaml_quote(v):
    return "'" + v.replace("'", "''") + "'"


def emit(tid, rules):
    name, tactic = TECH_NAMES.get(tid, (tid, "execution"))
    evs = {GROUP_EVENT.get(r["chain"], (1, "process_creation")) for r in rules}
    eid, category = sorted(evs)[0]
    top_level = level_of(max(r["level"] for r in rules))

    L = []
    L.append("# " + "=" * 94)
    L.append("# ⚠️  PROVENANCE — BACK-TRANSLATED, NOT AUTHORED SIGMA-FIRST")
    L.append("#")
    L.append("#   This rule was generated on 2026-08-12 by scripts/wazuh_to_sigma.py from the DEPLOYED")
    L.append("#   Wazuh rules in wazuh_rules/local_rules.xml. The Wazuh XML was written first, during")
    L.append("#   the measurement runs; this Sigma file did not exist at that time.")
    L.append("#")
    L.append("#   Three techniques in this directory WERE authored Sigma-first and translated to Wazuh")
    L.append("#   afterwards, by hand, with implementation notes: T1087.001, T1082, T1136.001.")
    L.append("#   This is not one of them. Chapter 3 must not describe all twelve as Sigma-first.")
    L.append("#")
    L.append("#   What this file legitimately shows: the deployed detection logic is expressible in a")
    L.append("#   vendor-neutral form and is portable to another SIEM.")
    L.append("# " + "=" * 94)
    L.append("")
    L.append(f"title: {name} ({tid}) — custom detection")
    L.append(f"id: {tid.lower().replace('.', '-')}-backtranslated-c5038891")
    L.append("status: experimental")
    L.append("description: |")
    L.append(f"  Custom detection for {tid} {name}, deployed and measured in an MSc detection-engineering")
    L.append(f"  study on Wazuh 4.14.6. Covers {len(rules)} deployed rule(s): "
             + ", ".join(r["id"] for r in rules) + ".")
    if tid in CAVEATS:
        L.append("")
        for line in re.findall(r".{1,92}(?:\s|$)", CAVEATS[tid]):
            if line.strip():
                L.append("  MEASURED CAVEAT: " + line.strip() if line is CAVEATS[tid][:len(line)]
                         else "  " + line.strip())
    L.append("references:")
    L.append(f"  - https://attack.mitre.org/techniques/{tid.split('.')[0]}/"
             + (f"{tid.split('.')[1]}/" if "." in tid else ""))
    L.append("  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/"
             f"{tid}/{tid}.md")
    L.append("author: Abdul Basit Mohammed (c5038891), Sheffield Hallam University")
    L.append("date: 2026-08-12")
    L.append("tags:")
    L.append(f"  - attack.{tactic}")
    for t in sorted({m for r in rules for m in r["mitre"]}):
        L.append(f"  - attack.{t.lower()}")
    L.append("logsource:")
    L.append("  product: windows")
    L.append(f"  category: {category}")
    L.append("  definition: |")
    L.append(f"    Sysmon EID {eid}. In Wazuh these rules chain from "
             f"{', '.join(sorted({r['chain'] for r in rules if r['chain']}))} via if_group/if_sid,")
    L.append("    which has no Sigma equivalent — Sigma matches events directly rather than other rules.")
    L.append("    ⚠️ Rules chaining from `sysmon_eid1_detections` only see events a VENDOR rule already")
    L.append("    matched, so they inherit its blind spots. That constraint disappears in Sigma.")
    L.append("detection:")

    # ⚠️ A negation binds to ITS OWN rule, not to the whole disjunction. The first version emitted
    # `(a or b) and not filter_b`, which silently applied 100321's sourceImage exclusion to 100320 as
    # well and changed what the rule means. Each term is now `sel` or `(sel and not filter)`.
    terms = []
    sel_names, neg_names = [], []
    for r in rules:
        sel = f"wazuh_{r['id']}"
        L.append(f"  {sel}:   # Wazuh rule {r['id']}, level {r['level']} — {r['desc'][:70]}")
        pos = [f for f in r["fields"] if not f["negate"]]
        neg = [f for f in r["fields"] if f["negate"]]
        if not pos:
            L.append("    EventID: " + str(eid))
        for f in pos:
            L.append(f"    {f['sigma']}|re: {yaml_quote(f['pattern'])}")
        sel_names.append(sel)
        if neg:
            nname = f"filter_{r['id']}"
            L.append(f"  {nname}:   # negated in the Wazuh rule; Sigma expresses this in the condition")
            for f in neg:
                L.append(f"    {f['sigma']}|re: {yaml_quote(f['pattern'])}")
            neg_names.append((sel, nname))
            terms.append(f"({sel} and not {nname})")
        else:
            terms.append(sel)
        L.append("")

    L.append(f"  condition: {' or '.join(terms)}")
    L.append("falsepositives:")
    if tid in CAVEATS:
        L.append("  - See MEASURED CAVEAT in the description — these counts were observed, not estimated.")
    L.append("  - Routine administration. Measured in this lab as a both-classes signal for most rules,")
    L.append("    so this is a triage input rather than a standalone verdict.")
    L.append(f"level: {top_level}")
    L.append("---")
    L.append("# Deployed Wazuh mapping")
    for r in rules:
        L.append(f"#   {r['id']}  L{r['level']:<3} {r['chain']:<26} {r['desc'][:78]}")
    return "\n".join(L) + "\n"


def main():
    check = "--check" in sys.argv
    rules = parse_rules()
    have = {f.split("_")[0].replace("T1136", "T1136.001") for f in os.listdir(OUT) if f.endswith(".yml")}
    existing = {f for f in os.listdir(OUT) if f.endswith(".yml")}

    print(f"deployed techniques with custom rules : {len(rules)}")
    print(f"sigma files present                   : {len(existing)}")
    print(f"hand-authored (Sigma-first)           : {', '.join(sorted(HAND_AUTHORED))}")
    missing = [t for t in rules if t not in HAND_AUTHORED]
    print(f"missing / back-translated             : {len(missing)}  {', '.join(sorted(missing))}")

    if check:
        if missing and not all(
            os.path.exists(os.path.join(OUT, f"{t.replace('.', '_')}_backtranslated.yml"))
            for t in missing
        ):
            print("\nINCOMPLETE — run without --check to generate")
            sys.exit(1)
        print("\ncomplete")
        return

    written = 0
    for tid in sorted(missing):
        path = os.path.join(OUT, f"{tid.replace('.', '_')}_backtranslated.yml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(emit(tid, sorted(rules[tid], key=lambda r: r["id"])))
        written += 1
        print("  written:", os.path.relpath(path, ROOT))
    print(f"\n{written} back-translated Sigma rules written.")
    print("⚠️  Each carries a provenance banner. Chapter 3 must distinguish these from the three "
          "hand-authored ones.")


if __name__ == "__main__":
    main()
