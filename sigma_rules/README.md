# Sigma rules

Detection-as-code artefacts for the twelve techniques that received custom Wazuh rules.

> ## ⚠️ READ THIS BEFORE CITING THIS DIRECTORY IN CHAPTER 3
>
> **The twelve files here were not all produced the same way, and the methodology must say so.**
>
> | Provenance | Count | Techniques |
> |---|---|---|
> | **Authored in Sigma first**, then translated to Wazuh XML by hand, with implementation notes | **3** | T1087.001, T1082, T1136.001 |
> | **Back-translated from the deployed Wazuh XML** on 2026-08-12 by `scripts/wazuh_to_sigma.py` | **9** | T1033, T1016, T1053.005, T1547.001, T1112, T1218.011, T1070.004, T1003.001, T1560.001 |
>
> For the nine, the Wazuh rule was written directly during the measurement runs and the Sigma artefact
> did not exist at that time. Each of those files carries a provenance banner saying exactly that.
>
> **What the back-translated files legitimately demonstrate:** the deployed detection logic is
> expressible in a vendor-neutral form and is portable to another SIEM.
> **What they do not demonstrate:** that Sigma drove the engineering.
>
> **Chapter 3 must not describe all twelve as Sigma-first.** Either wording below is defensible; the
> mismatch between them is not:
>
> - *"Detections were authored in Sigma for three techniques and expressed in Sigma retrospectively for
>   the remainder, to demonstrate portability."*
> - *"Detections were implemented directly as Wazuh rules and subsequently expressed in Sigma as a
>   vendor-neutral artefact."*

## Regenerating

```bash
python3 scripts/wazuh_to_sigma.py           # write any missing back-translations
python3 scripts/wazuh_to_sigma.py --check   # report coverage, exit 1 if incomplete
```

The script groups rules by **rule-ID block** (per `RULE_ID_REGISTER.md`), not by each rule's first
`<mitre>` tag. Keying on the tag invented two techniques that were never studied — `100283` carries a
secondary T1098 and a T1112 rule carries T1027 — and emitted Sigma files for both.

## Naming

- `<TECHNIQUE_ID>_<short_description>.yml` — hand-authored, Sigma-first
- `<TECHNIQUE_ID>_backtranslated.yml` — generated from the deployed XML

## What does not survive translation

**Wazuh rule chaining.** `if_group` and `if_sid` make a rule fire only on events another rule already
matched; Sigma matches events directly and has no equivalent. This is recorded in each `logsource`
definition, and it matters: every rule chaining from `sysmon_eid1_detections` inherits the vendor
ruleset's blind spots. `100300` failed to fire on `comsvcs.dll,MiniDump` for exactly this reason, because
`rundll32`'s parent was `powershell.exe` rather than `cmd.exe`. **The Sigma versions do not have that
limitation, which is itself an argument for the portable artefact.**

**Sibling evaluation by descending level.** Wazuh emits only the highest-level matching sibling, so
`100332` (L12) displaces `100330` (L8) on the same event. Sigma has no such precedence. A count taken
from Wazuh is therefore not directly comparable to what these rules would produce elsewhere — see the
T1560.001 row of `COVERAGE_TABLE.md`.

## Measured caveats are carried in the files

Each back-translated rule repeats the finding that qualifies it, so the artefact cannot be read without
it. The sharpest is T1003.001: the benign mirror runs a **character-identical command line**, so nothing
in the command line can separate the classes — `100320` fires 5 attack / 5 benign, and `100321`, which
adds only the access-mask condition, fires 6 / 0.
