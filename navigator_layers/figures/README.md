# Chapter 4 figures — rendered ATT&CK Navigator layers

Exported from <https://mitre-attack.github.io/attack-navigator/> on 10 August 2026, ATT&CK v19.

| File | Source layer | What it shows |
|---|---|---|
| `01_default_ruleset_v19.svg` | `01_default_ruleset_v19.json` | Stock Wazuh 4.14.6, default Sysmon |
| `02_custom_ruleset_v19.svg` | `02_custom_ruleset_v19.json` | 37 custom rules + widened Sysmon |

SVG, so they stay sharp at any size — place them full-width on a landscape page rather than shrinking
them to fit a column.

## What the two figures show side by side

| | Stock | Engineered |
|---|---|---|
| 🔴 Red — blind | **9** | **0** |
| 🟠 Orange — parent only | 1 | 0 |
| 🟡 Amber — detected | 6 | **18** |
| 🟢 Green — detected *and* discriminating | **3** | **1** |

**Read the last row, not the first.** Every blind spot closed and the count of detections that fire only
on genuine attack activity went *down*. That is the dissertation's central finding rendered as a picture:
rule engineering solves coverage, not discrimination.

## ⚠️ These are CELL counts, not technique counts

The v19 layers omit the `tactic` field so the Navigator resolves placement itself, which means a
technique belonging to several tactics is drawn in each of them — Scheduled Task appears under Execution,
Persistence *and* Privilege Escalation. Fifteen techniques produce nineteen coloured cells.

**Quote the technique counts from `COVERAGE_TABLE.md` (7 / 1 / 4 / 3 → 0 / 0 / 14 / 1), never the cells
in these images.**

## ⚠️ Sub-techniques must be expanded before export

Ten of the fifteen techniques are sub-techniques. The Navigator exports whatever is currently on screen,
so with parent rows collapsed the SVG silently contains only the five top-level techniques — no error,
no warning, just a figure missing two thirds of its data. The first export of
`02_custom_ruleset_v19.svg` had exactly this defect and was caught only by grepping the SVG for expected
technique labels.

**Before exporting: confirm no cell shows a `(1/5)`-style fraction, and that `LSASS Memory`, `Rundll32`,
`Local Account`, `Registry Run Keys / Startup Folder` and `Archive via Utility` are each visible as their
own box.** Both files here have been verified to contain all fifteen.

## Regenerating

```bash
python3 scripts/build_navigator_layers.py     # rebuilds all four JSON layers from labelled_alerts.csv
```

Then reload the `_v19` JSONs in the Navigator, expand sub-techniques, and re-export. The `_v19` files are
for rendering; **the v14 pair is the citable record** — see `../README.md`.
